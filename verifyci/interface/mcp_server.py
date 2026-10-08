import asyncio
import time as _time
from typing import Any

from verifyci.contracts.scheduler import TERMINAL_STATUSES
from verifyci.interface.limits import MAX_DIFF_CHARS, MAX_K, MAX_QUERY_CHARS, MAX_TASK_DIFF_CHARS


class MCPServer:
    def __init__(self):
        self._tools = {}

    def register_tool(self, name: str, handler: Any, description: str = ""):
        self._tools[name] = {"handler": handler, "description": description}

    def list_tools(self) -> list[str]:
        return list(self._tools.keys())

    async def call_tool(self, name: str, **kwargs) -> Any:
        tool = self._tools.get(name)
        if tool is None:
            raise ValueError(f"unknown_tool:{name}")
        return await tool["handler"](**kwargs)


def _describe_graph(graph, node_map: dict, limit: int = 5000) -> tuple:
    from verifyci.retrieval.sparse import BM25Retriever

    bm25 = BM25Retriever()
    texts: dict[str, str] = {}
    if graph is not None and hasattr(graph, "nodes"):
        try:
            nodes = list(graph.nodes())
            indices = list(graph.node_indices()) if hasattr(graph, "node_indices") else range(len(nodes))
            for idx, data in zip(indices, nodes):
                eid = getattr(data, "revision_entity_id", str(idx))
                text = f"{getattr(data, 'name', '')} {getattr(data, 'file_path', '')}"
                texts[str(eid)] = text
                bm25.add(str(eid), text)
                if len(texts) >= limit:
                    break
        except Exception:  # noqa: BLE001, S110
            pass
    reverse = {v: k for k, v in (node_map or {}).items()}
    for idx, eid in reverse.items():
        if eid not in texts and hasattr(graph, "nodes"):
            texts[str(eid)] = str(eid)
            bm25.add(str(eid), str(eid))
    return bm25, texts


class MCPServerHandlers:
    def __init__(
        self,
        graph=None,
        store=None,
        node_map: dict | None = None,
        dense_provider: Any = None,
        ledger: Any = None,
        entities: list | None = None,
        rw_store: Any = None,
    ):
        from verifyci.orchestration.scheduler import AsyncDAGScheduler
        from verifyci.verification.config import load_repo_invariants, load_repo_waivers

        self.graph = graph
        self.store = store
        self.node_map = node_map or {}
        self.dense_provider = dense_provider
        self.ledger = ledger
        self.rw_store = rw_store
        self.scheduler = AsyncDAGScheduler(ledger=ledger)

        if entities is None:
            from verifyci.interface.commands.graph_loader import payload_entities
            entities = payload_entities(graph)
        self.entities = entities

        self._index_cache: dict[str, Any] = {"key": None, "bm25": None, "texts": None}

        self.by_revision_id = {}
        for _e in self.entities or []:
            _rid = getattr(_e, "revision_entity_id", None)
            if _rid and _rid not in self.by_revision_id:
                self.by_revision_id[_rid] = _e

        self._repo_invariants_err: str | None = None
        try:
            self._repo_invariants = load_repo_invariants(getattr(store, "db_path", None))
            self._repo_waivers = load_repo_waivers(getattr(store, "db_path", None))
        except ValueError:
            self._repo_invariants = []
            self._repo_waivers = []
            self._repo_invariants_err = "invalid_invariants_config"

    def _index_fingerprint(self):
        if self.graph is None:
            return None
        try:
            return (id(self.graph), int(self.graph.num_nodes()), int(self.graph.num_edges()))
        except Exception:  # noqa: BLE001 - adapter without counts
            return None

    def _search_index(self):
        key = self._index_fingerprint()
        if key is None:
            return _describe_graph(self.graph, self.node_map)
        if self._index_cache["key"] == key and self._index_cache["bm25"] is not None:
            return self._index_cache["bm25"], self._index_cache["texts"]
        bm25, texts = _describe_graph(self.graph, self.node_map)
        self._index_cache.update({"key": key, "bm25": bm25, "texts": texts})
        return bm25, texts

    def _enriched_hit(self, hit: Any) -> dict:
        entity = self.by_revision_id.get(hit.id)
        return {"id": hit.id, "score": hit.score,
                "name": getattr(entity, "name", None),
                "file_path": getattr(entity, "file_path", None),
                "line_start": getattr(entity, "line_start", None),
                "line_end": getattr(entity, "line_end", None)}

    def _resolve_symbol(self, symbol: str, asOf: float | None = None):
        # Revision id first (what search returns), then logical id,
        # then name — in that order, so chained lookups never miss.
        # The revision-id shortcut is timeless: with asOf given it is
        # skipped so the time filter (not the loaded revision) decides.
        if asOf is None and symbol in self.by_revision_id:
            return self.by_revision_id[symbol]
        if self.store is None:
            return None
        entity = self.store.get_entity_by_logical(symbol, asOf=asOf)
        if entity is None and hasattr(self.store, "get_entity_by_name"):
            entity = self.store.get_entity_by_name(symbol, as_of=asOf)
        return entity

    async def code_search(self, query: str, k: int = 10, conversation_id: str = "",
                          rerank: bool = False) -> dict:
        from verifyci.observability.tracing import start_agent_span
        from verifyci.retrieval.dense import SearchResult
        from verifyci.retrieval.fusion import rrf_fusion_with_scores
        from verifyci.retrieval.graph_retriever import GraphRetriever
        from verifyci.retrieval.reranker import CrossEncoderReranker

        _qstart = _time.time()
        _qstatus = "ok"

        def _emit_log(_result=None):
            # Same wiring as commands/query.py: env-gated query log,
            # fail-silent — observability must never break retrieval.
            try:
                from verifyci.env import get_env as _ql_env
                from verifyci.observability.querylog import QueryLogger as _QL
                _log_path = _ql_env("QUERYLOG") or ""
                if not _log_path:
                    return
                _dur = (_time.time() - _qstart) * 1000.0
                _n = len((_result or {}).get("results", [])) if isinstance(_result, dict) else 0
                _QL(_log_path).log_query(query, caller="mcp.code.search",
                                         duration_ms=_dur, results_count=_n,
                                         status=_qstatus)
            except Exception:  # noqa: BLE001
                pass

        with start_agent_span("code.search", conversation_id, "code.search"):
            k = max(1, min(int(k or 10), MAX_K))
            if len(query) > MAX_QUERY_CHARS:
                _qstatus = "query_too_large"
                _r = {"results": [], "query": query, "methods": [], "error": "query_too_large"}
                _emit_log(_r)
                return _r
            if self.graph is None:
                _qstatus = "no_graph_loaded"
                _r = {"results": [], "query": query, "methods": [], "error": "no_graph_loaded"}
                _emit_log(_r)
                return _r
            from verifyci.retrieval.provider import default_dense_provider
            import os as _os
            cache_dir = None
            if self.store is not None and getattr(self.store, "db_path", None):
                cache_dir = _os.path.dirname(_os.path.abspath(self.store.db_path))
            provider = self.dense_provider or default_dense_provider(cache_dir)
            bm25, texts = self._search_index()
            sparse_hits = bm25.search(query, k=k)
            seeds = [h.id for h in sparse_hits[:3]]
            graph_hits = GraphRetriever(self.graph, self.node_map).retrieve(seeds)
            universe = list(texts)[:500]
            try:
                q_emb = (await provider.embed([query]))[0]
                t_embs = await provider.embed([texts[e] for e in universe])
                dense_hits = []
                for eid, t_emb in zip(universe, t_embs):
                    dot = sum(a * b for a, b in zip(q_emb, t_emb))
                    dense_hits.append(SearchResult(id=eid, score=dot, metadata={"text": texts[eid]}))
                dense_hits.sort(key=lambda r: r.score, reverse=True)
                dense_hits = dense_hits[:k]
                dense_ok = True
            except Exception:  # noqa: BLE001
                dense_hits = []
                dense_ok = False
            fused = rrf_fusion_with_scores(dense_hits, sparse_hits, graph_hits)
            methods = ["bm25", "graph", "rrf"] + (["dense"] if dense_ok else ["dense-unavailable"])
            if rerank:
                reranker = CrossEncoderReranker()
                ranked = reranker.rerank(
                    query, [SearchResult(id=i, score=s, metadata={"text": texts.get(i, i)})
                            for i, s in fused], k=k)
                methods = methods + [f"rerank:{reranker.backend}"]
            else:
                ranked = [SearchResult(id=i, score=s, metadata={}) for i, s in fused[:k]]
            out = {"results": [self._enriched_hit(r) for r in ranked],
                   "query": query, "methods": methods}
            _emit_log(out)
            return out

    async def code_definition(self, symbol: str) -> dict:
        if len(symbol) > MAX_QUERY_CHARS:
            return {"symbol": symbol, "definition": None, "error": "query_too_large"}
        if self.store is None and symbol not in self.by_revision_id:
            return {"symbol": symbol, "definition": None, "error": "no_store_loaded"}
        entity = self._resolve_symbol(symbol)
        if entity:
            return {"symbol": symbol, "definition": {"file_path": entity.file_path,
                    "line_start": entity.line_start, "line_end": entity.line_end,
                    "revision_entity_id": getattr(entity, "revision_entity_id", None)}}
        return {"symbol": symbol, "definition": None}

    async def graph_query(self, query: str, asOf: float | None = None) -> dict:
        if len(query) > MAX_QUERY_CHARS:
            return {"query": query, "asOf": asOf, "results": [], "error": "query_too_large"}
        if self.store is None and query not in self.by_revision_id:
            return {"query": query, "asOf": asOf, "results": [], "error": "no_store_loaded"}
        entity = self._resolve_symbol(query, asOf=asOf)
        if entity:
            return {"query": query, "asOf": asOf,
                    "results": [{"name": entity.name, "file_path": entity.file_path,
                                 "revision_entity_id": getattr(
                                     entity, "revision_entity_id", None)}]}
        return {"query": query, "asOf": asOf, "results": []}

    async def verify_diff(self, diff: str, revision_id: str = "", conversation_id: str = "") -> dict:
        from verifyci.contracts.verification_ir import VerificationPolicy
        from verifyci.observability.tracing import start_agent_span
        from verifyci.verification.blast_radius import blast_radius_check
        from verifyci.verification.diffmap import parse_diff_files, seed_entities_for_diff
        from verifyci.verification.intent_align import evaluate_invariants
        from verifyci.verification.policy import PolicyEvaluator
        from verifyci.verification.removal import removal_provenance_check
        from verifyci.verification.return_swap import return_statement_check
        from verifyci.verification.call_swap import call_target_check
        from verifyci.verification.call_semantics import call_semantics_check
        from verifyci.verification.guard_inversion import guard_condition_check
        from verifyci.verification.import_resolution import import_resolution_check
        from verifyci.verification.config import (
            is_policy_file,
            load_trusted_base_invariants,
            load_trusted_base_waivers,
        )
        from verifyci.verification.semi_formal_reason import SemiFormalReasoner
        from verifyci.verification.verification_ir import build_semi_check, build_verification_report

        with start_agent_span("verify.diff", conversation_id, "verify.diff"):
            if self._repo_invariants_err:
                return {
                    "revision_id": revision_id,
                    "status": "FAIL",
                    "report_id": "",
                    "rationale": "invalid_invariants_config",
                    "files": [],
                    "changed_entities": [],
                }
            if len(diff) > MAX_DIFF_CHARS:
                return {
                    "revision_id": revision_id,
                    "status": "FAIL",
                    "error": "diff_too_large",
                    "report_id": "",
                    "rationale": "diff_too_large",
                    "files": [],
                    "changed_entities": [],
                }
            reasoner = SemiFormalReasoner()
            try:
                _db_path = getattr(self.store, "db_path", None)
                repo_invariants = load_trusted_base_invariants(_db_path, diff=diff)
                repo_waivers = load_trusted_base_waivers(_db_path, diff=diff)
            except ValueError:
                return {
                    "revision_id": revision_id,
                    "status": "FAIL",
                    "report_id": "",
                    "rationale": "invalid_invariants_config",
                    "files": [],
                    "changed_entities": [],
                }
            cert = reasoner.verify(diff=diff, graph=self.graph, node_map=self.node_map,
                                   entities=self.entities or None, waivers=repo_waivers)
            files = parse_diff_files(diff)
            checks = [build_semi_check(cert, files, self.entities or [], diff=diff)]
            mapping = seed_entities_for_diff(files, self.entities or [], diff)
            changed = sorted({eid for eids in mapping.values() for eid in eids})
            blast, blast_check = blast_radius_check(
                graph=self.graph, changed_entities=changed, test_entities=set(), node_map=self.node_map)
            checks.append(blast_check)
            checks.append(removal_provenance_check(diff, self.entities or []))
            checks.append(return_statement_check(diff))
            checks.append(call_target_check(diff))
            checks.append(call_semantics_check(diff))
            checks.append(guard_condition_check(diff))
            checks.append(import_resolution_check(diff))
            inv_checks, _metrics = evaluate_invariants(
                diff, repo_invariants, self.graph, evidence=list(cert.evidence))
            checks.extend(inv_checks)
            report = build_verification_report(task_id="mcp_verify", policy_id="default",
                                               checks=checks, blast_radius=blast)
            policy = VerificationPolicy(policy_id="default", on_failure="block",
                                        on_inconclusive="human_review", on_human_review="block",
                                        require_deterministic_checker=True)
            decision = PolicyEvaluator().evaluate(report, policy)
            used_revision = revision_id
            if self.entities:
                used_revision = (getattr(self.entities[0], "revision_id", "")
                                 or revision_id)
            if self.store is None and self.graph is None and not self.entities and decision.status == "INCONCLUSIVE":
                return {"revision_id": used_revision, "status": "INFRA_ERROR",
                        "report_id": report.report_id,
                        "error": "no_store_loaded",
                        "rationale": "storage_unavailable:no_store_loaded",
                        "files": files, "changed_entities": changed}
            if decision.status != "FAIL" and any(is_policy_file(f) for f in files):
                return {"revision_id": used_revision, "status": "HUMAN_REVIEW",
                        "report_id": report.report_id,
                        "rationale": "unverified_policy_change: gate configuration modified in diff",
                        "files": files, "changed_entities": changed}
            return {"revision_id": used_revision, "status": decision.status,
                    "report_id": report.report_id, "rationale": decision.rationale,
                    "files": files, "changed_entities": changed}

    async def task_run(self, task: str, conversation_id: str = "", diff: str = "") -> dict:
        from verifyci.observability.tracing import start_agent_span
        from verifyci.orchestration.compiler.validation import validate_task_ir
        from verifyci.orchestration.intent import build_intent_package
        from verifyci.orchestration.planner import Planner

        with start_agent_span("task.run", conversation_id, "task.run"):
            if self._repo_invariants_err:
                return {"task": task, "task_id": None, "status": "FAILED", "steps": 0, "decision": None, "error": "invalid_invariants_config", "ledger_head": None}
            if len(diff) > MAX_TASK_DIFF_CHARS:
                return {"task": task, "task_id": None, "status": "FAILED", "steps": 0, "decision": None, "error": "diff_too_large", "ledger_head": None}
            if len(task) > MAX_TASK_DIFF_CHARS:
                return {"task": task, "task_id": None, "status": "FAILED", "steps": 0, "decision": None, "error": "task_too_large", "ledger_head": None}
            planner = Planner()
            intent = build_intent_package(task)
            task_ir = planner.plan(task, intent.intent_package_id, "default")
            if not validate_task_ir(task_ir):
                return {"task": task, "task_id": None, "status": "FAILED", "steps": 0, "decision": None, "error": "invalid_task_ir",
                        "ledger_head": None}
            from verifyci.interface.commands.run import _dedupe_invariants
            from verifyci.verification.config import (
                load_trusted_base_invariants, load_trusted_base_waivers,
            )
            try:
                _db_path = getattr(self.store, "db_path", None)
                repo_invariants = load_trusted_base_invariants(_db_path, diff=diff)
                repo_waivers = load_trusted_base_waivers(_db_path, diff=diff)
            except ValueError:
                return {"task": task, "task_id": None, "status": "FAILED", "steps": 0, "decision": None, "error": "invalid_invariants_config", "ledger_head": None}
            context = {
                "graph": self.graph, "node_map": self.node_map, "entities": self.entities,
                "invariants": _dedupe_invariants(intent.invariants + repo_invariants),
                "waivers": list(repo_waivers),
                "diff": diff, "store": self.rw_store or self.store,
            }
            task_id = await self.scheduler.submit(task_ir, conversation_id=conversation_id,
                                                  context=context)
        for _ in range(300):
            status = await self.scheduler.status(task_id)
            if status in TERMINAL_STATUSES:
                decision = self.scheduler.decision(task_id)
                head = self.scheduler.ledger_head(task_id)
                from verifyci.interface.commands.run import _audit_notes
                result = {"task": task, "task_id": task_id, "status": status.value,
                          "steps": len(task_ir.steps),
                          "decision": decision.status if decision else None,
                          "ledger_head": head}
                result.update(_audit_notes(self.scheduler._tasks.get(task_id, {})))
                return result
            await asyncio.sleep(0.1)
        await self.scheduler.cancel(task_id)
        from verifyci.interface.commands.run import _audit_notes
        result = {"task": task, "task_id": task_id, "status": "TIMEOUT",
                  "ledger_head": self.scheduler.ledger_head(task_id)}
        result.update(_audit_notes(self.scheduler._tasks.get(task_id, {})))
        return result

    async def task_status(self, task_id: str) -> dict:
        status = await self.scheduler.status(task_id)
        decision = self.scheduler.decision(task_id)
        return {"task_id": task_id, "status": status.value,
                "decision": decision.status if decision else None,
                "ledger_head": self.scheduler.ledger_head(task_id)}


def create_mcp_server(graph=None, store=None, node_map: dict | None = None,
                      dense_provider: Any = None, ledger: Any = None,
                      entities: list | None = None,
                      rw_store: Any = None) -> MCPServer:
    handlers = MCPServerHandlers(
        graph=graph,
        store=store,
        node_map=node_map,
        dense_provider=dense_provider,
        ledger=ledger,
        entities=entities,
        rw_store=rw_store,
    )
    server = MCPServer()
    server.register_tool("code.search", handlers.code_search, "Hybrid BM25 + graph retrieval with RRF + rerank")
    server.register_tool("code.definition", handlers.code_definition, "Symbol lookup")
    server.register_tool("graph.query", handlers.graph_query, "Bitemporal graph lookup with asOf")
    server.register_tool("verify.diff", handlers.verify_diff, "Semi-formal + blast radius verification")
    server.register_tool("task.run", handlers.task_run, "Planner → Compiler → Scheduler")
    server.register_tool("task.status", handlers.task_status, "Scheduler-backed DAG execution status")
    return server

