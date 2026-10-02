import asyncio
from typing import Any

from verifyci.contracts.scheduler import TERMINAL_STATUSES


MAX_DIFF_CHARS = 1_000_000
MAX_TASK_DIFF_CHARS = 100_000


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


def create_mcp_server(graph=None, store=None, node_map: dict | None = None,
                      dense_provider: Any = None, ledger: Any = None,
                      entities: list | None = None) -> MCPServer:
    from verifyci.observability.tracing import start_agent_span
    from verifyci.orchestration.scheduler import AsyncDAGScheduler

    server = MCPServer()
    scheduler = AsyncDAGScheduler(ledger=ledger)
    if entities is None:
        from verifyci.interface.commands.graph_loader import payload_entities
        entities = payload_entities(graph)

    # Search-index reuse: the server is long-lived and loads the graph
    # once, but code_search used to rebuild the whole BM25 index (and its
    # texts map) on every call. Cache keyed on a structural fingerprint
    # of the graph; any node/edge change busts it, so a rebuilt graph is
    # never served stale. A graph that exposes no counts is always
    # rebuilt (no cheap staleness guard available).
    _index_cache: dict[str, Any] = {"key": None, "bm25": None, "texts": None}

    def _index_fingerprint():
        try:
            return (id(graph), int(graph.num_nodes()), int(graph.num_edges()))
        except Exception:  # noqa: BLE001 - adapter without counts
            return None

    def _search_index():
        key = _index_fingerprint()
        if key is None:
            return _describe_graph(graph, node_map or {})
        if _index_cache["key"] == key and _index_cache["bm25"] is not None:
            return _index_cache["bm25"], _index_cache["texts"]
        bm25, texts = _describe_graph(graph, node_map or {})
        _index_cache.update({"key": key, "bm25": bm25, "texts": texts})
        return bm25, texts

    # Revision-id index over the loaded revision: lets search hits carry
    # file/name/lines and lets definition/query resolve a revision id
    # directly, so an agent can chain search -> definition without
    # re-deriving a logical id or symbol name.
    by_revision_id = {}
    for _e in entities or []:
        _rid = getattr(_e, "revision_entity_id", None)
        if _rid and _rid not in by_revision_id:
            by_revision_id[_rid] = _e
    from verifyci.verification.config import load_repo_invariants
    _repo_invariants = load_repo_invariants(getattr(store, "db_path", None))

    async def code_search(query: str, k: int = 10, conversation_id: str = "",
                        rerank: bool = False) -> dict:
        from verifyci.retrieval.dense import SearchResult
        from verifyci.retrieval.fusion import rrf_fusion_with_scores
        from verifyci.retrieval.graph_retriever import GraphRetriever
        from verifyci.retrieval.reranker import CrossEncoderReranker

        with start_agent_span("code.search", conversation_id, "code.search"):
            if graph is None:
                return {"results": [], "query": query, "methods": [], "error": "no_graph_loaded"}
            from verifyci.retrieval.provider import default_dense_provider
            import os as _os
            cache_dir = None
            if store is not None and getattr(store, "db_path", None):
                cache_dir = _os.path.dirname(_os.path.abspath(store.db_path))
            provider = dense_provider or default_dense_provider(cache_dir)
            bm25, texts = _search_index()
            sparse_hits = bm25.search(query, k=k)
            seeds = [h.id for h in sparse_hits[:3]]
            graph_hits = GraphRetriever(graph, node_map or {}).retrieve(seeds)
            # One shared universe for both channels: the old code embedded
            # only the first 500 texts while BM25 indexed thousands, so the
            # two channels ranked disjoint document sets.
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
                # Dense is down: fuse sparse+graph only and SAY SO. The old
                # code substituted a copy of the sparse channel, silently
                # doubling every fused score while reporting a full fusion.
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
            return {"results": [_enriched_hit(r) for r in ranked],
                    "query": query, "methods": methods}

    def _enriched_hit(hit: Any) -> dict:
        entity = by_revision_id.get(hit.id)
        return {"id": hit.id, "score": hit.score,
                "name": getattr(entity, "name", None),
                "file_path": getattr(entity, "file_path", None),
                "line_start": getattr(entity, "line_start", None),
                "line_end": getattr(entity, "line_end", None)}

    def _resolve_symbol(symbol: str, asOf: float | None = None):
        # Revision id first (what search returns), then logical id,
        # then name — in that order, so chained lookups never miss.
        # The revision-id shortcut is timeless: with asOf given it is
        # skipped so the time filter (not the loaded revision) decides.
        if asOf is None and symbol in by_revision_id:
            return by_revision_id[symbol]
        if store is None:
            return None
        entity = store.get_entity_by_logical(symbol, asOf=asOf)
        if entity is None and hasattr(store, "get_entity_by_name"):
            entity = store.get_entity_by_name(symbol, as_of=asOf)
        return entity

    async def code_definition(symbol: str) -> dict:
        if store is None and symbol not in by_revision_id:
            return {"symbol": symbol, "definition": None, "error": "no_store_loaded"}
        entity = _resolve_symbol(symbol)
        if entity:
            return {"symbol": symbol, "definition": {"file_path": entity.file_path,
                    "line_start": entity.line_start, "line_end": entity.line_end,
                    "revision_entity_id": getattr(entity, "revision_entity_id", None)}}
        return {"symbol": symbol, "definition": None}

    async def graph_query(query: str, asOf: float | None = None) -> dict:
        if store is None and query not in by_revision_id:
            return {"query": query, "asOf": asOf, "results": [], "error": "no_store_loaded"}
        entity = _resolve_symbol(query, asOf=asOf)
        if entity:
            return {"query": query, "asOf": asOf,
                    "results": [{"name": entity.name, "file_path": entity.file_path,
                                 "revision_entity_id": getattr(
                                     entity, "revision_entity_id", None)}]}
        return {"query": query, "asOf": asOf, "results": []}

    async def verify_diff(diff: str, revision_id: str = "", conversation_id: str = "") -> dict:
        from verifyci.contracts.verification_ir import VerificationPolicy
        from verifyci.verification.blast_radius import blast_radius_check
        from verifyci.verification.diffmap import parse_diff_files, seed_entities_for_diff
        from verifyci.verification.intent_align import evaluate_invariants
        from verifyci.verification.policy import PolicyEvaluator
        from verifyci.verification.removal import removal_provenance_check
        from verifyci.verification.semi_formal_reason import SemiFormalReasoner
        from verifyci.verification.verification_ir import build_semi_check, build_verification_report

        with start_agent_span("verify.diff", conversation_id, "verify.diff"):
            if len(diff) > MAX_DIFF_CHARS:
                return {"revision_id": revision_id, "status": "FAILED", "error": "diff_too_large"}
            reasoner = SemiFormalReasoner()
            cert = reasoner.verify(diff=diff, graph=graph, node_map=node_map,
                                   entities=entities or None)
            files = parse_diff_files(diff)
            checks = [build_semi_check(cert, files, entities or [], diff=diff)]
            mapping = seed_entities_for_diff(files, entities or [], diff)
            changed = sorted({eid for eids in mapping.values() for eid in eids})
            blast, blast_check = blast_radius_check(
                graph=graph, changed_entities=changed, test_entities=set(), node_map=node_map)
            checks.append(blast_check)
            checks.append(removal_provenance_check(diff, entities or []))
            inv_checks, _metrics = evaluate_invariants(
                diff, _repo_invariants, graph, evidence=list(cert.evidence))
            checks.extend(inv_checks)
            report = build_verification_report(task_id="mcp_verify", policy_id="default",
                                               checks=checks, blast_radius=blast)
            policy = VerificationPolicy(policy_id="default", on_failure="block",
                                        on_inconclusive="human_review", on_human_review="block",
                                        require_deterministic_checker=True)
            decision = PolicyEvaluator().evaluate(report, policy)
            # Report the revision actually grounding the check (the
            # loaded entities'), not just the requested one.
            used_revision = revision_id
            if entities:
                used_revision = (getattr(entities[0], "revision_id", "")
                                 or revision_id)
            return {"revision_id": used_revision, "status": decision.status,
                    "report_id": report.report_id, "rationale": decision.rationale,
                    "files": files, "changed_entities": changed}

    async def task_run(task: str, conversation_id: str = "", diff: str = "") -> dict:
        from verifyci.orchestration.compiler.validation import validate_task_ir
        from verifyci.orchestration.intent import build_intent_package
        from verifyci.orchestration.planner import Planner

        with start_agent_span("task.run", conversation_id, "task.run"):
            if len(diff) > MAX_TASK_DIFF_CHARS:
                return {"task": task, "status": "FAILED", "error": "diff_too_large", "ledger_head": None}
            if len(task) > MAX_TASK_DIFF_CHARS:
                return {"task": task, "status": "FAILED", "error": "task_too_large", "ledger_head": None}
            planner = Planner()
            intent = build_intent_package(task)
            task_ir = planner.plan(task, intent.intent_package_id, "default")
            if not validate_task_ir(task_ir):
                return {"task": task, "status": "FAILED", "error": "invalid_task_ir",
                        "ledger_head": None}
            from verifyci.interface.commands.run import _dedupe_invariants
            context = {
                "graph": graph, "node_map": node_map, "entities": entities,
                "invariants": _dedupe_invariants(intent.invariants + _repo_invariants),
                "diff": diff, "store": store,
            }
            task_id = await scheduler.submit(task_ir, conversation_id=conversation_id,
                                             context=context)
        for _ in range(300):
            status = await scheduler.status(task_id)
            if status in TERMINAL_STATUSES:
                decision = scheduler.decision(task_id)
                head = scheduler.ledger_head(task_id)
                result = {"task": task, "task_id": task_id, "status": status.value,
                          "steps": len(task_ir.steps),
                          "decision": decision.status if decision else None,
                          "ledger_head": head}
                return result
            await asyncio.sleep(0.1)
        return {"task": task, "task_id": task_id, "status": "TIMEOUT",
                "ledger_head": None}

    async def task_status(task_id: str) -> dict:
        status = await scheduler.status(task_id)
        decision = scheduler.decision(task_id)
        return {"task_id": task_id, "status": status.value,
                "decision": decision.status if decision else None,
                "ledger_head": scheduler.ledger_head(task_id)}

    server.register_tool("code.search", code_search, "Hybrid BM25 + graph retrieval with RRF + rerank")
    server.register_tool("code.definition", code_definition, "Symbol lookup")
    server.register_tool("graph.query", graph_query, "Bitemporal graph lookup with asOf")
    server.register_tool("verify.diff", verify_diff, "Semi-formal + blast radius verification")
    server.register_tool("task.run", task_run, "Planner → Compiler → Scheduler")
    server.register_tool("task.status", task_status, "Scheduler-backed DAG execution status")

    return server

