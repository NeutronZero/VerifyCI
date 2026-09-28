import asyncio
from typing import Any

from src.contracts.scheduler import TERMINAL_STATUSES, TaskStatus


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
    from src.retrieval.sparse import BM25Retriever

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
    from src.observability.tracing import start_agent_span
    from src.orchestration.scheduler import AsyncDAGScheduler

    server = MCPServer()
    scheduler = AsyncDAGScheduler(ledger=ledger)
    if entities is None:
        from src.interface.commands.graph_loader import payload_entities
        entities = payload_entities(graph)

    async def code_search(query: str, k: int = 10, conversation_id: str = "") -> dict:
        from src.retrieval.dense import SearchResult
        from src.retrieval.fusion import rrf_fusion
        from src.retrieval.graph_retriever import GraphRetriever
        from src.retrieval.reranker import CrossEncoderReranker

        with start_agent_span("code.search", conversation_id, "code.search"):
            if graph is None:
                return {"results": [], "query": query, "methods": [], "error": "no_graph_loaded"}
            from src.retrieval.provider import HashEmbeddingProvider
            provider = dense_provider or HashEmbeddingProvider()
            bm25, texts = _describe_graph(graph, node_map or {})
            sparse_hits = bm25.search(query, k=k)
            seeds = [h.id for h in sparse_hits[:3]]
            graph_hits = GraphRetriever(graph, node_map or {}).retrieve(seeds)
            try:
                q_emb = (await provider.embed([query]))[0]
                t_embs = await provider.embed([texts[e] for e in list(texts)[:500]])
                dense_hits = []
                for eid, t_emb in zip(list(texts)[:500], t_embs):
                    dot = sum(a * b for a, b in zip(q_emb, t_emb))
                    dense_hits.append(SearchResult(id=eid, score=dot, metadata={"text": texts[eid]}))
                dense_hits.sort(key=lambda r: r.score, reverse=True)
                dense_hits = dense_hits[:k]
            except Exception:  # noqa: BLE001
                dense_hits = [SearchResult(id=h.id, score=h.score, metadata={"text": texts.get(h.id, "")}) for h in sparse_hits]
            fused = rrf_fusion(dense_hits, sparse_hits, graph_hits)
            reranker = CrossEncoderReranker()
            reranked = reranker.rerank(
                query, [SearchResult(id=i, score=0.0, metadata={"text": texts.get(i, i)}) for i in fused], k=k)
            return {"results": [{"id": r.id, "score": r.score} for r in reranked],
                    "query": query, "methods": ["bm25", "graph", "rrf", f"rerank:{reranker.backend}"]}

    async def code_definition(symbol: str) -> dict:
        if store is None:
            return {"symbol": symbol, "definition": None, "error": "no_store_loaded"}
        entity = store.get_entity_by_logical(symbol)
        if entity is None and hasattr(store, "get_entity_by_name"):
            entity = store.get_entity_by_name(symbol)
        if entity:
            return {"symbol": symbol, "definition": {"file_path": entity.file_path,
                    "line_start": entity.line_start, "line_end": entity.line_end,
                    "revision_entity_id": entity.revision_entity_id}}
        return {"symbol": symbol, "definition": None}

    async def graph_query(query: str, asOf: float | None = None) -> dict:
        if store is None:
            return {"query": query, "asOf": asOf, "results": [], "error": "no_store_loaded"}
        entity = store.get_entity_by_logical(query, asOf=asOf)
        if entity is None and hasattr(store, "get_entity_by_name"):
            entity = store.get_entity_by_name(query)
        if entity:
            return {"query": query, "asOf": asOf,
                    "results": [{"name": entity.name, "file_path": entity.file_path,
                                 "revision_entity_id": entity.revision_entity_id}]}
        return {"query": query, "asOf": asOf, "results": []}

    async def verify_diff(diff: str, revision_id: str = "", conversation_id: str = "") -> dict:
        from src.contracts.verification_ir import CheckResult, VerificationPolicy
        from src.verification.blast_radius import blast_radius_check
        from src.verification.diffmap import map_files_to_entity_ids, parse_diff_files
        from src.verification.intent_align import evaluate_invariants
        from src.verification.policy import PolicyEvaluator
        from src.verification.semi_formal_reason import SemiFormalReasoner
        from src.verification.verification_ir import build_verification_report

        with start_agent_span("verify.diff", conversation_id, "verify.diff"):
            reasoner = SemiFormalReasoner()
            cert = reasoner.verify(diff=diff, graph=graph, node_map=node_map,
                                   entities=entities or None)
            checks = [CheckResult(
                check_id="semi_formal", passed=cert.certificate_verified, score=cert.confidence,
                evidence=[e.file_path for e in cert.evidence],
                explanation=cert.conclusion.reasoning, certificate=cert,
            )]
            files = parse_diff_files(diff)
            mapping = map_files_to_entity_ids(files, entities or [])
            changed = sorted({eid for eids in mapping.values() for eid in eids})
            blast, blast_check = blast_radius_check(
                graph=graph, changed_entities=changed, test_entities=set(), node_map=node_map)
            checks.append(blast_check)
            inv_checks, _metrics = evaluate_invariants(
                diff, _mcp_invariants(), graph, evidence=list(cert.evidence))
            checks.extend(inv_checks)
            report = build_verification_report(task_id="mcp_verify", policy_id="default",
                                               checks=checks, blast_radius=blast)
            policy = VerificationPolicy(policy_id="default", on_failure="block",
                                        on_inconclusive="human_review", on_human_review="block",
                                        require_deterministic_checker=True)
            decision = PolicyEvaluator().evaluate(report, policy)
            return {"diff": diff, "revision_id": revision_id, "status": decision.status,
                    "report_id": report.report_id, "rationale": decision.rationale,
                    "files": files, "changed_entities": changed}

    async def task_run(task: str, conversation_id: str = "", diff: str = "") -> dict:
        from src.orchestration.compiler.validation import validate_task_ir
        from src.orchestration.intent import build_intent_package
        from src.orchestration.planner import Planner

        with start_agent_span("task.run", conversation_id, "task.run"):
            planner = Planner()
            intent = build_intent_package(task)
            task_ir = planner.plan(task, intent.intent_package_id, "default")
            if not validate_task_ir(task_ir):
                return {"task": task, "status": "FAILED", "error": "invalid_task_ir"}
            context = {
                "graph": graph, "node_map": node_map, "entities": entities,
                "invariants": intent.invariants + _mcp_invariants(),
                "diff": diff, "store": store,
            }
            task_id = await scheduler.submit(task_ir, conversation_id=conversation_id,
                                             context=context)
        for _ in range(300):
            status = await scheduler.status(task_id)
            if status in TERMINAL_STATUSES:
                decision = scheduler.decision(task_id)
                return {"task": task, "task_id": task_id, "status": status.value,
                        "steps": len(task_ir.steps),
                        "decision": decision.status if decision else None}
            await asyncio.sleep(0.1)
        return {"task": task, "task_id": task_id, "status": "TIMEOUT"}

    async def task_status(task_id: str) -> dict:
        status = await scheduler.status(task_id)
        decision = scheduler.decision(task_id)
        return {"task_id": task_id, "status": status.value,
                "decision": decision.status if decision else None}

    server.register_tool("code.search", code_search, "Hybrid BM25 + graph retrieval with RRF + rerank")
    server.register_tool("code.definition", code_definition, "Symbol lookup")
    server.register_tool("graph.query", graph_query, "Bitemporal graph lookup with asOf")
    server.register_tool("verify.diff", verify_diff, "Semi-formal + blast radius verification")
    server.register_tool("task.run", task_run, "Planner → Compiler → Scheduler")
    server.register_tool("task.status", task_status, "Scheduler-backed DAG execution status")

    return server


def _mcp_invariants():
    from src.contracts.verification_ir import Invariant
    return [
        Invariant(invariant_id="secrets_scan", rule="no hardcoded secrets",
                  compiled_query="secrets_scan", blocking=True),
        Invariant(invariant_id="provenance_check", rule="claims traceable to files",
                  compiled_query="provenance_check", blocking=False),
    ]
