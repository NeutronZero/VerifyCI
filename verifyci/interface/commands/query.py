import asyncio
import sqlite3

from verifyci.contracts.evidence import SourceChunk
from verifyci.contracts.vector_store import InMemoryVectorStore, VectorRecord
from verifyci.interface.commands import resolve_db
from verifyci.retrieval.blast_radius import compute_blast_radius
from verifyci.retrieval.dense import SearchResult
from verifyci.retrieval.evidence import build_evidence_pack
from verifyci.retrieval.fusion import rrf_fusion_with_scores
from verifyci.retrieval.graph_retriever import GraphRetriever
from verifyci.retrieval.provider import HashEmbeddingProvider
from verifyci.retrieval.reranker import CrossEncoderReranker
from verifyci.retrieval.sparse import BM25Retriever
from verifyci.storage.graph_store import GraphStore


def run_query(question: str, db_path: str | None = None, k: int = 10,
              dense_provider=None, rerank: bool = False) -> dict:
    """Fused-only is the default path. The offline reranker demotes correct
    fused answers about as often as it lifts them (measured 2 lifts / 4
    demotions across two repos), so it is opt-in per query shape, not default.
    """
    from verifyci.graph.builder import GraphBuilder

    import time as _qt
    _qstart = _qt.time()
    _qstatus = "ok"

    def _emit_log(_result=None):
        try:
            from verifyci.env import get_env as _ql_env
            from verifyci.observability.querylog import QueryLogger as _QL
            _log_path = _ql_env("QUERYLOG") or ""
            if not _log_path:
                return
            _dur = (_qt.time() - _qstart) * 1000.0
            _n = len((_result or {}).get("results", [])) if isinstance(_result, dict) else 0
            _QL(_log_path).log_query(question, caller="run_query",
                                     duration_ms=_dur, results_count=_n, status=_qstatus)
        except Exception:  # noqa: BLE001
            pass

    db = resolve_db(db_path)
    import os as _query_os
    if not _query_os.path.exists(db):
        _r = {"query": question, "results": [], "methods": [],
                "evidence": {"entities": 0, "chunks": 0, "provenance": 0},
                "error": "db_not_found"}
        _qstatus = "db_not_found"
        _emit_log(_r)
        return _r
    try:
        store = GraphStore(db, read_only=True)
    except sqlite3.Error as e:
        # An unreadable store is infrastructure, not "no hits": the CLI
        # maps the error key to exit 3 instead of a green zero-answer.
        _r = {"query": question, "results": [], "methods": [],
                "evidence": {"entities": 0, "chunks": 0, "provenance": 0},
                "error": f"db_unreadable: {e}"}
        _qstatus = "db_unreadable"
        _emit_log(_r)
        return _r
    try:
        # Search the latest revision only: older revisions stay in the DB
        # for history, but returning superseded rows as answers is wrong.
        # Scoped to this DB's repo so a shared file never answers from
        # another repo's revision.
        from verifyci.interface.commands import resolve_repository
        rev = store.latest_revision_id(resolve_repository(db))
        # No row cap: truncating the corpus silently drops recall (measured:
        # LIMIT 5000 hid 1676 of 6676 entities on a real repo).
        # TODO(scaling): uncapped loads the whole revision per query — fine
        # at 10k rows, not at 100k. The answer is scoped retrieval (filter by
        # path prefix, or traverse the graph first and load only those
        # entity ids), not a bigger cap. Revisit before repos grow 10x.
        rows = store.conn.execute(
            "SELECT revision_entity_id, name, file_path FROM entities WHERE revision_id = ?",
            (rev,),
        ).fetchall() if rev else []
        from verifyci.retrieval.representation import build_doc_text
        texts = {rid: build_doc_text(name, fpath) for rid, name, fpath in rows}

        bm25 = BM25Retriever()
        for rid, text in texts.items():
            bm25.add(rid, text)
        sparse_hits = bm25.search(question, k=k)

        from verifyci.retrieval.provider import default_dense_provider
        import os as _os
        provider = dense_provider or default_dense_provider(
            _os.path.dirname(_os.path.abspath(db)))
        try:
            dense_hits = _dense_search(provider, texts, question, k)
            dense_label = provider.model_name()
        except Exception:  # noqa: BLE001
            # Advisory path (not a gate): an unreachable embedding
            # server degrades to the offline hash with an honest label,
            # never a failed query.
            provider = HashEmbeddingProvider()
            dense_hits = _dense_search(provider, texts, question, k)
            dense_label = "hash-fallback(server-unreachable)"

        builder = GraphBuilder()
        entities = [store._row_to_entity(r) for r in store.conn.execute(
            "SELECT * FROM entities WHERE revision_id = ? AND valid_until IS NULL", (rev,)).fetchall()] if rev else []
        edges = [store._row_to_edge(r) for r in store.conn.execute(
            "SELECT * FROM edges WHERE revision_id = ? AND valid_until IS NULL", (rev,)).fetchall()] if rev else []
        graph = builder.build(entities, edges) if entities else None
        node_map = builder.get_node_map()
        seeds: list[str] = []
        for d, s in zip(dense_hits, sparse_hits):
            for sid in (s.id, d.id):
                if sid not in seeds:
                    seeds.append(sid)
                if len(seeds) >= 3:
                    break
            if len(seeds) >= 3:
                break
        if len(seeds) < 3:
            for h in sparse_hits + dense_hits:
                if h.id not in seeds:
                    seeds.append(h.id)
                if len(seeds) >= 3:
                    break
        graph_hits = GraphRetriever(graph, node_map).retrieve(seeds) if graph is not None else []

        fused = rrf_fusion_with_scores(dense_hits, sparse_hits, graph_hits)
        methods = ["dense:" + dense_label, "bm25", "graph", "rrf"]
        if rerank:
            ranked = CrossEncoderReranker().rerank(
                question,
                [SearchResult(id=i, score=s, metadata={"text": texts.get(i, i)})
                 for i, s in fused],
                k=k,
            )
            methods = methods + ["rerank"]
        else:
            ranked = [SearchResult(id=i, score=s, metadata={}) for i, s in fused[:k]]
        by_id = {e.revision_entity_id: e for e in entities}
        pack_entities = [by_id[i] for i in [r.id for r in ranked] if i in by_id]
        chunks = [
            SourceChunk(
                chunk_id=f"chunk_{e.revision_entity_id[:12]}",
                file_path=e.file_path, line_start=e.line_start, line_end=e.line_end,
                content=f"{e.name} ({e.type.value}) @ {e.file_path}:{e.line_start}-{e.line_end}",
                source_hash=e.source_hash,
            )
            for e in pack_entities if e.source_hash
        ]
        from verifyci.graph.traverse import NodeMapError
        try:
            blast = compute_blast_radius(
                graph, [r.id for r in ranked[:3]], set(), node_map=node_map or None)
        except NodeMapError:
            # Informational path (not a gate): an unreadable graph yields
            # no blast data rather than a failed query. The verification
            # gate (blast_radius_check) treats this as inability instead.
            from verifyci.contracts.verification_ir import BlastRadiusResult
            blast = BlastRadiusResult(
                affected_callers=[], affected_callees=[], test_coverage_gap=[],
                risk_score=0.0, dependency_impact=[], vulnerability_impact=[])
        pack = build_evidence_pack(
            query=question, entities=pack_entities, relationships=[],
            source_chunks=chunks,
            scores={r.id: r.score for r in ranked},
            retrieval_methods=methods,
            graph_revision=pack_entities[0].revision_id if pack_entities else "",
            blast_radius=blast,
        )
        hits = []
        for r in ranked:
            e = by_id.get(r.id)
            hits.append({"id": r.id, "score": r.score,
                         "name": getattr(e, "name", None),
                         "file_path": getattr(e, "file_path", None),
                         "line_start": getattr(e, "line_start", None),
                         "line_end": getattr(e, "line_end", None)})
        _out = {"query": question,
                "results": hits,
                "methods": methods,
                "evidence": {"entities": len(pack.entities), "chunks": len(pack.source_chunks),
                             "provenance": len(pack.provenance)}}
        _emit_log(_out)
        return _out
    finally:
        store.close()


def _dense_search(provider, texts: dict, question: str, k: int) -> list[SearchResult]:
    async def _run():
        store = InMemoryVectorStore()
        ids = list(texts)
        vectors = await provider.embed([texts[i] for i in ids])
        store.upsert([VectorRecord(id=i, embedding=v) for i, v in zip(ids, vectors)])
        (qvec,) = await provider.embed([question])
        return [SearchResult(id=rid, score=score, metadata={"text": texts[rid]})
                for rid, score in store.search(qvec, k=k)]
    return asyncio.run(_run())
