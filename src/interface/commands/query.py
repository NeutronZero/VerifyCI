import asyncio

from src.contracts.evidence import SourceChunk
from src.contracts.vector_store import InMemoryVectorStore, VectorRecord
from src.interface.commands import resolve_db
from src.retrieval.blast_radius import compute_blast_radius
from src.retrieval.dense import SearchResult
from src.retrieval.evidence import build_evidence_pack
from src.retrieval.fusion import rrf_fusion
from src.retrieval.graph_retriever import GraphRetriever
from src.retrieval.provider import HashEmbeddingProvider
from src.retrieval.reranker import CrossEncoderReranker
from src.retrieval.sparse import BM25Retriever
from src.storage.graph_store import GraphStore


def run_query(question: str, db_path: str | None = None, k: int = 10,
              dense_provider=None) -> dict:
    from src.graph.builder import GraphBuilder

    db = resolve_db(db_path)
    store = GraphStore(db)
    try:
        rows = store.conn.execute(
            "SELECT revision_entity_id, name, file_path FROM entities LIMIT 5000"
        ).fetchall()
        texts = {rid: f"{name} {fpath}" for rid, name, fpath in rows}

        bm25 = BM25Retriever()
        for rid, text in texts.items():
            bm25.add(rid, text)
        sparse_hits = bm25.search(question, k=k)

        provider = dense_provider or HashEmbeddingProvider()
        dense_hits = _dense_search(provider, texts, question, k)

        builder = GraphBuilder()
        entities = [store._row_to_entity(r) for r in store.conn.execute("SELECT * FROM entities LIMIT 5000").fetchall()]
        edges = [store._row_to_edge(r) for r in store.conn.execute("SELECT * FROM edges LIMIT 20000").fetchall()]
        graph = builder.build(entities, edges) if entities else None
        node_map = builder.get_node_map()
        seeds = [h.id for h in sparse_hits[:3]]
        graph_hits = GraphRetriever(graph, node_map).retrieve(seeds) if graph is not None else []

        fused = rrf_fusion(dense_hits, sparse_hits, graph_hits)
        reranked = CrossEncoderReranker().rerank(
            question,
            [SearchResult(id=i, score=0.0, metadata={"text": texts.get(i, i)}) for i in fused],
            k=k,
        )
        by_id = {e.revision_entity_id: e for e in entities}
        pack_entities = [by_id[i] for i in [r.id for r in reranked] if i in by_id]
        chunks = [
            SourceChunk(
                chunk_id=f"chunk_{e.revision_entity_id[:12]}",
                file_path=e.file_path, line_start=e.line_start, line_end=e.line_end,
                content=f"{e.name} ({e.type.value}) @ {e.file_path}:{e.line_start}-{e.line_end}",
                source_hash=e.source_hash,
            )
            for e in pack_entities if e.source_hash
        ]
        blast = compute_blast_radius(
            graph, [r.id for r in reranked[:3]], set(), node_map=node_map or None)
        pack = build_evidence_pack(
            query=question, entities=pack_entities, relationships=[],
            source_chunks=chunks,
            scores={r.id: r.score for r in reranked},
            retrieval_methods=["dense:" + provider.model_name(), "bm25", "graph", "rrf", "rerank"],
            graph_revision=pack_entities[0].revision_id if pack_entities else "",
            blast_radius=blast,
        )
        return {"query": question,
                "results": [{"id": r.id, "score": r.score} for r in reranked],
                "evidence": {"entities": len(pack.entities), "chunks": len(pack.source_chunks),
                             "provenance": len(pack.provenance)}}
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
