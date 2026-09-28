"""Offline retrieval micro-benchmark (no network, no models).

Corpus + relevance judgments live here so both the CLI path and the test
suite measure the same thing. This is a smoke-scale stand-in for the
BEIR-style gate (hybrid nDCG@10 >= dense-only + margin on real data);
 Hypotheses it checks: hybrid recall is perfect on exact topics and the
fusion never degrades the dense-only ordering below parity.
"""
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.retrieval.dense import SearchResult
from src.retrieval.fusion import rrf_fusion
from src.retrieval.provider import HashEmbeddingProvider
from src.retrieval.reranker import OfflineReranker
from src.retrieval.sparse import BM25Retriever

CORPUS = {
    "auth_login": "authentication login password user session",
    "auth_oauth": "authentication oauth token refresh grant",
    "db_query": "database query sql connection pool",
    "db_migrate": "database migration schema version upgrade",
    "graph_traverse": "graph traversal callers callees blast radius",
    "graph_build": "graph builder nodes edges rustworkx",
    "sched_dag": "scheduler dag task execution topological",
    "verify_policy": "verification policy decision pass fail review",
}

QUERIES = {
    "how does login work": {"auth_login", "auth_oauth"},
    "migrate the database schema": {"db_migrate", "db_query"},
    "who calls this function": {"graph_traverse", "graph_build"},
    "run the task dag": {"sched_dag"},
    "policy review decision": {"verify_policy"},
}


def _dcg(ranked: list[str], relevant: set[str], k: int) -> float:
    return sum((1.0 / math.log2(i + 2)) for i, doc in enumerate(ranked[:k]) if doc in relevant)


def ndcg_at(ranked: list[str], relevant: set[str], k: int = 10) -> float:
    if not relevant:
        return 0.0
    ideal = _dcg(sorted(relevant), relevant, k)
    return _dcg(ranked, relevant, k) / ideal if ideal else 0.0


def recall_at(ranked: list[str], relevant: set[str], k: int = 5) -> float:
    if not relevant:
        return 0.0
    return len(set(ranked[:k]) & relevant) / len(relevant)


async def _dense_ranked(provider, query: str) -> list[str]:
    qvec = (await provider.embed([query]))[0]
    scored = []
    for doc_id, text in CORPUS.items():
        (tvec,) = await provider.embed([text])
        dot = sum(a * b for a, b in zip(qvec, tvec))
        scored.append((doc_id, dot))
    scored.sort(key=lambda t: t[1], reverse=True)
    return [d for d, _ in scored]


def _hybrid_ranked(provider, query: str, k: int = 10) -> list[str]:
    bm25 = BM25Retriever()
    for doc_id, text in CORPUS.items():
        bm25.add(doc_id, text)
    sparse = bm25.search(query, k=k)
    import asyncio
    dense_ids = asyncio.run(_dense_ranked_async(provider, query))
    dense = [SearchResult(id=d, score=1.0 / (i + 1), metadata={"text": CORPUS[d]})
             for i, d in enumerate(dense_ids)]
    fused = rrf_fusion(dense, sparse, [])
    reranked = OfflineReranker().rerank(
        query, [SearchResult(id=d, score=0.0, metadata={"text": CORPUS[d]}) for d in fused], k=k)
    return [r.id for r in reranked]


async def _dense_ranked_async(provider, query: str) -> list[str]:
    return await _dense_ranked(provider, query)


def run_benchmark(k_recall: int = 5, k_ndcg: int = 10) -> dict:
    import asyncio
    provider = HashEmbeddingProvider()
    recs, ndcgs, dense_ndcgs = [], [], []
    for query, relevant in QUERIES.items():
        hybrid = _hybrid_ranked(provider, query)
        dense = asyncio.run(_dense_ranked(provider, query))
        recs.append(recall_at(hybrid, relevant, k_recall))
        ndcgs.append(ndcg_at(hybrid, relevant, k_ndcg))
        dense_ndcgs.append(ndcg_at(dense, relevant, k_ndcg))
    return {
        "queries": len(QUERIES),
        f"recall@{k_recall}": sum(recs) / len(recs),
        f"ndcg@{k_ndcg}": sum(ndcgs) / len(ndcgs),
        f"dense_only_ndcg@{k_ndcg}": sum(dense_ndcgs) / len(dense_ndcgs),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run_benchmark(), indent=2))
