"""Dense-provider comparison: offline hash vs Ollama embeddings.

Needs a live server (`ollama serve` + `ollama pull nomic-embed-text`);
without one it prints SKIP and exits 0 — this benchmark never gates CI.
Compares dense-only and RRF-hybrid rankings on the lexical set from
`retrieval_eval` plus a small paraphrase set (queries sharing no content
words with their relevant docs). Sample is small (5+5); treat deltas as
directional, not as a gate.
"""
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.retrieval_eval import (  # noqa: E402
    CORPUS,
    QUERIES,
    _dense_ranked,
    ndcg_at,
    recall_at,
)
from src.retrieval.dense import SearchResult  # noqa: E402
from src.retrieval.fusion import rrf_fusion  # noqa: E402
from src.retrieval.provider import (  # noqa: E402
    HashEmbeddingProvider,
    OllamaEmbeddingProvider,
)
from src.retrieval.sparse import BM25Retriever  # noqa: E402

PARAPHRASE = {
    "how do I sign in": {"auth_login", "auth_oauth"},
    "evolve the db structure": {"db_migrate", "db_query"},
    "which routines invoke this procedure": {"graph_traverse", "graph_build"},
    "execute the workflow DAG": {"sched_dag"},
    "moderation verdict rules": {"verify_policy"},
}


def _server_up(provider) -> bool:
    async def _probe():
        try:
            await provider.embed(["probe"])
            return True
        except Exception:  # noqa: BLE001
            return False
    return asyncio.run(_probe())


async def _hybrid(provider, query: str) -> list[str]:
    bm25 = BM25Retriever()
    for doc_id, text in CORPUS.items():
        bm25.add(doc_id, text)
    sparse = bm25.search(query, k=10)
    qvec = (await provider.embed([query]))[0]
    scored = []
    for doc_id, text in CORPUS.items():
        (tvec,) = await provider.embed([text])
        scored.append((doc_id, sum(a * b for a, b in zip(qvec, tvec))))
    scored.sort(key=lambda t: t[1], reverse=True)
    dense = [SearchResult(id=d, score=1.0 / (i + 1), metadata={})
             for i, (d, _) in enumerate(scored)]
    return rrf_fusion(dense, sparse, [])


async def _bench(provider, queries):
    dense_recs, dense_ndcgs, hyb_recs, hyb_ndcgs = [], [], [], []
    t0 = time.time()
    for query, relevant in queries.items():
        dense = await _dense_ranked(provider, query)
        ranked = await _hybrid(provider, query)
        dense_recs.append(recall_at(dense, relevant, 5))
        dense_ndcgs.append(ndcg_at(dense, relevant, 10))
        hyb_recs.append(recall_at(ranked, relevant, 5))
        hyb_ndcgs.append(ndcg_at(ranked, relevant, 10))
    dt = time.time() - t0
    avg = lambda xs: sum(xs) / len(xs)  # noqa: E731
    return avg(dense_recs), avg(dense_ndcgs), avg(hyb_recs), avg(hyb_ndcgs), dt


def main() -> int:
    providers = [("hash", HashEmbeddingProvider())]
    ollama = OllamaEmbeddingProvider()
    if _server_up(ollama):
        providers.append(("ollama/" + ollama.model, ollama))
    else:
        print("SKIP: no Ollama server (ollama serve + pull nomic-embed-text)")
        return 0
    for name, provider in providers:
        for label, queries in [("lexical", QUERIES), ("paraphrase", PARAPHRASE)]:
            r5, n10, hr5, hn10, dt = asyncio.run(_bench(provider, queries))
            print(f"{name:28} {label:10} dense R@5={r5:.3f} N@10={n10:.3f} "
                  f"hybrid R@5={hr5:.3f} N@10={hn10:.3f} ({dt:.1f}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
