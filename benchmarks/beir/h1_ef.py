"""H1-E/F: predeclared RRF k search + deterministic final measurement.

Input representation fixed by the frozen B/C/D selection rule (highest
hybrid Recall@5 -> H1-C signatures, 0.6909, no tie): this script takes
NO representation decision. k runs EXACTLY {20, 60, 120} through
PRODUCTION rrf_fusion (verifyci/retrieval/fusion.py) on the H1-C corpus;
the harness-local _rrf copy is not used anywhere here.

Ranking mirrors the frozen harness bit-for-bit (same stores, same
BM25, same tiebreak, same scorer, same 62 queries); only the fusion k
varies. H1-F selects by the frozen rule (recall -> nDCG -> smallest
change: k closest to the 60 control) and re-measures the winner once
as the final confirmation. Output merges into results_h1.json;
results.json and all frozen artifacts untouched.
"""
import asyncio
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from verifyci.contracts.vector_store import InMemoryVectorStore, VectorRecord  # noqa: E402
from verifyci.retrieval.fusion import rrf_fusion  # noqa: E402 PRODUCTION
from verifyci.retrieval.provider import (  # noqa: E402
    CachedEmbeddingProvider, OllamaEmbeddingProvider,
)
from verifyci.retrieval.sparse import BM25Retriever  # noqa: E402

KS = (20, 60, 120)
SCRATCH_CACHE = HERE / "embedding_cache_h1_nomic_embed_text.json"


def _harness():
    spec = importlib.util.spec_from_file_location("beir_harness", HERE / "eval_harness.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def _embed_all(provider, doc_ids, doc_texts, queries):
    vecs = await provider.embed(doc_texts + [q["text"] for q in queries])
    return vecs[:len(doc_ids)], vecs[len(doc_ids):]


def _rank(h, corpus, queries, provider, k):
    doc_ids = list(corpus)
    doc_vecs, q_vecs = asyncio.run(
        _embed_all(provider, doc_ids, [corpus[d] for d in doc_ids], queries))
    store = InMemoryVectorStore()
    store.upsert([VectorRecord(id=d, embedding=v) for d, v in zip(doc_ids, doc_vecs)])
    bm25 = BM25Retriever()
    for d, text in corpus.items():
        bm25.add(d, text)
    out = {}
    for q, qv in zip(queries, q_vecs):
        dense = store.search(qv, k=len(doc_ids))
        dense_ranked = h._tiebreak_rank(list(dense))[:10]
        sparse_ranked = [r.id for r in bm25.search(q["text"], k=10)]
        dense_res = [h._res(i) for i in dense_ranked]
        sparse_res = [h._res(i) for i in sparse_ranked]
        out[q["qid"]] = {
            "dense": dense_ranked,
            "hybrid": list(rrf_fusion(dense_res, sparse_res, [], k))[:10],
        }
    return out


def _metrics(h, rankings, queries):
    m = h.score(rankings, queries)
    d, hy = m["dense"], m["hybrid"]
    return {"dense": d, "hybrid": hy, "delta_ndcg": hy["ndcg"] - d["ndcg"]}


def main() -> None:
    h = _harness()
    recorded = json.loads((HERE / "results.json").read_text(encoding="utf-8"))
    frozen = recorded["frozen"]
    assert _sha(HERE / "corpus.jsonl") == frozen["corpus_sha256"]
    assert _sha(HERE / "qrels.jsonl") == frozen["qrels_sha256"]
    assert _sha(HERE / "config.json") == frozen["config_sha256"]
    assert frozen["rrf_k"] == 60, "control k must be the frozen 60"

    _, queries = h.load()
    corpus_c = json.loads((HERE / "corpus_h1_c.json").read_text(encoding="utf-8"))
    assert set(corpus_c) == {d for d in h.load()[0]}, "H1-C corpus ids drifted"
    fatal = [e for e in h.validate(corpus_c, queries)
             if not e.startswith("gate UNESTABLISHED")]
    assert fatal == [], fatal

    config = json.loads((HERE / "config.json").read_text(encoding="utf-8"))
    provider = CachedEmbeddingProvider(
        OllamaEmbeddingProvider(model=config["model"], base_url=config["ollama_url"]),
        str(SCRATCH_CACHE),
    )
    results = {}
    for k in KS:
        rankings = _rank(h, corpus_c, queries, provider, k)
        results[str(k)] = _metrics(h, rankings, queries)
        m = results[str(k)]
        print(f"H1-E k={k}: hybrid R@5={m['hybrid']['recall']:.4f} "
              f"nDCG={m['hybrid']['ndcg']:.4f} delta={m['delta_ndcg']:+.4f}")

    # Frozen selection: recall -> nDCG -> k closest to the 60 control.
    def _key(k):
        m = results[str(k)]
        return (m["hybrid"]["recall"], m["hybrid"]["ndcg"], -abs(k - 60))
    best_k = max(KS, key=_key)
    # H1-F: one final measurement of the selected combination.
    f_rankings = _rank(h, corpus_c, queries, provider, best_k)
    f_metrics = _metrics(h, f_rankings, queries)
    assert f_metrics == results[str(best_k)], "final pass did not reproduce E"

    dest = HERE / "results_h1.json"
    report = json.loads(dest.read_text(encoding="utf-8"))
    report["h1_e"] = {"representation": "H1-C (frozen-rule selection)",
                      "ks": list(KS), "production_rrf": True, "results": results,
                      "selected_k": best_k}
    report["h1_f"] = {"representation": "H1-C", "k": best_k,
                      "metrics": f_metrics,
                      "selection_rule": "recall -> nDCG -> smallest change"}
    dest.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"H1-F: (H1-C, k={best_k}) R@5={f_metrics['hybrid']['recall']:.4f} "
          f"nDCG={f_metrics['hybrid']['ndcg']:.4f}")
    print(f"report -> {dest.name} (results.json untouched)")


if __name__ == "__main__":
    main()
