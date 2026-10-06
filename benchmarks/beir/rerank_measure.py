#!/usr/bin/env python3
"""H1-RR measurement: hybrid + cross-encoder rerank (separate claim lineage).

Frozen protocol: same corpus/queries/qrels/scoring/tiebreak as the H1 gate.
Only the hybrid channel differs: equal-weight RRF top-20 re-scored by a
local-only cross-encoder to top-10 with (-score, docid) tiebreak.
Requires a loadable local CrossEncoder (never downloads); fails closed
otherwise. Writes rerank_revision/results.json. Frozen H1 artifacts untouched.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REVISION = HERE / "rerank_revision"
MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"
RERANK_DEPTH = 20


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def main() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("beir_harness", HERE / "eval_harness.py")
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)

    from verifyci.contracts.vector_store import InMemoryVectorStore, VectorRecord
    from verifyci.retrieval.sparse import BM25Retriever

    try:
        from sentence_transformers import CrossEncoder  # type: ignore
        ce = CrossEncoder(MODEL, local_files_only=True)
    except Exception as e:  # noqa: BLE001
        raise SystemExit(f"H1-RR requires local model {MODEL!r}: {e}")

    corpus, queries = h.load()
    errs = h.validate(corpus, queries)
    fatal = [e for e in errs if not e.startswith("gate UNESTABLISHED")]
    assert fatal == [], fatal
    cache = json.loads((HERE / "embedding_cache_nomic_embed_text.json").read_text(encoding="utf-8"))

    async def _embed(texts):
        return [[float(x) for x in cache[hashlib.sha256(t.encode()).hexdigest()]] for t in texts]

    doc_ids = list(corpus)
    vecs = asyncio.run(_embed([corpus[d] for d in doc_ids] + [q["text"] for q in queries]))
    doc_vecs, q_vecs = vecs[:len(doc_ids)], vecs[len(doc_ids):]
    store = InMemoryVectorStore()
    store.upsert([VectorRecord(id=d, embedding=v) for d, v in zip(doc_ids, doc_vecs)])
    bm25 = BM25Retriever()
    for d, text in corpus.items():
        bm25.add(d, text)

    k = 10
    ndc, nch = [], []
    for q, qv in zip(queries, q_vecs):
        dense = h._tiebreak_rank(list(store.search(qv, k=len(doc_ids))))[:k]
        sparse = [r.id for r in bm25.search(q["text"], k=k)]
        scores: dict[str, float] = {}
        for rank, did in enumerate(dense):
            scores[did] = scores.get(did, 0) + 1.0 / (60 + rank + 1)
        for rank, did in enumerate(sparse):
            scores[did] = scores.get(did, 0) + 1.0 / (60 + rank + 1)
        fused = [d for d, _ in sorted(scores.items(), key=lambda t: -t[1])]
        top = fused[:RERANK_DEPTH]
        s = ce.predict([(q["text"], corpus[d]) for d in top]).tolist()
        hybrid = [d for d, _ in sorted(zip(top, s), key=lambda t: (-t[1], t[0]))][:k]
        r = q["relevance"]
        ndc.append(h.ndcg_at(dense, r, k))
        nch.append(h.ndcg_at(hybrid, r, k))
    dense_ndcg = sum(ndc) / len(ndc)
    hybrid_ndcg = sum(nch) / len(nch)
    delta = hybrid_ndcg - dense_ndcg
    established = (delta >= 0.05 and len(queries) >= 50 and not errs
                   and not any("drift" in str(e).lower() for e in errs))
    REVISION.mkdir(exist_ok=True)
    report = {
        "frozen": {"corpus_sha256": _sha(HERE / "corpus.jsonl"),
                   "qrels_sha256": _sha(HERE / "qrels.jsonl"),
                   "config_sha256": _sha(HERE / "config.json"),
                   "revision_config_sha256": None,
                   "model_dense": "nomic-embed-text",
                   "model_rerank": MODEL, "rerank_depth": RERANK_DEPTH,
                   "rrf_k": 60, "k_ndcg": 10},
        "run": {"provider": "cached:nomic-embed-text+local-cross-encoder",
                "queries": len(queries), "documents": len(corpus), "dry_run": False},
        "metrics": {"dense": {"ndcg": dense_ndcg}, "hybrid": {"ndcg": hybrid_ndcg},
                    "delta_ndcg": delta},
        "validators": {"errors": errs, "drift": False},
        "gate": {"established": established,
                 "rule": "H1-RR: (hybrid_reranked - dense) >= +0.05 AND queries >= 50 AND validators passed",
                 "note": "recorded gate boolean is provenance only; canonical predicate derives establishment"},
    }
    (REVISION / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"H1-RR: dense={dense_ndcg:.4f} hybrid={hybrid_ndcg:.4f} delta={delta:+.4f} "
          f"established={established}")
    print(f"report -> {REVISION / 'results.json'}")


if __name__ == "__main__":
    main()
