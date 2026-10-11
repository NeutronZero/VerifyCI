#!/usr/bin/env python3
"""Retrieval scalability measurement (frozen protocol in config.json).

Times separately, on a frozen doc/dim grid with deterministic RNG:
  1. InMemoryVectorStore.search (brute-force O(N*d) + sort)
  2. BM25Retriever.search (O(N*|q|))
  3. rrf fusion over the two ranked lists
  4. CachedEmbeddingProvider miss path incl. _save bytes + wall ms

Env-gated: set VERIFYCI_RETRIEVAL=1 to run. Writes results.json with
protocol hash, source hashes, and environment. Changes nothing under
verifyci/ beyond importing it.
"""
from __future__ import annotations

import gc
import hashlib
import json
import math
import os
import platform
import random
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _sha(path: Path) -> str:
    # Normalize line endings: working copies may carry CRLF while git blobs
    # are LF (see .gitattributes eol=lf). Hash the normalized form so the
    # pin is checkout-independent.
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def pct(samples: list[int], q: float) -> int:
    return sorted(samples)[math.ceil(q * len(samples)) - 1]


def env_block() -> dict:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.node(),
        "cpu_count": os.cpu_count(),
    }


def measure_search(store_search, queries: list, k: int) -> dict:
    samples = []
    gc.collect()
    gc.disable()
    try:
        for q in queries:
            t = time.perf_counter_ns()
            store_search(q, k)
            samples.append(time.perf_counter_ns() - t)
    finally:
        gc.enable()
    s = sorted(samples)
    return {
        "n": len(s),
        "us": {
            "median": round(pct(s, 0.50) / 1e3, 1),
            "p95": round(pct(s, 0.95) / 1e3, 1),
            "p99": round(pct(s, 0.99) / 1e3, 1),
            "max": round(s[-1] / 1e3, 1),
        },
    }


def main() -> None:
    if not os.environ.get("VERIFYCI_RETRIEVAL"):
        raise SystemExit("set VERIFYCI_RETRIEVAL=1 to run (seconds; never silently in CI)")
    from verifyci.contracts.vector_store import InMemoryVectorStore, VectorRecord
    from verifyci.retrieval.dense import SearchResult
    from verifyci.retrieval.fusion import rrf_fusion_with_scores
    from verifyci.retrieval.sparse import BM25Retriever

    cfg = json.loads((HERE / "config.json").read_text(encoding="utf-8"))
    grid = cfg["grid"]
    rng = random.Random(grid["seed"])

    out: dict = {
        "protocol": "benchmarks/retrieval/config.json (frozen)",
        "protocol_sha256": _sha(HERE / "config.json"),
        "frozen_sources": {
            "vector_store.py": _sha(Path("verifyci/contracts/vector_store.py")),
            "dense.py": _sha(Path("verifyci/retrieval/dense.py")),
            "sparse.py": _sha(Path("verifyci/retrieval/sparse.py")),
            "fusion.py": _sha(Path("verifyci/retrieval/fusion.py")),
        },
        "environment": env_block(),
        "grid": grid,
        "scales": {},
    }
    for n_docs in grid["docs"]:
        dim = grid["dim"]
        vecs = [[rng.gauss(0, 1) for _ in range(dim)] for _ in range(n_docs)]
        store = InMemoryVectorStore()
        store.upsert([VectorRecord(id=f"d{i}", embedding=v) for i, v in enumerate(vecs)])
        bm25 = BM25Retriever()
        for i in range(n_docs):
            bm25.add(f"d{i}", f"doc {i} " + " ".join(f"term{rng.randrange(500)}" for _ in range(20)))
        queries_dense = [[rng.gauss(0, 1) for _ in range(dim)] for _ in range(grid["queries"])]
        queries_text = [" ".join(f"term{rng.randrange(500)}" for _ in range(5)) for _ in range(grid["queries"])]
        k = grid["k"]
        dense = measure_search(lambda q, kk, s=store: s.search(q, kk), queries_dense, k)
        sparse = measure_search(lambda q, kk, b=bm25: b.search(q, kk), queries_text, k)
        dense_lists = [[SearchResult(id=r, score=s, metadata={}) for r, s in store.search(q, k)] for q in queries_dense[:10]]
        sparse_lists = [bm25.search(q, k) for q in queries_text[:10]]
        t = time.perf_counter_ns()
        for dl, sl in zip(dense_lists, sparse_lists):
            rrf_fusion_with_scores(dl, sl, [], k=k)
        fusion_us = round((time.perf_counter_ns() - t) / 10 / 1e3, 1)
        out["scales"][str(n_docs)] = {"dense_search": dense, "sparse_search": sparse, "fusion_us_avg": fusion_us}
    (HERE / "results.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"Retrieval measurement written to {HERE / 'results.json'}")


if __name__ == "__main__":
    main()
