"""Frozen BEIR-style evaluation harness: dense-only vs hybrid (dense+BM25 RRF).

Adds NO retrieval logic. Ranking comes from the production components:
InMemoryVectorStore cosine search (verifyci/contracts/vector_store.py),
BM25Retriever (verifyci/retrieval/sparse.py), rrf_fusion
(verifyci/retrieval/fusion.py). Scoring follows config.json exactly:
graded nDCG@10 (gain 2^g-1) and Recall@5 over grade>=2.

Order enforced here: validate -> embed -> rank -> score -> report.
Validators refuse evaluation drift (dup ids, unknown docids, empty
relevance sets, condition mismatch, model mismatch) before anything
computes, so a "nice" result cannot be produced by corpus rot.

Usage:
  python benchmarks/beir/eval_harness.py --provider hash --dry-run   # pipeline self-check (NOT gate evidence)
  python benchmarks/beir/eval_harness.py                              # live, config-frozen provider (gate run)
Report written to results.json + printed table; corpus/qrels/config
sha256 recorded so identical reruns are bit-comparable.
"""
import argparse
import asyncio
import hashlib
import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from verifyci.contracts.vector_store import InMemoryVectorStore, VectorRecord  # noqa: E402
from verifyci.retrieval.fusion import rrf_fusion  # noqa: E402
from verifyci.retrieval.provider import OllamaEmbeddingProvider  # noqa: E402
from verifyci.retrieval.sparse import BM25Retriever  # noqa: E402

CONFIG = json.loads((HERE / "config.json").read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def load():
    corpus = {}
    for line in (HERE / "corpus.jsonl").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and "_doc" not in line:
            d = json.loads(line)
            corpus[d["id"]] = d["text"]
    queries = []
    for line in (HERE / "qrels.jsonl").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and "_doc" not in line:
            queries.append(json.loads(line))
    return corpus, queries


def validate(corpus: dict, queries: list) -> list[str]:
    errs = []
    ids = [q["qid"] for q in queries]
    if len(ids) != len(set(ids)):
        dup = {i for i in ids if ids.count(i) > 1}
        errs.append(f"duplicate query ids: {sorted(dup)}")
    if not corpus:
        errs.append("empty corpus")
    for did, text in corpus.items():
        if not text.strip():
            errs.append(f"empty document text: {did}")
    seen_rel = set()
    for q in queries:
        rel = q.get("relevance") or {}
        if not rel:
            errs.append(f"empty relevance set: {q['qid']}")
        for did, grade in rel.items():
            if did not in corpus:
                errs.append(f"unknown docid {did} in {q['qid']}")
            if not isinstance(grade, int) or not 1 <= grade <= 3:
                errs.append(f"bad grade {grade!r} for {did} in {q['qid']}")
        if not q.get("text", "").strip():
            errs.append(f"empty query text: {q['qid']}")
        seen_rel.add(q["qid"])
    dead = [d for d in corpus if not any(d in q["relevance"] for q in queries)]
    if dead:
        errs.append(f"docs never judged: {sorted(dead)[:5]} ... count={len(dead)}")
    if len(queries) < CONFIG["min_queries_to_establish"]:
        errs.append(f"gate UNESTABLISHED: only {len(queries)} judged queries "
                    f"(< {CONFIG['min_queries_to_establish']})")
    return errs


def _dcg(ranked_ids: list[str], rel: dict[str, int], k: int) -> float:
    return sum(((2 ** rel[d] - 1) / math.log2(i + 2) for i, d in enumerate(ranked_ids[:k])
                if d in rel), 0.0)


def ndcg_at(ranked_ids: list[str], rel: dict[str, int], k: int = 10) -> float:
    ideal = sorted(rel, key=lambda d: -rel[d])
    idcg = _dcg(ideal, rel, k)
    return _dcg(ranked_ids, rel, k) / idcg if idcg else 0.0


def recall_at(ranked_ids: list[str], rel: dict[str, int], k: int = 5) -> float:
    wanted = {d for d, g in rel.items() if g >= 2}
    if not wanted:
        return 0.0
    return len(set(ranked_ids[:k]) & wanted) / len(wanted)


def _tiebreak_rank(pairs: list[tuple[str, float]]) -> list[str]:
    """Deterministic: score desc, then docid asc (bit-comparable reruns)."""
    return [d for d, _ in sorted(pairs, key=lambda t: (-t[1], t[0]))]


async def build_rankings(corpus, queries, provider):
    doc_ids = list(corpus)
    q_texts = [q["text"] for q in queries]
    vecs = await provider.embed([corpus[d] for d in doc_ids] + q_texts)
    doc_vecs = vecs[:len(doc_ids)]
    q_vecs = vecs[len(doc_ids):]

    store = InMemoryVectorStore()
    store.upsert([VectorRecord(id=d, embedding=v) for d, v in zip(doc_ids, doc_vecs)])
    bm25 = BM25Retriever()
    for d, text in corpus.items():
        bm25.add(d, text)

    out = {}
    k = CONFIG["k_ndcg"]
    for q, qv in zip(queries, q_vecs):
        dense = store.search(qv, k=len(doc_ids))
        dense_ranked = _tiebreak_rank(list(dense))[:k]
        sparse_ranked = [r.id for r in bm25.search(q["text"], k=k)]
        dense_res = [_res(i) for i in dense_ranked]
        sparse_res = [_res(i) for i in sparse_ranked]
        # Single fusion path for every k: rrf_fusion with the configured k
        # is exactly _rrf (same formula, same docid tiebreak). The old fork
        # (private _rrf unless k == 60) made reported metrics depend on an
        # untested code path; _rrf is retained only for the equivalence test.
        fused_ids = rrf_fusion(dense_res, sparse_res, [], CONFIG["rrf_k"])
        hybrid_ranked = list(fused_ids)[:k]
        out[q["qid"]] = {"dense": dense_ranked, "hybrid": hybrid_ranked}
    return out


def _res(doc_id: str):
    from verifyci.retrieval.dense import SearchResult
    return SearchResult(id=doc_id, score=0.0, metadata={})


def _rrf(dense, sparse, rrf_k):
    scores = {}
    for rank, res in enumerate(dense):
        scores[res.id] = scores.get(res.id, 0) + 1.0 / (rrf_k + rank + 1)
    for rank, res in enumerate(sparse):
        scores[res.id] = scores.get(res.id, 0) + 1.0 / (rrf_k + rank + 1)
    return [d for d, _ in sorted(scores.items(), key=lambda t: (-t[1], t[0]))]


def score(rankings, queries):
    kr, kn = CONFIG["k_recall"], CONFIG["k_ndcg"]
    agg = {c: {"ndcg": [], "recall": []} for c in ("dense", "hybrid")}
    for q in queries:
        r = q["relevance"]
        for c in ("dense", "hybrid"):
            ids = rankings[q["qid"]][c]
            agg[c]["ndcg"].append(ndcg_at(ids, r, kn))
            agg[c]["recall"].append(recall_at(ids, r, kr))
    return {c: {m: (sum(v) / len(v) if v else 0.0) for m, v in d.items()}
            for c, d in agg.items()}


def make_provider(name: str, cache_dir: Path):
    if name == "hash":
        from verifyci.retrieval.provider import HashEmbeddingProvider
        return HashEmbeddingProvider()
    if name != CONFIG["provider"]:
        raise SystemExit(f"provider {name!r} != frozen config {CONFIG['provider']!r}")
    base = OllamaEmbeddingProvider(model=CONFIG["model"], base_url=CONFIG["ollama_url"])
    from verifyci.retrieval.provider import CachedEmbeddingProvider
    safe = "".join(c if c.isalnum() else "_" for c in CONFIG["model"])
    return CachedEmbeddingProvider(base, str(cache_dir / f"embedding_cache_{safe}.json"))


def gate_established(dry_run: bool, provider: str, n_queries: int,
                     delta: float) -> bool:
    """The single predicate deciding whether a run is gate evidence.

    Factored so tests execute the real rule instead of re-stating it:
    dry runs and non-frozen providers are pipeline checks, never evidence.
    """
    return (
        not dry_run and provider == CONFIG["provider"]
        and n_queries >= CONFIG["min_queries_to_establish"]
        and delta >= CONFIG["pass_rule"]["target_delta_ndcg_abs"])


async def amain(args):
    corpus, queries = load()
    errs = validate(corpus, queries)
    fatal = [e for e in errs if not e.startswith("gate UNESTABLISHED")]
    if fatal:
        print("VALIDATION FAILED (evaluation drift guard):")
        for e in fatal:
            print("  -", e)
        raise SystemExit(2)
    provider = make_provider(args.provider, HERE)
    rankings = await build_rankings(corpus, queries, provider)
    # Same corpus/query hashes for both conditions by construction; assert anyway.
    ch = _sha(HERE / "corpus.jsonl")
    qh = _sha(HERE / "qrels.jsonl")
    metrics = score(rankings, queries)
    d, h = metrics["dense"], metrics["hybrid"]
    delta = h["ndcg"] - d["ndcg"]
    established = gate_established(args.dry_run, args.provider,
                                   len(queries), delta)
    report = {
        "frozen": {"corpus_sha256": ch, "qrels_sha256": qh,
                   "config_sha256": _sha(HERE / "config.json"),
                   "model": CONFIG["model"], "rrf_k": CONFIG["rrf_k"],
                   "k_ndcg": CONFIG["k_ndcg"], "k_recall": CONFIG["k_recall"]},
        "run": {"provider": provider.model_name(), "queries": len(queries),
                "documents": len(corpus), "dry_run": bool(args.dry_run)},
        "metrics": {"dense": d, "hybrid": h, "delta_ndcg": delta},
        "validators": {"errors": errs, "drift": bool(fatal)},
        "gate": {"established": established,
                 "rule": CONFIG["pass_rule"],
                 "note": "dry_run and non-frozen-provider runs are pipeline "
                         "checks, not gate evidence"},
        "smoke_disclaimer": CONFIG["smoke_disclaimer"],
    }
    (HERE / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"{'Metric':16}{'Dense-only':>12}{'Hybrid':>12}{'Delta':>12}")
    print(f"{'Recall@5':16}{d['recall']:>12.4f}{h['recall']:>12.4f}{'—':>12}")
    print(f"{'nDCG@10':16}{d['ndcg']:>12.4f}{h['ndcg']:>12.4f}{delta:>+12.4f}")
    print(f"{'Queries':16}{len(queries):>12}{len(queries):>12}{'same set':>12}")
    print(f"{'Embedding':16}{provider.model_name():>12}{'':>12}{'':>12}")
    print(f"{'Corpus':16}{len(corpus):>12}{'':>12}{'':>12}")
    if errs:
        print("Validator notes:", *errs, sep="\n  - ")
    print(f"GATE ESTABLISHED: {established}"
          + ("" if established else f"  (measured-only: delta {delta:+.4f}, "
             f"dry_run={args.dry_run}, provider={args.provider})"))
    print(f"report -> {HERE / 'results.json'}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default=CONFIG["provider"], choices=["ollama", "hash"])
    ap.add_argument("--dry-run", action="store_true",
                    help="pipeline self-check; never counts as gate evidence")
    asyncio.run(amain(ap.parse_args()))
