"""H1-B/C/D single measurement pass (ONE run, no tuning, no E/F).

Protocol mirrors the frozen harness exactly (same queries, same rankers,
same scorer, same k=60 production RRF): only the indexed document texts
vary (frozen control re-embedded + B/C/D enriched corpora). Fresh
embeddings go through Ollama `nomic-embed-text` ONLY, into a SEPARATE
scratch cache — the frozen cache file and results.json are never
touched. Output: results_h1.json only.
"""
import asyncio
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from verifyci.retrieval.provider import (  # noqa: E402
    CachedEmbeddingProvider, OllamaEmbeddingProvider,
)

BASELINE = {
    "dense_recall": 0.6465053763440861,
    "dense_ndcg": 0.6219642456212527,
    "hybrid_recall": 0.6706989247311829,
    "hybrid_ndcg": 0.6603443467936309,
    "delta_ndcg": 0.03838010117237811,
}
SCRATCH_CACHE = HERE / "embedding_cache_h1_nomic_embed_text.json"
VARIANTS = ("control", "b", "c", "d")


def _harness():
    spec = importlib.util.spec_from_file_location("beir_harness", HERE / "eval_harness.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    h = _harness()
    frozen_corpus, queries = h.load()
    recorded = json.loads((HERE / "results.json").read_text(encoding="utf-8"))
    frozen = recorded["frozen"]
    assert _sha(HERE / "corpus.jsonl") == frozen["corpus_sha256"]
    assert _sha(HERE / "qrels.jsonl") == frozen["qrels_sha256"]
    assert _sha(HERE / "config.json") == frozen["config_sha256"]

    config = json.loads((HERE / "config.json").read_text(encoding="utf-8"))
    provider = CachedEmbeddingProvider(
        OllamaEmbeddingProvider(model=config["model"], base_url=config["ollama_url"]),
        str(SCRATCH_CACHE),
    )
    corpora = {"control": frozen_corpus}
    for variant in ("b", "c", "d"):
        corpora[variant] = json.loads(
            (HERE / f"corpus_h1_{variant}.json").read_text(encoding="utf-8"))
        assert set(corpora[variant]) == set(frozen_corpus), variant
        assert all(t.strip() for t in corpora[variant].values()), variant

    report = {
        "campaign": "H1-B/C/D single measurement pass",
        "frozen_reference": "v1.0.2-correctness",
        "frozen_hashes_reverified": True,
        "model": config["model"],
        "rrf_k": config["rrf_k"],
        "production_rrf": True,
        "scratch_cache": SCRATCH_CACHE.name,
        "frozen_cache_untouched": True,
        "queries": len(queries),
        "variants": {},
    }
    for variant in VARIANTS:
        corpus = corpora[variant]
        fatal = [e for e in h.validate(corpus, queries)
                 if not e.startswith("gate UNESTABLISHED")]
        assert fatal == [], (variant, fatal)
        rankings = asyncio.run(h.build_rankings(corpus, queries, provider))
        m = h.score(rankings, queries)
        d, hy = m["dense"], m["hybrid"]
        delta = hy["ndcg"] - d["ndcg"]
        report["variants"][variant] = {
            "dense": d, "hybrid": hy, "delta_ndcg": delta,
            "vs_baseline": {
                "hybrid_recall": hy["recall"] - BASELINE["hybrid_recall"],
                "hybrid_ndcg": hy["ndcg"] - BASELINE["hybrid_ndcg"],
                "delta_ndcg": delta - BASELINE["delta_ndcg"],
                "dense_recall": d["recall"] - BASELINE["dense_recall"],
                "dense_ndcg": d["ndcg"] - BASELINE["dense_ndcg"],
            },
        }
        print(f"H1-{variant}: dense R@5={d['recall']:.4f} nDCG={d['ndcg']:.4f} | "
              f"hybrid R@5={hy['recall']:.4f} nDCG={hy['ndcg']:.4f} "
              f"delta={delta:+.4f}")
    dest = HERE / "results_h1.json"
    dest.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"report -> {dest.name} (results.json untouched)")


if __name__ == "__main__":
    main()
