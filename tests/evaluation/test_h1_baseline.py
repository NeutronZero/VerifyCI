"""H1-A: frozen baseline reproduction (MUST pass before any intervention).

Runs the frozen harness's own load/validate/rank/score functions against
the frozen corpus — never `amain` (which would rewrite results.json).
Uses the `ollama` provider entry, which is cache-backed: frozen texts
hit the content-keyed embedding cache, so no live model is needed and
no model substitution occurs. Failing this test STOPS the campaign.
"""
import asyncio
import hashlib
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent.parent / "benchmarks" / "beir"

RECORDED = {
    "dense_recall": 0.6465053763440861,
    "dense_ndcg": 0.6219642456212527,
    "hybrid_recall": 0.6706989247311829,
    "hybrid_ndcg": 0.6603443467936309,
    "delta_ndcg": 0.03838010117237811,
    "queries": 62,
    "documents": 60,
}


def _harness():
    spec = importlib.util.spec_from_file_location("beir_harness", HERE / "eval_harness.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def test_h1a_frozen_inputs_untouched():
    """Evidence integrity gate: frozen file hashes still match the record."""
    recorded = (HERE / "results.json")
    import json
    frozen = json.loads(recorded.read_text(encoding="utf-8"))["frozen"]
    assert _sha(HERE / "corpus.jsonl") == frozen["corpus_sha256"]
    assert _sha(HERE / "qrels.jsonl") == frozen["qrels_sha256"]
    assert _sha(HERE / "config.json") == frozen["config_sha256"]


def test_h1a_reproduces_frozen_baseline():
    h = _harness()
    corpus, queries = h.load()
    assert len(corpus) == RECORDED["documents"]
    assert len(queries) == RECORDED["queries"]
    fatal = [e for e in h.validate(corpus, queries)
             if not e.startswith("gate UNESTABLISHED")]
    assert fatal == []
    safe = "".join(c if c.isalnum() else "_" for c in h.CONFIG["model"])
    cache_path = HERE / f"embedding_cache_{safe}.json"
    if not cache_path.exists():
        import pytest
        pytest.skip(f"Offline embedding cache {cache_path.name} not found")
    provider = h.make_provider("ollama", HERE)
    rankings = asyncio.run(h.build_rankings(corpus, queries, provider))
    metrics = h.score(rankings, queries)
    d, hy = metrics["dense"], metrics["hybrid"]
    assert d["recall"] == RECORDED["dense_recall"]
    assert d["ndcg"] == RECORDED["dense_ndcg"]
    assert hy["recall"] == RECORDED["hybrid_recall"]
    assert hy["ndcg"] == RECORDED["hybrid_ndcg"]
    assert hy["ndcg"] - d["ndcg"] == RECORDED["delta_ndcg"]
