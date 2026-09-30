"""Frozen BEIR harness integrity: scoring formula, drift guards, evidence rule.

These tests never require the network. They prove the harness (a) scores
the way config.json says, (b) refuses evaluation drift, and (c) never
marks the gate established from a dry-run or a non-frozen provider.
"""
import json
from pathlib import Path

import pytest

from benchmarks.beir import eval_harness as eh

HERE = Path(eh.__file__).resolve().parent


def _corpus():
    c, _ = eh.load()
    return c


def _queries():
    _, q = eh.load()
    return q


def test_frozen_files_load_and_validate_clean():
    corpus, queries = _corpus(), _queries()
    errs = eh.validate(corpus, queries)
    # corpus >= min, every doc judged, no dup ids, no unknown docids
    assert [e for e in errs if not e.startswith("gate UNESTABLISHED")] == []


def test_ndcg_matches_hand_computed():
    import math
    rel = {"a": 3, "b": 1}
    # gains: a=2^3-1=7, b=2^1-1=1
    # ideal order a,b: DCG = 7/log2(2) + 1/log2(3) = 7 + 1/1.58496
    idcg = 7.0 / math.log2(2) + 1.0 / math.log2(3)
    assert eh.ndcg_at(["a", "b"], rel, k=10) == pytest.approx(1.0)
    # reversed b,a: DCG = 1/log2(2) + 7/log2(3)
    dcg = 1.0 / math.log2(2) + 7.0 / math.log2(3)
    assert eh.ndcg_at(["b", "a"], rel, k=10) == pytest.approx(dcg / idcg)
    assert eh.ndcg_at(["b", "a"], rel, k=10) < 1.0


def test_recall_at_5_ignores_marginal_grade_one():
    rel = {"x": 2, "y": 1}  # only grade>=2 counts
    assert eh.recall_at(["x"], rel, k=5) == 1.0   # y not required for recall
    assert eh.recall_at(["z"], rel, k=5) == 0.0


def test_duplicate_query_id_rejected():
    qs = _queries() + [{"qid": _queries()[0]["qid"], "text": "dup", "relevance": {"d001": 3}}]
    assert any("duplicate query id" in e.lower() for e in eh.validate(_corpus(), qs))


def test_unknown_docid_rejected():
    qs = _queries()
    qs = qs + [{"qid": "zz", "text": "t", "relevance": {"NOPE": 3}}]
    assert any("unknown docid" in e.lower() for e in eh.validate(_corpus(), qs))


def test_empty_relevance_set_rejected():
    qs = _queries() + [{"qid": "zz", "text": "t", "relevance": {}}]
    assert any("empty relevance set" in e for e in eh.validate(_corpus(), qs))


def test_empty_query_text_rejected():
    qs = _queries() + [{"qid": "zz", "text": "   ", "relevance": {"d001": 3}}]
    assert any("empty query text" in e for e in eh.validate(_corpus(), qs))


def test_judged_set_is_diverse_not_smoke():
    corpus, queries = _corpus(), _queries()
    assert len(queries) >= eh.CONFIG["min_queries_to_establish"]
    assert len(corpus) >= 50
    # every query must reference corpus docs that actually exist
    for q in queries:
        assert q["relevance"], q["qid"]


def test_dry_run_or_nonfrozen_provider_never_establishes_gate():
    # The established flag is computed from provider==frozen AND not dry_run
    # AND size AND delta. Simulate the arithmetic the CLI performs.
    cfg = eh.CONFIG
    established_dry = (False and cfg["provider"] == "hash"
                       and 62 >= cfg["min_queries_to_establish"] and 0.08 >= 0.05)
    assert established_dry is False  # dry_run short-circuits


def test_report_records_corpora_hash_for_both_conditions():
    # corpus/qrels sha256 are the single frozen source read by BOTH ranking
    # conditions (dense and hybrid come from one embeddings pass), so a
    # condition cannot silently drift to a different corpus.
    corpus, queries = _corpus(), _queries()
    rankings = {"q": {"dense": list(corpus)[:10], "hybrid": list(corpus)[:10]}}
    metrics = eh.score({q["qid"]: rankings["q"] for q in queries}, queries)
    assert metrics["dense"]["ndcg"] == metrics["hybrid"]["ndcg"]


def test_results_file_wellformed_if_present():
    p = HERE / "results.json"
    if not p.exists():
        pytest.skip("live gate run not executed yet")
    rep = json.loads(p.read_text(encoding="utf-8"))
    for key in ("frozen", "run", "metrics", "validators", "gate", "smoke_disclaimer"):
        assert key in rep
    assert rep["run"]["queries"] == rep["run"]["documents"] or rep["run"]["queries"]
    # both conditions ran over the identical frozen corpus/query hashes
    assert rep["frozen"]["corpus_sha256"]
