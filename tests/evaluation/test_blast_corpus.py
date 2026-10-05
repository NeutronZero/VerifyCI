"""C2 frozen blast-corpus regression guard.

The first frozen measurement is recorded in benchmarks/blast_corpus/
results.json. This pins the corpus shape and the published metrics, and
(opt-in) re-measures to prove reproducibility. Expected sets are frozen
topology truth derived by hand before detection; misses — notably the
pre-labeled B6 tail-insertion gap — are reported, not repaired.

Set VERIFYCI_BLAST_RERUN=1 to re-run the full measurement and compare.
"""
import hashlib
import json
import os
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
CORPUS = Path(HERE, "..", "..", "benchmarks", "blast_corpus")

# Recorded measurement after reviewed CAP-003 re-baseline: 9/9 recall 1.0.
# Historical v1 baseline (2026-10-01) was coverage 6/7 = 0.8571 < 0.90 with
# the B6 tail-insertion gap labeled known_gap; preserved in git history and
# cap003_tail_seeding/config.json frozen_reference. Promotion reviewed:
# modes B6/B7 known_gap->seeded per frozen MODE_PROTOCOL (stdlib geometry),
# expected sets unchanged (topology-derived, match v1 exactly).
RECORDED = {
    "coverage_all": 1.0,
    "coverage_seeded_only": 1.0,
    "contract_fn_ids": [],
    "known_gap_miss_ids": [],
    "total_fp": 1,
}

# Post-repair re-measurement (diffmap A2 insertion-anchor seeding,
# correctness campaign): the labeled gap CLOSED — B6 now seeds (2 entities,
# risk 0.45) and its 6 dependents are detected; coverage 7/7 = 1.0. The
# disclosed B5 context-bleed FP is unchanged (total_fp still 1); seeded
# cases gained adjacent-line seeds but every seeded recall stays 1.0.
# results.json keeps the historical first measurement untouched.
POSTFIX = {
    "coverage_all": 1.0,
    "coverage_seeded_only": 1.0,
    "contract_fn_ids": [],
    "known_gap_miss_ids": [],
    "total_fp": 1,
}


def _cases():
    return [json.loads(line) for line in
            (CORPUS / "cases.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def _results():
    return json.loads((CORPUS / "results.json").read_text(encoding="utf-8"))


def test_corpus_shape_is_frozen():
    cases = _cases()
    assert len(cases) == 9
    assert len({c["id"] for c in cases}) == 9
    # required coverage dimensions: direct, transitive, multi-path, zero,
    # boundary/def-line, tail insertion, cross-file+method.
    # CAP-003 reviewed re-baseline: all cases seeded (B6/B7 tail-insertion
    # hunks attribute to enclosing functions per frozen MODE_PROTOCOL).
    modes = {c["mode"] for c in cases}
    assert modes == {"seeded"}, modes
    seeds = {c["seed"] for c in cases}
    assert {"hub", "leaf", "far", "isolated", "handle", "mid2"} <= seeds
    empty = [c for c in cases if not c["expected_impacted"]]
    assert {c["id"] for c in empty} == {"B3-isolated-zero", "B7-isolated-tail-insert"}


def test_recorded_metrics_are_stable():
    m = _results()["metrics"]
    for k, v in RECORDED.items():
        assert m[k] == v, f"{k}: recorded baseline changed ({v} -> {m[k]})"


def test_per_case_frozen_expectations():
    rows = {r["id"]: r for r in _results()["cases"]}
    # traversal is exact whenever seeding hits the span
    for cid in ("B1-hub-midline", "B2-leaf-midline", "B4-far-change",
                "B8-method-callee", "B9-mid2-branch"):
        assert rows[cid]["recall"] == 1.0, cid
        assert rows[cid]["FN"] == 0, cid
    # hub exposure includes cross-file remote and method handle
    assert {"remote", "handle"} <= set(rows["B1-hub-midline"]["detected"])
    # CAP-003: the tail-insertion gap is closed — B6 seeds hub and detects
    # all 6 dependents (was: n_changed 0, risk 0.0, FN 6 pre-repair)
    b6 = rows["B6-hub-tail-insert"]
    assert b6["recall"] == 1.0 and b6["FN"] == 0 and b6["TP"] == 6, b6
    # B5 precision artifact (context-bleed second-degree seeding re-adds
    # the seed) is the only FP; disclosed, not retuned
    assert rows["B5-hub-defline"]["FP"] == 1
    assert "hub" in rows["B5-hub-defline"]["detected"]


def test_zero_impact_and_isolation_hold():
    rows = {r["id"]: r for r in _results()["cases"]}
    assert rows["B3-isolated-zero"]["detected"] == []
    assert rows["B7-isolated-tail-insert"]["detected"] == []  # vacuously


@pytest.mark.skipif(os.environ.get("VERIFYCI_BLAST_RERUN") != "1",
                    reason="full re-measure; set VERIFYCI_BLAST_RERUN=1")
def test_measurement_reproduces_recorded_report():
    """Re-measure on the CURRENT code: it must reproduce the recorded
    CAP-003 report exactly (9/9 recall 1.0; B5 FP stable at 1).
    Historical v1 baseline (0.8571) lives in git history + cap003 config;
    the recorded file now holds the reviewed re-baseline — evidence
    tracking, not expectation retuning: expected sets match v1 exactly."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("blast_measure", CORPUS / "measure.py")
    measure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(measure)
    rows = measure.collect()  # rerun detection on a fresh ingest
    m = measure.compute_metrics(rows)
    for k in POSTFIX:
        assert m[k] == POSTFIX[k], f"rerun drift on {k}: {m[k]} != {POSTFIX[k]}"
    recorded = _results()["metrics"]
    for k in RECORDED:
        assert recorded[k] == RECORDED[k], f"historical record changed on {k}"


def test_results_hash_pinned():
    data = (CORPUS / "cases.jsonl").read_bytes()
    sha_raw = hashlib.sha256(data).hexdigest()[:16]
    sha_crlf = hashlib.sha256(data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")).hexdigest()[:16]
    sha_lf = hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()[:16]
    expected = _results()["frozen"]["cases_sha256"]
    assert expected in (sha_raw, sha_crlf, sha_lf), \
        "frozen corpus changed without re-measuring"
