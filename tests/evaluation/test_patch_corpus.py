"""C1 frozen patch-corpus regression guard.

The first frozen measurement is recorded in results.json; this test
asserts the corpus data and the recorded metrics stay as published, and
(optionally) re-runs the measurement to prove reproducibility. Labels
and base files are frozen data; changing them intentionally requires
updating the recorded baseline constants here with a review note — the
same protocol as the invariant/BEIR corpora.

Set VERIFYCI_PATCH_RERUN=1 to also execute the full measure step
(fresh ingest + 17 verifies) and compare against results.json.
"""
import hashlib
import json
import os
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
CORPUS = Path(HERE, "..", "..", "benchmarks", "patch_corpus")

# Recorded first frozen measurement (2026-10-01). Gate outcomes:
# patch_equivalence 0.875 < 0.90 (NOT MET); verification_precision 1.0
# (MET); deterministic_catch 1.0; semantic_false_accept 1.0 (documented
# scope limit); one label miss (C3: exposure contract silent on
# tail-insertion hunks) kept, not retuned.
RECORDED = {
    "patch_equivalence": 0.875,
    "verification_precision": 1.0,
    "deterministic_catch_rate": 1.0,
    "semantic_false_accept_rate": 1.0,
    "semantic_decline_rate": 0.0,
    "false_reject_ids": [],
    "false_positive_fail_ids": [],
    "confusion": {
        "wrong_all": {"caught": 4, "accepted": 4, "declined": 1},
        "correct_all": {"caught": 0, "accepted": 6, "declined": 2},
        "wrong_deterministic": {"caught": 4, "accepted": 0, "declined": 0},
        "wrong_semantic": {"caught": 0, "accepted": 4, "declined": 0},
    },
}

# Re-measurement after the diffmap A2 insertion-anchor repair (correctness
# campaign). The single verdict change is C3-send-notify PASS ->
# HUMAN_REVIEW (blast now seeds the tail insertion, so exposure reaches the
# reviewer as its expected outcome). Effect: patch_equivalence 0.875 -> 1.0,
# correct_all confusion accepted 6 -> declined 3-side; precision, deterministic
# catch, semantic false-accept, and false-reject lists all unchanged.
# results.json keeps the historical first measurement untouched.
POSTFIX = {
    "patch_equivalence": 1.0,
    "verification_precision": 1.0,
    "deterministic_catch_rate": 1.0,
    "semantic_false_accept_rate": 1.0,
    "semantic_decline_rate": 0.0,
    "false_reject_ids": [],
    "false_positive_fail_ids": [],
    "confusion": {
        "wrong_all": {"caught": 4, "accepted": 4, "declined": 1},
        "correct_all": {"caught": 0, "accepted": 5, "declined": 3},
        "wrong_deterministic": {"caught": 4, "accepted": 0, "declined": 0},
        "wrong_semantic": {"caught": 0, "accepted": 4, "declined": 0},
    },
}


def _cases():
    return [json.loads(line) for line in
            (CORPUS / "cases.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def _results():
    return json.loads((CORPUS / "results.json").read_text(encoding="utf-8"))


def test_corpus_is_frozen_shaped():
    cases = _cases()
    assert len(cases) == 17
    assert {c["ground_truth"] for c in cases} == {"correct", "wrong"}
    correct = [c for c in cases if c["ground_truth"] == "correct"]
    wrong = [c for c in cases if c["ground_truth"] == "wrong"]
    assert len(correct) == 8 and len(wrong) == 9
    # every case carries intent + expected outcome (freeze protocol)
    assert all(c.get("intent") and c.get("expected_status") for c in cases)
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids))
    # deterministic + semantic failure modes present (not a toy set)
    cats = {c["category"] for c in cases}
    assert {"forbid_call", "forbid_import", "secret", "fabricated_removal"} <= cats
    assert "semantic" in cats


def test_recorded_metrics_are_stable():
    m = _results()["metrics"]
    for k, v in RECORDED.items():
        assert m[k] == v, f"{k}: recorded baseline changed ({v} -> {m[k]})"


def test_first_run_outcomes_as_documented():
    table = {t["id"]: t for t in _results()["verdicts"]}
    # All deterministic wrong patches caught; all semantic wrong patches
    # accepted (documented V1 limit: provenance+impact, not intent).
    for cid in ("W1-eval-call", "W2-subprocess-import", "W3-hardcoded-key",
                "W4-fabricated-removal"):
        assert table[cid]["status"] == "FAIL"
    for cid in ("S1-weak-validation", "S2-wrong-var", "S3-return-identity",
                "S4-wrong-multiplier"):
        assert table[cid]["status"] == "PASS"
    # zero false rejects: no correct patch FAILed
    correct = [t for t in table.values() if t["ground_truth"] == "correct"]
    assert all(t["status"] != "FAIL" for t in correct)
    # the one kept-not-retuned label miss, documented in config.json
    assert table["C3-send-notify"]["expected"] == "HUMAN_REVIEW"
    assert table["C3-send-notify"]["status"] == "PASS"


@pytest.mark.skipif(os.environ.get("VERIFYCI_PATCH_RERUN") != "1",
                    reason="full re-measure; set VERIFYCI_PATCH_RERUN=1")
def test_measurement_reproduces_recorded_report():
    """Re-measure on the CURRENT code. The A2 insertion-anchor repair in
    diffmap.py changes the C3 verdict: PASS -> HUMAN_REVIEW (exposure now
    reaches the blast reviewer), lifting patch_equivalence 0.875 -> 1.0 and
    overall agreement 16/17 -> 17/17, with every other per-case verdict,
    precision, and the deterministic/semantic breakdown unchanged. The
    historical results.json record stays pinned to RECORDED; the fresh
    measurement is pinned to POSTFIX (evidence tracking, not retuning)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("patch_measure", CORPUS / "measure.py")
    measure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(measure)
    fresh = measure.compute_metrics(measure.run())
    recorded = _results()["metrics"]
    for k in RECORDED:  # historical file untouched
        assert recorded[k] == RECORDED[k], f"historical record changed on {k}"
    for k in POSTFIX:  # current code reproduces its documented delta
        assert fresh[k] == POSTFIX[k], f"rerun drift on {k}: {fresh[k]}"


def test_results_hash_pinned():
    data = (CORPUS / "cases.jsonl").read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    assert _results()["frozen"]["cases_sha256"] == sha[:16], \
        "frozen corpus changed without re-measuring"
