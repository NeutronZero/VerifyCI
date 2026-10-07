"""CAP-006: Temporal Lineage & Multi-Branch Replay Attestation Benchmark Integrity Tests.

Verifies:
- Step 1 Cryptographic freeze hashes for cases.jsonl, labels.jsonl, and oracle_manifest.jsonl
- LOCK-1: Immutability of the 64-case frozen benchmark corpus
- LOCK-2: Independent Oracle isolation (zero verifyci dependencies)
- LOCK-4: Fail-closed contract on all 8 tripwire anomalies (INCONCLUSIVE)
- LOCK-5: Explicit branch and commit coordinates across all 8 stratified slices
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

BENCHMARK_DIR = Path(__file__).resolve().parent.parent.parent / "benchmarks" / "temporal_corpus" / "cap006"
FROZEN_CORPUS_SHA256 = "d89ae5f9d641a209ef525f64dd6f0b060e3f8db8be1891944efdba3877298b1a"
FROZEN_LABEL_SHA256 = "5bfa328a9f5f1f96cec1c3a1e674ee22358999dd9f69857603c95d34121a003c"
FROZEN_ORACLE_MANIFEST_SHA256 = "99ea4c3b128f74d82338c9416f2929088de0185ac112d34cb68569b562c0baf8"
FROZEN_MEASURE_SHA256 = "0a6c9b5947af381c330f482d9c93be1e6b3c81ade1956b64b9d83ac9b7eb690c"
FROZEN_RESULTS_SHA256 = "19fe88bf5554711b838b4205943cc32b4823c37a79deff587245d374a82568e8"


@pytest.fixture(scope="module")
def cap006_data():
    cases_file = BENCHMARK_DIR / "cases.jsonl"
    labels_file = BENCHMARK_DIR / "labels.jsonl"
    manifest_file = BENCHMARK_DIR / "oracle_manifest.jsonl"

    cases = [json.loads(line) for line in cases_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    labels = {json.loads(line)["id"]: json.loads(line) for line in labels_file.read_text(encoding="utf-8").splitlines() if line.strip()}
    manifest = {json.loads(line)["id"]: json.loads(line) for line in manifest_file.read_text(encoding="utf-8").splitlines() if line.strip()}

    return {
        "cases": cases,
        "labels": labels,
        "manifest": manifest,
    }


def test_cap006_cryptographic_hashes():
    """Assert byte-level integrity against the frozen cryptographic coordinates."""
    c_bytes = (BENCHMARK_DIR / "cases.jsonl").read_bytes()
    l_bytes = (BENCHMARK_DIR / "labels.jsonl").read_bytes()
    m_bytes = (BENCHMARK_DIR / "oracle_manifest.jsonl").read_bytes()
    meas_bytes = (BENCHMARK_DIR / "measure_cap006.py").read_bytes()
    res_bytes = (BENCHMARK_DIR / "results.json").read_bytes()

    assert hashlib.sha256(c_bytes).hexdigest() == FROZEN_CORPUS_SHA256
    assert hashlib.sha256(l_bytes).hexdigest() == FROZEN_LABEL_SHA256
    assert hashlib.sha256(m_bytes).hexdigest() == FROZEN_ORACLE_MANIFEST_SHA256
    assert hashlib.sha256(meas_bytes).hexdigest() == FROZEN_MEASURE_SHA256
    assert hashlib.sha256(res_bytes).hexdigest() == FROZEN_RESULTS_SHA256


def test_cap006_slice_distribution_and_case_count(cap006_data):
    """Verify 64 cases, exactly 8 per slice, and expected status distribution."""
    cases = cap006_data["cases"]
    labels = cap006_data["labels"]

    assert len(cases) == 64
    assert len(labels) == 64

    expected_slices = {
        "rename_edit_rename_back": 8,
        "delete_and_restore": 8,
        "revert_cycles": 8,
        "cherry_pick_cross_branch": 8,
        "interleaved_branch_ingest": 8,
        "criss_cross_merges": 8,
        "stale_cache_and_idempotence": 8,
        "truncated_lineage_tripwire": 8,
    }

    counts = {}
    for c in cases:
        sl = c["slice"]
        counts[sl] = counts.get(sl, 0) + 1

    assert counts == expected_slices

    pass_count = sum(1 for lbl in labels.values() if lbl["expected_status"] == "PASS")
    inconclusive_count = sum(1 for lbl in labels.values() if lbl["expected_status"] == "INCONCLUSIVE")
    fail_count = sum(1 for lbl in labels.values() if lbl["expected_status"] == "FAIL")

    assert pass_count == 56
    assert inconclusive_count == 8
    assert fail_count == 0


def test_cap006_independent_oracle_lock2_isolation():
    """Verify LOCK-2: oracle.py imports zero modules from verifyci."""
    import ast as _ast

    oracle_path = BENCHMARK_DIR / "oracle.py"
    tree = _ast.parse(oracle_path.read_text(encoding="utf-8"))

    for node in _ast.walk(tree):
        if isinstance(node, _ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("verifyci"), f"Leaked import: {alias.name}"
        elif isinstance(node, _ast.ImportFrom):
            assert node.module is not None
            assert not node.module.startswith("verifyci"), f"Leaked from-import: {node.module}"

    # Dynamic import check
    if str(BENCHMARK_DIR) not in sys.path:
        sys.path.insert(0, str(BENCHMARK_DIR))
    import oracle  # noqa: E402

    # Check imported modules in oracle's namespace
    for key, val in oracle.__dict__.items():
        if hasattr(val, "__module__") and val.__module__:
            assert not val.__module__.startswith("verifyci"), f"Leaked verifyci dependency: {key} ({val.__module__})"


def test_cap006_tripwires_fail_closed_lock4(cap006_data):
    """Verify LOCK-4: all 8 lineage tripwires evaluate strictly to INCONCLUSIVE."""
    cases = {c["id"]: c for c in cap006_data["cases"]}
    labels = cap006_data["labels"]
    manifest = cap006_data["manifest"]

    for i in range(1, 9):
        cid = f"TEMP-TRIP-0{i}"
        assert cid in cases
        assert labels[cid]["expected_status"] == "INCONCLUSIVE"
        assert manifest[cid]["expected_status"] == "INCONCLUSIVE"
        assert manifest[cid]["dag_valid"] is False


def test_cap006_explicit_coordinates_lock5(cap006_data):
    """Verify LOCK-5: every case specifies explicit commit IDs, parent IDs, and replay sequences."""
    for c in cap006_data["cases"]:
        assert c["id"].startswith("TEMP-")
        assert c.get("repository")
        assert len(c["commits"]) >= 1
        assert len(c["replay_sequence"]) >= 1
        assert "target_commit" in c["target_query"]
        assert "target_branch" in c["target_query"]

        for commit in c["commits"]:
            assert "commit_id" in commit
            assert "branch" in commit
            assert "files" in commit
            assert isinstance(commit["files"], dict)


def test_cap006_r2_adjudication_metrics():
    """Assert R2 final benchmark achieved 100% agreement, 0 hard vetoes, and all 8 gates PASS."""
    res_file = BENCHMARK_DIR / "results.json"
    res = json.loads(res_file.read_text(encoding="utf-8"))

    assert res["total_cases"] == 64
    assert res["agreed"] == 64
    assert res["disagreed"] == 0
    assert res["agreement_rate"] == 100.0
    assert res["tripwires_caught"] == "8/8"
    assert res["hard_veto_summary"]["cross_branch_contamination"] == 0
    assert res["hard_veto_summary"]["overlapping_live_intervals"] == 0
    assert res["hard_veto_summary"]["historical_anchor_drift"] == 0
    assert res["hard_veto_summary"]["fabricated_lineage"] == 0
    assert res["hard_veto_summary"]["fail_closed_tripwires_missed"] == 0
    assert res["hard_veto_summary"]["replay_equivalence_failures"] == 0
    assert res["hard_veto_summary"]["idempotent_ingest_failures"] == 0

    for gate_name, gate_status in res["gates"].items():
        assert gate_status == "PASS", f"Gate {gate_name} did not PASS"

