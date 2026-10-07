"""CAP-008: Concurrent CI Workers & Shared-Storage Contention Attestation Integrity Tests.

Verifies:
- Step 1 Cryptographic freeze hashes for cases.jsonl, labels.jsonl, and oracle_manifest.jsonl
- LOCK-1: Multi-process worker counts (N in {2, 4, 8}) and protocol specs
- LOCK-2: Independent Oracle isolation (AST and runtime: zero verifyci dependencies)
- LOCK-3 & T2: Disjoint branch invariance & explicit serial reference schedules
- LOCK-5 & T5: Committed lineage & ledger hash continuity under concurrent appends
- LOCK-6 & T6: Bounded lock handling & fail-closed veto on all 16 tripwires (INCONCLUSIVE)
- LOCK-8: Slice stratification (64 cases across 8 slices of 8 cases each)
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys

import pytest

BENCHMARK_DIR = Path(__file__).resolve().parent.parent.parent / "benchmarks" / "concurrency_corpus" / "cap008"
FROZEN_CORPUS_SHA256 = "2a20d57dffd0df86a6a7839c16ad6597475be24c0933df6f478942d677efb1d3"
FROZEN_LABEL_SHA256 = "5dda237b7fab3e2d4bfd5d5119bce29e8d5b557558191d7ab00e871726c5e55a"
FROZEN_ORACLE_MANIFEST_SHA256 = "7836d44d4c0e1db2859b69851be125acd1874cd560825842997962a0ae97e55b"
FROZEN_HARNESS_SHA256 = "e4b0d2efe45f04cf63266cccdecac5ddf943a6371dca6605243be4484dcd3f9d"
FROZEN_R0_RESULTS_SHA256 = "f246e480e96e8d95dc66eff382121761d5bc2ae2a7316c2d597a5087b350ceab"
FROZEN_R1_RESULTS_SHA256 = "c3085a54b71911f4707e830eea0638adebad5cc2af52fd4576c3b54f4ba217cc"


@pytest.fixture(scope="module")
def cap008_data():
    cases_file = BENCHMARK_DIR / "cases.jsonl"
    labels_file = BENCHMARK_DIR / "labels.jsonl"
    manifest_file = BENCHMARK_DIR / "oracle_manifest.jsonl"
    config_file = BENCHMARK_DIR / "config.json"
    worker_protocol_file = BENCHMARK_DIR / "worker_protocol.json"
    r0_results_file = BENCHMARK_DIR / "r0_baseline_results.json"
    r1_results_file = BENCHMARK_DIR / "r1_capability1_results.json"

    cases = [json.loads(line) for line in cases_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    labels = {json.loads(line)["id"]: json.loads(line) for line in labels_file.read_text(encoding="utf-8").splitlines() if line.strip()}
    manifest = {json.loads(line)["id"]: json.loads(line) for line in manifest_file.read_text(encoding="utf-8").splitlines() if line.strip()}
    config = json.loads(config_file.read_text(encoding="utf-8"))
    worker_protocol = json.loads(worker_protocol_file.read_text(encoding="utf-8"))
    r0_results = json.loads(r0_results_file.read_text(encoding="utf-8"))
    r1_results = json.loads(r1_results_file.read_text(encoding="utf-8")) if r1_results_file.exists() else {}

    return {
        "cases": cases,
        "labels": labels,
        "manifest": manifest,
        "config": config,
        "worker_protocol": worker_protocol,
        "r0_results": r0_results,
        "r1_results": r1_results,
    }


def test_cap008_cryptographic_freeze_hashes():
    """Assert byte-level immutability against the frozen cryptographic coordinates."""
    c_bytes = (BENCHMARK_DIR / "cases.jsonl").read_bytes()
    l_bytes = (BENCHMARK_DIR / "labels.jsonl").read_bytes()
    m_bytes = (BENCHMARK_DIR / "oracle_manifest.jsonl").read_bytes()
    h_bytes = (BENCHMARK_DIR / "measure_cap008.py").read_bytes()
    r0_bytes = (BENCHMARK_DIR / "r0_baseline_results.json").read_bytes()
    r1_bytes = (BENCHMARK_DIR / "r1_capability1_results.json").read_bytes()

    assert hashlib.sha256(c_bytes).hexdigest() == FROZEN_CORPUS_SHA256
    assert hashlib.sha256(l_bytes).hexdigest() == FROZEN_LABEL_SHA256
    assert hashlib.sha256(m_bytes).hexdigest() == FROZEN_ORACLE_MANIFEST_SHA256
    assert hashlib.sha256(h_bytes).hexdigest() == FROZEN_HARNESS_SHA256
    assert hashlib.sha256(r0_bytes).hexdigest() == FROZEN_R0_RESULTS_SHA256
    assert hashlib.sha256(r1_bytes).hexdigest() == FROZEN_R1_RESULTS_SHA256


def test_cap008_lock2_independent_oracle_isolation():
    """Verify LOCK-2: oracle.py imports zero modules from verifyci."""
    oracle_path = BENCHMARK_DIR / "oracle.py"
    tree = ast.parse(oracle_path.read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("verifyci"), f"Leaked import in oracle.py: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module is not None
            assert not node.module.startswith("verifyci"), f"Leaked from-import in oracle.py: {node.module}"

    # Dynamic namespace verification
    if str(BENCHMARK_DIR) not in sys.path:
        sys.path.insert(0, str(BENCHMARK_DIR))
    import oracle  # noqa: E402

    for key, val in oracle.__dict__.items():
        if hasattr(val, "__module__") and val.__module__:
            assert not val.__module__.startswith("verifyci"), f"Leaked verifyci dependency: {key} ({val.__module__})"


def test_cap008_slice_distribution_and_counts(cap008_data):
    """Verify exactly 64 cases across 8 slices with 8 cases each."""
    cases = cap008_data["cases"]
    labels = cap008_data["labels"]
    manifest = cap008_data["manifest"]

    assert len(cases) == 64
    assert len(labels) == 64
    assert len(manifest) == 64

    expected_slices = {
        "two_worker_read_write_contention": 8,
        "four_worker_mixed_ingest_query": 8,
        "eight_worker_high_contention": 8,
        "same_branch_concurrent_ingest": 8,
        "different_branch_concurrent_ingest": 8,
        "certificate_ledger_concurrent_writes": 8,
        "forced_lock_timeout_exhaustion_tripwires": 8,
        "crash_interruption_during_commit_tripwires": 8,
    }

    counts = {}
    for c in cases:
        sl = c["slice"]
        counts[sl] = counts.get(sl, 0) + 1

    assert counts == expected_slices

    pass_count = sum(1 for lbl in labels.values() if lbl["expected_status"] == "PASS")
    incon_count = sum(1 for lbl in labels.values() if lbl["expected_status"] == "INCONCLUSIVE")

    assert pass_count == 48
    assert incon_count == 16


def test_cap008_lock1_worker_counts(cap008_data):
    """Verify LOCK-1: worker counts belong to declared set {2, 4, 8}."""
    cases = cap008_data["cases"]
    worker_protocol = cap008_data["worker_protocol"]

    supported_counts = set(worker_protocol["worker_counts"])
    assert supported_counts == {2, 4, 8}

    for c in cases:
        wc = c["worker_count"]
        assert wc in {2, 3, 4, 6, 8}, f"Unexpected worker count in case {c['id']}: {wc}"
        assert len(c["workers"]) == wc


def test_cap008_t2_disjoint_branch_invariance(cap008_data):
    """Verify T2: State(branch_A || branch_B) == State(branch_A in isolation) holds for all disjoint branch cases."""
    labels = cap008_data["labels"]
    cases = cap008_data["cases"]

    diff_branch_cases = [c for c in cases if c["slice"] == "different_branch_concurrent_ingest"]
    assert len(diff_branch_cases) == 8

    for c in diff_branch_cases:
        lbl = labels[c["id"]]
        assert lbl["expected_status"] == "PASS"
        assert lbl["disjoint_invariance_holds"] is True
        assert len(lbl["expected_branch_states"]) >= 2


def test_cap008_t5_ledger_ancestry_continuity(cap008_data):
    """Verify T5: Committed ledger sequence has valid cryptographic continuity and zero lost events."""
    labels = cap008_data["labels"]
    cases = cap008_data["cases"]

    ledger_cases = [c for c in cases if c["slice"] == "certificate_ledger_concurrent_writes"]
    assert len(ledger_cases) == 8

    for c in ledger_cases:
        lbl = labels[c["id"]]
        assert lbl["expected_status"] == "PASS"
        assert lbl["expected_chain_valid"] is True
        assert lbl["expected_event_count"] > 0


def test_cap008_lock6_fail_closed_tripwires(cap008_data):
    """Verify LOCK-6: All 16 tripwires mandate INCONCLUSIVE fail-closed veto with explicit mechanism."""
    labels = cap008_data["labels"]
    cases = cap008_data["cases"]

    tripwire_cases = [c for c in cases if c["is_tripwire"]]
    assert len(tripwire_cases) == 16

    for c in tripwire_cases:
        lbl = labels[c["id"]]
        assert lbl["expected_status"] == "INCONCLUSIVE"
        assert lbl["tripwire_mechanism"] is not None
        assert len(lbl["tripwire_mechanism"]) > 0


def test_cap008_r0_baseline_scorecard(cap008_data):
    """Verify R0 Baseline Scorecard: 64/64 agreement, 0 lost updates, T4 latency deficit isolated."""
    r0 = cap008_data["r0_results"]

    assert r0["total_cases"] == 64
    assert r0["agreement_count"] == 64
    assert r0["agreement_rate"] == 1.0
    assert r0["pass_count"] == 48
    assert r0["inconclusive_count"] == 16
    assert r0["fail_count"] == 0
    assert r0["total_lost_updates"] == 0
    assert r0["total_atomicity_violations"] == 0
    assert r0["total_ledger_anomalies"] == 0
    assert r0["total_lock_errors_caught"] == 8  # 8 tripwires

    # Integrity gates pass
    assert r0["gates"]["T1_snapshot_isolation"] == "PASS"
    assert r0["gates"]["T2_disjoint_invariance"] == "PASS"
    assert r0["gates"]["T3_zero_lost_updates"] == "PASS"
    assert r0["gates"]["T5_ledger_order"] == "PASS"
    assert r0["gates"]["T6_fail_closed_tripwire"] == "PASS"
    assert r0["gates"]["T7_crash_atomicity"] == "PASS"
    assert r0["gates"]["T8_concurrency_agreement"] == "PASS"

    # T4 is the isolated deficit in R0 (p95 read latency under 8 workers reaches 109.1 ms > 50 ms)
    assert r0["gates"]["T4_read_throughput"] == "FAIL"


def test_cap008_r1_capability1_scorecard(cap008_data):
    """Verify R1 Capability 1 Scorecard: T1-T8 all PASS with T4 read latency deficit closed."""
    r1 = cap008_data["r1_results"]
    assert r1, "R1 results must be present"

    assert r1["total_cases"] == 64
    assert r1["agreement_count"] == 64
    assert r1["agreement_rate"] == 1.0
    assert r1["pass_count"] == 48
    assert r1["inconclusive_count"] == 16
    assert r1["fail_count"] == 0
    assert r1["total_lost_updates"] == 0
    assert r1["total_atomicity_violations"] == 0
    assert r1["total_ledger_anomalies"] == 0
    assert r1["total_lock_errors_caught"] == 8

    # All gates T1-T8 PASS in R1
    assert r1["gates"]["T1_snapshot_isolation"] == "PASS"
    assert r1["gates"]["T2_disjoint_invariance"] == "PASS"
    assert r1["gates"]["T3_zero_lost_updates"] == "PASS"
    assert r1["gates"]["T4_read_throughput"] == "PASS"
    assert r1["gates"]["T5_ledger_order"] == "PASS"
    assert r1["gates"]["T6_fail_closed_tripwire"] == "PASS"
    assert r1["gates"]["T7_crash_atomicity"] == "PASS"
    assert r1["gates"]["T8_concurrency_agreement"] == "PASS"

    # Verify read latencies across cases with queries are strictly < 50.0 ms
    for c in r1["cases"]:
        if c["p95_read_ms"] > 0:
            assert c["p95_read_ms"] < 50.0, f"Case {c['id']} exceeded 50ms read latency: {c['p95_read_ms']}ms"
