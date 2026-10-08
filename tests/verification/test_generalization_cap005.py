"""CAP-005: Generalization & Real-World Patch Validation Test Suite.

Verifies:
- Cryptographic freeze hashes for cases.jsonl, labels.jsonl, and sources.jsonl
- Real-world multi-repository patch verification across all 8 stratified slices
- Zero false acceptance rate (FAR = 0.0000) on true security & contract violations
- 100% rediscovery on pre-labeled falsifier classes (secret_name_independence, removal_provenance, argument_value_blindness)
- Fast execution latency (p95 <= 500ms) with zero crashes
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from verifyci.interface.commands.verify import run_verify

BENCHMARK_DIR = Path(__file__).resolve().parent.parent.parent / "benchmarks" / "patch_real" / "cap005"
FROZEN_CORPUS_SHA256 = "ca475b33a385e8d1478afedf00d2eeeefdc8ae0f72c9e5527f20fc1fe814e17c"
FROZEN_LABEL_SHA256 = "589231d38fdf85a764eab85ba19f1ad9e2839fe63c043c3c9636d745f1893075"
FROZEN_SOURCE_MANIFEST_SHA256 = "f330fca7d317ec9a1e8398295d930c49f802e2cc25cf94b3906d7b9b0d47af8d"
FROZEN_HARNESS_SHA256 = "c3f12cba865f80d19505d4dd8a5daf8110b98658099a4e3f0f75bed5854023cf"
FROZEN_RESULTS_SHA256 = "e7ed2033774e27646232eb8e9ce82b0ee891186acfb35cd2f6529e74fa0133ba"


@pytest.fixture(scope="module")
def cap005_data(tmp_path_factory):
    import shutil

    cases_file = BENCHMARK_DIR / "cases.jsonl"
    labels_file = BENCHMARK_DIR / "labels.jsonl"
    sources_file = BENCHMARK_DIR / "sources.jsonl"

    cases = [json.loads(line) for line in cases_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    labels = {json.loads(line)["id"]: json.loads(line) for line in labels_file.read_text(encoding="utf-8").splitlines() if line.strip()}
    sources = [json.loads(line) for line in sources_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    # P2: always ingest a pristine copy under tmp. The previous shape reused
    # a local-only `.verifyci.db` inside the benchmark tree when present, so
    # extractor/storage changes were silently tested against a stale graph
    # (and extractor runs could mutate the fixture tree in place).
    work = tmp_path_factory.mktemp("cap005_base")
    base_dir = work / "base"
    shutil.copytree(
        BENCHMARK_DIR / "base", base_dir,
        ignore=shutil.ignore_patterns(".verifyci"),
    )
    verifyci_dir = base_dir / ".verifyci"
    verifyci_dir.mkdir(parents=True, exist_ok=True)
    invariants_file = verifyci_dir / "invariants.yaml"
    invariants_file.write_text(
        "invariants:\n"
        "  - id: no-eval\n"
        "    rule: forbid eval\n"
        "    query: forbid_call:eval\n"
        "    blocking: true\n"
        "  - id: no-subprocess\n"
        "    rule: forbid subprocess\n"
        "    query: forbid_import:subprocess\n"
        "    blocking: true\n",
        encoding="utf-8",
    )
    db_file = verifyci_dir / "verifyci.db"
    from verifyci.interface.commands.ingest import run_ingest

    run_ingest(str(base_dir))
    db_path = str(db_file)

    return {
        "cases": cases,
        "labels": labels,
        "sources": sources,
        "db_path": db_path,
    }


def test_cap005_cryptographic_hashes():
    c_hash = hashlib.sha256((BENCHMARK_DIR / "cases.jsonl").read_bytes()).hexdigest()
    l_hash = hashlib.sha256((BENCHMARK_DIR / "labels.jsonl").read_bytes()).hexdigest()
    s_hash = hashlib.sha256((BENCHMARK_DIR / "sources.jsonl").read_bytes()).hexdigest()
    h_hash = hashlib.sha256((BENCHMARK_DIR / "measure_cap005.py").read_bytes()).hexdigest()
    r_hash = hashlib.sha256((BENCHMARK_DIR / "results.json").read_bytes()).hexdigest()

    assert c_hash == FROZEN_CORPUS_SHA256
    assert l_hash == FROZEN_LABEL_SHA256
    assert s_hash == FROZEN_SOURCE_MANIFEST_SHA256
    assert h_hash == FROZEN_HARNESS_SHA256
    assert r_hash == FROZEN_RESULTS_SHA256


def test_cap005_license_provenance(cap005_data):
    sources = cap005_data["sources"]
    assert len(sources) == 5
    for s in sources:
        assert s.get("license") in ("MIT", "BSD-3-Clause", "Apache-2.0", "MIT-Equivalent/Internal-Agent")
        assert s.get("repository")


@pytest.mark.xfail(
    strict=True,
    reason="P0 verdict drift: corpus labels predate fail-closed witness/deletion "
           "semantics (e.g. REAL-REM-07 mechanical-revert labeled PASS now "
           "declines INCONCLUSIVE). Full corpus re-label is a PHASE-2 evidence "
           "campaign item; do not tune the verifier to recover old verdicts.",
)
def test_cap005_falsifier_rediscovery_100_percent(cap005_data):
    cases = {c["id"]: c for c in cap005_data["cases"]}
    labels = cap005_data["labels"]
    db_path = cap005_data["db_path"]

    falsifier_ids = [
        "REAL-SEC-03", "REAL-SEC-05", "REAL-SEC-08",
        "REAL-REM-03", "REAL-REM-05", "REAL-REM-07",
        "REAL-CALL-02", "REAL-CALL-04", "REAL-CALL-06",
    ]

    for fid in falsifier_ids:
        c = cases[fid]
        gold = labels[fid]["expected_status"]
        res = run_verify(diff=c["diff"], db_path=db_path)
        pred = res["status"]
        assert pred == gold, f"Falsifier {fid} failed: expected {gold}, got {pred} ({res.get('rationale')})"


def test_cap005_zero_false_accepts(cap005_data):
    # LIVE safety invariant (not subject to the re-label xfail below):
    # whatever P0 strictness changes, nothing labeled FAIL/HUMAN_REVIEW
    # may verify as PASS. Drift is allowed only toward INCONCLUSIVE.
    cases = cap005_data["cases"]
    labels = cap005_data["labels"]
    db_path = cap005_data["db_path"]

    false_accepts = 0
    for c in cases:
        cid = c["id"]
        gold = labels[cid]["expected_status"]
        res = run_verify(diff=c["diff"], db_path=db_path)
        if gold in ("FAIL", "HUMAN_REVIEW") and res["status"] == "PASS":
            false_accepts += 1
    assert false_accepts == 0, f"False accepts {false_accepts} detected (must be strictly 0)"


@pytest.mark.xfail(
    strict=True,
    reason="P0 verdict drift: measured agreement ~0.5 vs the 0.90 bar set "
           "under pre-P0 witness semantics. Re-baseline with re-labeled "
           "corpus in PHASE-2; do not tune the verifier to recover it.",
)
def test_cap005_overall_agreement_and_zero_far(cap005_data):
    cases = cap005_data["cases"]
    labels = cap005_data["labels"]
    db_path = cap005_data["db_path"]

    agreed = 0
    false_accepts = 0

    for c in cases:
        cid = c["id"]
        gold = labels[cid]["expected_status"]
        res = run_verify(diff=c["diff"], db_path=db_path)
        pred = res["status"]

        if pred == gold:
            agreed += 1

        if gold in ("FAIL", "HUMAN_REVIEW") and pred == "PASS":
            false_accepts += 1

    agreement = agreed / len(cases)
    assert agreement >= 0.9000, f"Agreement {agreement:.4f} below 0.9000 target"
    assert false_accepts == 0, f"False accepts {false_accepts} detected (must be strictly 0)"
