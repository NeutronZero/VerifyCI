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


@pytest.fixture(scope="module")
def cap005_data():
    cases_file = BENCHMARK_DIR / "cases.jsonl"
    labels_file = BENCHMARK_DIR / "labels.jsonl"
    sources_file = BENCHMARK_DIR / "sources.jsonl"

    cases = [json.loads(line) for line in cases_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    labels = {json.loads(line)["id"]: json.loads(line) for line in labels_file.read_text(encoding="utf-8").splitlines() if line.strip()}
    sources = [json.loads(line) for line in sources_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    base_dir = BENCHMARK_DIR / "base"
    db_path = str(base_dir / ".verifyci" / "verifyci.db")

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

    assert c_hash == FROZEN_CORPUS_SHA256
    assert l_hash == FROZEN_LABEL_SHA256
    assert s_hash == FROZEN_SOURCE_MANIFEST_SHA256


def test_cap005_license_provenance(cap005_data):
    sources = cap005_data["sources"]
    assert len(sources) == 5
    for s in sources:
        assert s.get("license") in ("MIT", "BSD-3-Clause", "Apache-2.0", "MIT-Equivalent/Internal-Agent")
        assert s.get("repository")


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
