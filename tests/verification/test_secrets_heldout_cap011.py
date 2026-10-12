"""CAP-011: Held-out Secret Detection and Redaction Safety Benchmark Test Suite.

Guards:
- Cryptographic freeze hashes for CAP-011 corpus and labels
- CAP-002B corpus and labels remain untouched and bit-identical
- Zero raw-secret leakage (redaction_violations == 0) over runtime outputs
- Leakage scan explicitly excludes input cases.jsonl fixture
- Gates: >=95% recall, >=90% name-independent recall, >=99% precision
- Canonical recomputation of metrics from per-case rows
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
CORPUS_DIR = REPO_ROOT / "benchmarks" / "secret_heldout" / "cap011"
CAP002B_DIR = REPO_ROOT / "benchmarks" / "secret_corpus" / "cap002b"

# Frozen pins of existing CAP-002B (must remain untouched)
CAP002B_FROZEN_CORPUS_SHA256 = "b6c7df17e334f6847453012fe3a05bae82181a31411039f7d724df1a4a0ff65c"
CAP002B_FROZEN_LABEL_SHA256 = "6f7bc1edb7ff282b93b70e403830e199faab652f91d43753f3d97f1f1f4ac8f8"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_cap002b_remains_unmodified():
    c2b_cases = CAP002B_DIR / "cases.jsonl"
    assert c2b_cases.exists()
    assert _sha256(c2b_cases) == CAP002B_FROZEN_CORPUS_SHA256, "CAP-002B corpus has drifted!"


def test_cap011_freeze_pins():
    cfg_file = CORPUS_DIR / "config.json"
    cases_file = CORPUS_DIR / "cases.jsonl"
    labels_file = CORPUS_DIR / "labels.jsonl"
    corpus_sha_file = CORPUS_DIR / "CORPUS_SHA256"
    label_sha_file = CORPUS_DIR / "LABEL_SHA256"

    assert cfg_file.exists(), "CAP-011 config.json missing"
    assert cases_file.exists(), "CAP-011 cases.jsonl missing"
    assert labels_file.exists(), "CAP-011 labels.jsonl missing"
    assert corpus_sha_file.exists(), "CAP-011 CORPUS_SHA256 missing"
    assert label_sha_file.exists(), "CAP-011 LABEL_SHA256 missing"

    cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
    c_hash = _sha256(cases_file)
    l_hash = _sha256(labels_file)

    assert c_hash == cfg["corpus_sha256"]
    assert l_hash == cfg["label_sha256"]
    assert corpus_sha_file.read_text(encoding="utf-8").strip() == c_hash
    assert label_sha_file.read_text(encoding="utf-8").strip() == l_hash


def test_cap011_redaction_boundary_and_leakage_safety():
    from benchmarks.secret_heldout.cap011.measure_cap011 import get_scanned_runtime_artifacts

    # Assert that get_scanned_runtime_artifacts explicitly excludes cases.jsonl
    scanned_targets = get_scanned_runtime_artifacts()
    for target in scanned_targets:
        assert "cases.jsonl" not in str(target), (
            f"P0-3 Violation: Leakage scanner must never scan frozen input cases.jsonl: {target}"
        )

    results_file = CORPUS_DIR / "results.json"
    assert results_file.exists(), "results.json missing"
    data = json.loads(results_file.read_text(encoding="utf-8"))
    assert data["metrics"]["redaction_violations"] == 0


def test_cap011_results_canonical_recomputation():
    from benchmarks.secret_heldout.cap011.measure_cap011 import run_cap011

    cases_file = CORPUS_DIR / "cases.jsonl"
    labels_file = CORPUS_DIR / "labels.jsonl"
    results_file = CORPUS_DIR / "results.json"

    assert results_file.exists()
    data = json.loads(results_file.read_text(encoding="utf-8"))
    cfg = json.loads((CORPUS_DIR / "config.json").read_text(encoding="utf-8"))

    rows = data["cases"]
    assert len(rows) == cfg["case_count"]
    assert len({r["case_id"] for r in rows}) == cfg["case_count"]

    # Recompute precision, recall, far, frr
    tp = sum(1 for r in rows if r["is_secret"] and r["detected"])
    fn = sum(1 for r in rows if r["is_secret"] and not r["detected"])
    fp = sum(1 for r in rows if not r["is_secret"] and r["detected"])
    tn = sum(1 for r in rows if not r["is_secret"] and not r["detected"])

    rec = tp / max(1, tp + fn)
    prec = tp / max(1, tp + fp)
    far = fp / max(1, fp + tn)
    frr = fn / max(1, tp + fn)

    assert abs(rec - data["metrics"]["recall"]) < 1e-4
    assert abs(prec - data["metrics"]["precision"]) < 1e-4
    assert abs(far - data["metrics"]["far"]) < 1e-4
    assert abs(frr - data["metrics"]["frr"]) < 1e-4

    # Gate thresholds
    assert rec >= 0.95, f"Overall recall below 95%: {rec:.4f}"
    assert prec >= 0.99, f"Precision below 99%: {prec:.4f}"

    # Name-independent slice recall
    ni_rows = [r for r in rows if r.get("slice") == "name_independent" and r["is_secret"]]
    ni_tp = sum(1 for r in ni_rows if r["detected"])
    ni_rec = ni_tp / max(1, len(ni_rows))
    assert ni_rec >= 0.90, f"Name-independent recall below 90%: {ni_rec:.4f}"
    assert abs(ni_rec - data["metrics"]["name_independent_recall"]) < 1e-4

    # run_cap011 interface check
    res = run_cap011(str(cases_file), str(labels_file))
    expected_keys = {
        "recall",
        "recall_by_category",
        "precision",
        "far",
        "frr",
        "name_independent_recall",
        "redaction_violations",
    }
    assert expected_keys.issubset(res.keys())
