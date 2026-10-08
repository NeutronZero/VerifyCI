"""H2 measurement passes (ONE run each, no tuning).

Scores the frozen v2 invariant corpus with the current tree. Reads
labels read-only; writes benchmarks/invariants/results_h2.json only,
PRESERVING existing entries (the H2-B isolated record is history, never
rewritten). Run 1 recorded the H2-B state; run 2 (final) records the
combined B+C state. Asserts nothing about gates — raw metrics recorded;
classification is mechanical from the numbers, not hidden logic.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from tests.evaluation.test_labeled_ground_truth_v2 import load_v2_cases  # noqa: E402
from verifyci.verification.intent_align import score_labeled  # noqa: E402

LABELS = Path("tests/evaluation/labels/invariants_v2.jsonl")
FROZEN_SHA = "e17d65878ccc53305d6c581525524c573fa7fa1615cf2ea29bdf077e38e39011"
V102_BASELINE = {"recall": 16 / 18, "precision": 1.0, "coverage": 1.0}


def _classify(measured: dict) -> str:
    if measured["precision"] != 1.0 or measured["coverage"] != 1.0:
        return "REGRESSED"
    if measured["recall"] > V102_BASELINE["recall"]:
        return "IMPROVED"
    if measured["recall"] == V102_BASELINE["recall"]:
        return "NEUTRAL"
    return "REGRESSED"


def main() -> None:
    which = sys.argv[1] if len(sys.argv) > 1 else "final"
    assert which in ("h2b", "final"), "usage: h2_measure.py [h2b|final]"
    sha = hashlib.sha256(LABELS.read_bytes()).hexdigest()
    assert sha == FROZEN_SHA, f"frozen corpus changed: {sha}"
    metrics = score_labeled(load_v2_cases())
    assert metrics.detection_recall is not None and metrics.detection_precision is not None, (
        "unmeasured recall/precision cannot gate")
    measured = {
        "recall": metrics.detection_recall,
        "precision": metrics.detection_precision,
        "coverage": metrics.check_coverage,
    }
    gate = {
        "recall_ge_090": measured["recall"] >= 0.90,
        "precision_is_100": measured["precision"] == 1.0,
        "coverage_is_100": measured["coverage"] == 1.0,
    }
    dest = HERE / "results_h2.json"
    report = json.loads(dest.read_text(encoding="utf-8")) if dest.exists() else {}
    report.setdefault("frozen_reference", "v1.0.2-correctness")
    report.setdefault("v102_baseline", V102_BASELINE)
    if which == "h2b":
        if "h2_b" in report and not os.environ.get("VERIFYCI_REBENCHMARK"):
            raise SystemExit(f"{dest} exists; set VERIFYCI_REBENCHMARK=1 to overwrite")
        report["h2_b"] = {
            "measured": measured, "gate": gate,
            "classification": _classify(measured),
            "scope_notes": [
                "H2-C not implemented (short-secret residual still missed).",
                "added_refs lexical path untouched (out of scope).",
                "No thresholds tuned; single pass.",
            ],
        }
    else:
        if "final" in report and not os.environ.get("VERIFYCI_REBENCHMARK"):
            raise SystemExit(f"{dest} exists; set VERIFYCI_REBENCHMARK=1 to overwrite")
        report["final"] = {
            "measured": measured, "gate": gate,
            "classification": _classify(measured),
            "scope_notes": [
                "Combined B+C state; B and C never measured combined before this pass.",
                "added_refs lexical path untouched (out of scope).",
                "No thresholds tuned; single pass.",
            ],
        }
    report["frozen_labels_sha256_reverified"] = sha
    dest.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"H2-{which}: recall={measured['recall']:.4f} "
          f"precision={measured['precision']:.4f} "
          f"coverage={measured['coverage']:.4f} "
          f"classification={report['final' if which == 'final' else 'h2_b']['classification']} "
          f"-> {dest.name}")


if __name__ == "__main__":
    main()
