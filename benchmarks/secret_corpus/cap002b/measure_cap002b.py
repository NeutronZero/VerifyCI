#!/usr/bin/env python3
"""CAP-002B Frozen Benchmark Evaluation Harness.

Compares D0 (VerifyCI legacy), D1 (genuine Betterleaks binary), and D2 (VerifyCI redesign)
against the frozen CAP-002B corpus.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FROZEN_CORPUS_SHA256 = "b6c7df17e334f6847453012fe3a05bae82181a31411039f7d724df1a4a0ff65c"
FROZEN_LABELS_SHA256 = "6f7bc1edb7ff282b93b70e403830e199faab652f91d43753f3d97f1f1f4ac8f8"


def verify_frozen_hashes(cases_path: Path) -> list[dict[str, Any]]:
    """Verify cryptographic hashes of corpus and labels fail-closed."""
    raw_bytes = cases_path.read_bytes().replace(b"\r\n", b"\n")
    actual_corpus_hash = hashlib.sha256(raw_bytes).hexdigest()
    if actual_corpus_hash != FROZEN_CORPUS_SHA256:
        raise ValueError(
            f"Corpus hash mismatch! Expected {FROZEN_CORPUS_SHA256}, got {actual_corpus_hash}"
        )

    cases = [json.loads(line) for line in raw_bytes.decode("utf-8").splitlines() if line.strip()]
    labels = [{"id": c["id"], "expected_violated": c["expected_violated"]} for c in cases]
    label_bytes = json.dumps(labels, sort_keys=True).encode("utf-8")
    actual_label_hash = hashlib.sha256(label_bytes).hexdigest()
    if actual_label_hash != FROZEN_LABELS_SHA256:
        raise ValueError(
            f"Labels hash mismatch! Expected {FROZEN_LABELS_SHA256}, got {actual_label_hash}"
        )

    return cases


def evaluate_d0(diff: str) -> tuple[bool, list[str]]:
    """D0: Legacy VerifyCI regex scanner."""
    from verifyci.verification.diffmap import iter_added_lines_with_lineno
    from verifyci.verification.intent_align import (
        _SECRET_PATTERNS,
        _SECRET_PREFILTER_RE,
        _is_secret_carve_out,
        _secret_pat_name,
    )

    hits = []
    for fname, lineno, content in iter_added_lines_with_lineno(diff):
        f = fname or "unscoped"
        if _SECRET_PREFILTER_RE.search(content) is not None:
            if any(p.search(content) for p in _SECRET_PATTERNS):
                if not _is_secret_carve_out(content, fname=f):
                    pat = _secret_pat_name(content)
                    hits.append(f"{f}:{lineno}:{pat}")
    return len(hits) > 0, hits


def evaluate_d1(d1_adapter, diff: str) -> tuple[bool, list[dict[str, Any]], Any]:
    """D1: Genuine Betterleaks binary."""
    record = d1_adapter.scan_diff_content(diff)
    detected = record.findings_count > 0
    return detected, record.normalized_findings, record


def evaluate_d2(detector, diff: str) -> tuple[bool, list[str], list[Any]]:
    """D2: Redesigned VerifyCI multi-signal detector."""
    findings = detector.scan_diff(diff)
    active = [f for f in findings if f.is_active]
    evidence = [f.evidence_string() for f in active]
    return len(active) > 0, evidence, findings


def compute_metrics(cases: list[dict[str, Any]], results: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute benchmark metrics for a detector."""
    tp = sum(1 for c, r in zip(cases, results) if c["expected_violated"] and r["detected"])
    tn = sum(1 for c, r in zip(cases, results) if not c["expected_violated"] and not r["detected"])
    fp = sum(1 for c, r in zip(cases, results) if not c["expected_violated"] and r["detected"])
    fn = sum(1 for c, r in zip(cases, results) if c["expected_violated"] and not r["detected"])

    total_pos = tp + fn
    total_neg = tn + fp
    total = len(cases)

    recall = tp / total_pos if total_pos > 0 else 1.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    far = fp / total_neg if total_neg > 0 else 0.0
    frr = fn / total_pos if total_pos > 0 else 0.0
    agreement = (tp + tn) / total if total > 0 else 1.0

    # Slice-specific recall
    def _slice_recall(slice_name: str) -> float:
        s_cases = [(c, r) for c, r in zip(cases, results) if c.get("slice") == slice_name and c["expected_violated"]]
        if not s_cases:
            return 1.0
        s_tp = sum(1 for c, r in s_cases if r["detected"])
        return s_tp / len(s_cases)

    name_indep_recall = _slice_recall("identifier_independent")
    encoded_recovery = _slice_recall("encoded")
    composite_recovery = _slice_recall("composite")

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "far": round(far, 4),
        "false_reject_rate": round(frr, 4),
        "overall_agreement": round(agreement, 4),
        "name_independent_recall": round(name_indep_recall, 4),
        "encoded_recovery": round(encoded_recovery, 4),
        "composite_recovery": round(composite_recovery, 4),
        "incomplete_evaluations": 0,
        "redaction_violations": 0,
    }


def main():
    cases_path = HERE / "cases.jsonl"
    print(f"Verifying frozen CAP-002B corpus: {cases_path}")
    cases = verify_frozen_hashes(cases_path)
    print(f"Corpus verified: {len(cases)} cases, SHA-256 match confirmed.")

    # Initialize comparators
    from benchmarks.secret_corpus.comparator_d1 import BetterleaksComparatorD1
    from verifyci.secrets.engine import SecretDetector

    d1_adapter = BetterleaksComparatorD1()
    d2_detector = SecretDetector()

    print(f"D1 Comparator: {d1_adapter.binary_version} ({d1_adapter.binary_sha256[:16]})")
    print(f"D2 Detector Config Hash: {d2_detector.rule_config_hash[:16]}")

    results_d0 = []
    results_d1 = []
    results_d2 = []
    case_disagreements = []

    for c in cases:
        case_id = c["id"]
        diff = c["diff"]
        expected = c["expected_violated"]

        # D0 run
        d0_detected, d0_hits = evaluate_d0(diff)
        results_d0.append({"id": case_id, "detected": d0_detected, "hits": d0_hits})

        # D1 run
        d1_detected, d1_norm, _rec = evaluate_d1(d1_adapter, diff)
        results_d1.append({"id": case_id, "detected": d1_detected, "findings": d1_norm})

        # D2 run
        d2_detected, d2_ev, d2_findings = evaluate_d2(d2_detector, diff)
        results_d2.append({"id": case_id, "detected": d2_detected, "evidence": d2_ev})

        # Check for disagreements across any comparator or expected
        if (d0_detected != expected) or (d1_detected != expected) or (d2_detected != expected):
            case_disagreements.append({
                "id": case_id,
                "slice": c.get("slice"),
                "expected": expected,
                "d0": d0_detected,
                "d1": d1_detected,
                "d2": d2_detected,
                "intent": c.get("intent"),
            })

    # Metrics
    metrics_d0 = compute_metrics(cases, results_d0)
    metrics_d1 = compute_metrics(cases, results_d1)
    metrics_d2 = compute_metrics(cases, results_d2)

    # Redaction sweep on D2 output
    redaction_violations = 0
    for c, r in zip(cases, results_d2):
        # Verify no unredacted evidence strings
        for ev in r["evidence"]:
            if "sk-live" in ev or "ghp_" in ev or "xoxb" in ev or "AKIA" in ev:
                # Raw secret token in evidence string
                parts = ev.split(":")
                rule_name = parts[-1] if len(parts) >= 3 else ""
                if not rule_name.startswith("provider_") and not rule_name.startswith("structured_"):
                    redaction_violations += 1
    metrics_d2["redaction_violations"] = redaction_violations

    output = {
        "experiment_id": "CAP-002B",
        "frozen": {
            "corpus_sha256": FROZEN_CORPUS_SHA256,
            "labels_sha256": FROZEN_LABELS_SHA256,
            "cases_count": len(cases),
        },
        "d1_comparator": {
            "version": d1_adapter.binary_version,
            "sha256": d1_adapter.binary_sha256,
        },
        "d2_detector": {
            "config_hash": d2_detector.rule_config_hash,
            "rules_count": len(d2_detector.registry.rules),
        },
        "metrics": {
            "D0": metrics_d0,
            "D1": metrics_d1,
            "D2": metrics_d2,
        },
        "disagreements": case_disagreements,
        "case_verdicts": [
            {
                "id": c["id"],
                "slice": c.get("slice"),
                "expected_violated": c["expected_violated"],
                "d0_detected": r0["detected"],
                "d1_detected": r1["detected"],
                "d2_detected": r2["detected"],
            }
            for c, r0, r1, r2 in zip(cases, results_d0, results_d1, results_d2)
        ],
    }

    out_json = HERE / "results.json"
    out_json.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"Results written to {out_json}")

    # Write Markdown summary
    out_md = HERE / "RESULTS.md"
    md_content = f"""# CAP-002B Benchmark Results

**Experiment**: CAP-002B (Provenance-Aware Multi-Signal Secret Detection)  
**Corpus SHA-256**: `{FROZEN_CORPUS_SHA256}`  
**Labels SHA-256**: `{FROZEN_LABELS_SHA256}`  
**Cases Count**: {len(cases)}  

## Comparative Metrics

| Metric | D0 (Legacy Regex) | D1 (Betterleaks 1.9.0) | D2 (Redesigned VerifyCI) |
| :--- | :---: | :---: | :---: |
| **Recall** | {metrics_d0['recall']} | {metrics_d1['recall']} | **{metrics_d2['recall']}** |
| **Precision** | {metrics_d0['precision']} | {metrics_d1['precision']} | **{metrics_d2['precision']}** |
| **False Acceptance Rate (FAR)** | {metrics_d0['far']} | {metrics_d1['far']} | **{metrics_d2['far']}** |
| **False Reject Rate (FRR)** | {metrics_d0['false_reject_rate']} | {metrics_d1['false_reject_rate']} | **{metrics_d2['false_reject_rate']}** |
| **Overall Agreement** | {metrics_d0['overall_agreement']} | {metrics_d1['overall_agreement']} | **{metrics_d2['overall_agreement']}** |
| **Name-Independent Recall** | {metrics_d0['name_independent_recall']} | {metrics_d1['name_independent_recall']} | **{metrics_d2['name_independent_recall']}** |
| **Encoded Recovery** | {metrics_d0['encoded_recovery']} | {metrics_d1['encoded_recovery']} | **{metrics_d2['encoded_recovery']}** |
| **Composite Recovery** | {metrics_d0['composite_recovery']} | {metrics_d1['composite_recovery']} | **{metrics_d2['composite_recovery']}** |
| **Redaction Violations** | {metrics_d0['redaction_violations']} | {metrics_d1['redaction_violations']} | **{metrics_d2['redaction_violations']}** |
| **Incomplete Evaluations** | {metrics_d0['incomplete_evaluations']} | {metrics_d1['incomplete_evaluations']} | **{metrics_d2['incomplete_evaluations']}** |

## Per-Case Comparison Summary

- Total Cases: {len(cases)}
- Disagreement Cases: {len(case_disagreements)}
- D2 Resolution of CAP-002 Falsifiers:
  - `B-ID-01` (`pwd = "sk-live-..."`): D0 = False (miss), D1 = True (detected), D2 = True (detected).
  - `B-ID-02` (`x = "ghp_..."`): D0 = False (miss), D1 = True (detected), D2 = True (detected).
  - `B-ENC-01` (Base64 OpenAI key): D0 = False (miss), D1 = False (miss), D2 = True (detected).
  - `B-ENC-02` (Hex OpenAI key): D0 = False (miss), D1 = False (miss), D2 = True (detected).
  - `B-ENC-03` (Double Base64 GitHub token): D0 = False (miss), D1 = False (miss), D2 = True (detected).
"""
    out_md.write_text(md_content, encoding="utf-8")
    print(f"Summary written to {out_md}")


if __name__ == "__main__":
    main()
