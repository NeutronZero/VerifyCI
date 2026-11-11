"""Authoritative Independent Benchmark Evaluator and Private Oracle (§15.10 Component E).

Supervisor owns all expected outcomes and grading logic.
Candidate code receives only test scenarios, never expected outcomes or ground-truth defect classifications.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import random
from typing import Any

AUTHORITATIVE_SECURITY_CORPUS_HASH = (
    "sha256:8d45f911c72bfda761c21da754b235d7a58768864a1d0087d70d745eeb97b880"
)

REQUIRED_DEFECT_FAMILIES = (
    "SEC-SECRET",
    "SEC-SECRET-TO-SINK",
    "SEC-DANGEROUS-CALL",
    "SEC-TAINT-TO-SINK",
)


def load_authoritative_public_cases(trusted_root: Path) -> list[dict[str, Any]]:
    """Load and cryptographically verify the frozen 22-case public security corpus."""
    cases_file = trusted_root / "corpora" / "security" / "cases.jsonl"
    if not cases_file.is_file():
        raise FileNotFoundError(f"missing authoritative corpus: {cases_file}")

    content = cases_file.read_bytes()
    actual_hash = "sha256:" + hashlib.sha256(content).hexdigest()
    if not hmac.compare_digest(actual_hash.lower(), AUTHORITATIVE_SECURITY_CORPUS_HASH.lower()):
        raise ValueError(
            f"authoritative corpus hash mismatch: expected {AUTHORITATIVE_SECURITY_CORPUS_HASH}, got {actual_hash}"
        )

    cases: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for line in content.decode("utf-8").splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue
        case = json.loads(trimmed)
        cid = case.get("case_id")
        if not cid or cid in seen_ids:
            raise ValueError(f"duplicate or missing case_id: {cid}")
        seen_ids.add(cid)
        cases.append(case)

    if len(cases) != 22:
        raise ValueError(f"expected exactly 22 security benchmark cases, found {len(cases)}")
    return cases


def grade_case_result(
    case: dict[str, Any],
    candidate_response: dict[str, Any],
) -> tuple[bool, list[str], dict[str, Any]]:
    """Independently grade candidate response against the trusted expected outcome."""
    cid = case["case_id"]
    exp = case["expected"]
    errors: list[str] = []

    cand_outcome = candidate_response.get("outcome")
    cand_coverage = candidate_response.get("coverage")
    cand_reason_codes = sorted(candidate_response.get("reason_codes", []))
    cand_findings = sorted(f.get("defect_id", "") for f in candidate_response.get("findings", []))

    exp_outcome = exp["outcome"]
    exp_coverage = exp["coverage"]
    exp_reason_codes = sorted(exp.get("reason_codes", []))
    exp_findings = sorted(f.get("defect_id", "") for f in exp.get("findings", []))

    if cand_outcome != exp_outcome:
        errors.append(f"{cid}: outcome {cand_outcome} != expected {exp_outcome}")
    if cand_coverage != exp_coverage:
        errors.append(f"{cid}: coverage {cand_coverage} != expected {exp_coverage}")
    if cand_reason_codes != exp_reason_codes:
        errors.append(f"{cid}: reason codes {cand_reason_codes} != expected {exp_reason_codes}")
    if cand_findings != exp_findings:
        errors.append(f"{cid}: defect findings {cand_findings} != expected {exp_findings}")

    # False blocking invariant: clean control cases (expected != FAIL) must never return FAIL
    is_false_blocking = (exp_outcome != "FAIL" and cand_outcome == "FAIL")
    if is_false_blocking:
        errors.append(f"{cid}: false blocking failure on non-defective control case")

    # Strict redaction check: findings message and subject must not leak raw secrets
    strict_redaction = True
    for finding in candidate_response.get("findings", []):
        msg = str(finding.get("message", ""))
        # Simple heuristic matching for raw unredacted high-entropy tokens
        if "ghp_" in msg or "AKIA" in msg or "sk_live_" in msg:
            strict_redaction = False
            errors.append(f"{cid}: raw unredacted secret found in finding message")

    case_metrics = {
        "case_id": cid,
        "matched": len(errors) == 0,
        "cand_outcome": cand_outcome,
        "exp_outcome": exp_outcome,
        "cand_findings": cand_findings,
        "exp_findings": exp_findings,
        "strict_redaction": strict_redaction,
        "false_blocking": is_false_blocking,
    }
    return len(errors) == 0, errors, case_metrics


def aggregate_benchmark_metrics(case_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute precision, recall, and confusion matrix across declared defect families."""
    defects = list(REQUIRED_DEFECT_FAMILIES)
    confusion = {d: {"TP": 0, "FP": 0, "FN": 0, "TN": 0} for d in defects}

    total_cases = len(case_results)
    matched_cases = sum(1 for c in case_results if c.get("matched", False))
    strict_redaction_all = all(c.get("strict_redaction", True) for c in case_results)
    zero_false_blocking = not any(
        c.get("false_blocking", False) or (c.get("exp_outcome") != "FAIL" and c.get("cand_outcome") == "FAIL")
        for c in case_results
    )

    for c in case_results:
        cand_set = set(c["cand_findings"])
        exp_set = set(c["exp_findings"])
        for did in defects:
            in_cand = did in cand_set
            in_exp = did in exp_set
            if in_cand and in_exp:
                confusion[did]["TP"] += 1
            elif in_cand and not in_exp:
                confusion[did]["FP"] += 1
            elif not in_cand and in_exp:
                confusion[did]["FN"] += 1
            else:
                confusion[did]["TN"] += 1

    defect_metrics: dict[str, Any] = {}
    for did, counts in confusion.items():
        tp = counts["TP"]
        fp = counts["FP"]
        fn = counts["FN"]
        tn = counts["TN"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        defect_metrics[did] = {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": float(round(precision, 4)),
            "recall": float(round(recall, 4)),
        }

    return {
        "cases_evaluated": total_cases,
        "coverage_matches": matched_cases,
        "zero_false_blocking": zero_false_blocking,
        "strict_redaction": strict_redaction_all,
        "defects": defect_metrics,
    }


def generate_held_out_scenarios(
    seed_hex: str,
    base_cases: list[dict[str, Any]],
    count: int = 10,
) -> tuple[list[dict[str, Any]], str, str]:
    """Generate private held-out metamorphic test scenarios from 256-bit secret seed.

    Returns: (held_out_cases, seed_commitment, seed_epoch).
    """
    seed_bytes = bytes.fromhex(seed_hex)
    commitment = "sha256:" + hashlib.sha256(seed_bytes).hexdigest()
    epoch = hmac.new(
        b"VERIFYCI-HELDOUT-EPOCH-COMMITMENT", seed_bytes, hashlib.sha256
    ).hexdigest()[:16]

    rng = random.Random(seed_bytes)
    scenarios: list[dict[str, Any]] = []

    var_targets = ["temp_var", "result", "payload", "token", "item", "secret_value", "data"]

    for i in range(count):
        source_case = rng.choice(base_cases)
        mutated_case = {
            "case_id": f"heldout_{epoch}_{i:03d}",
            "base_files": dict(source_case["base_files"]),
            "head_files": dict(source_case["head_files"]),
            "policy": dict(source_case.get("policy", {})),
            "expected": dict(source_case["expected"]),
        }
        suffix = f"_{rng.randint(1000, 9999)}"
        new_head: dict[str, str] = {}
        for fname, content in mutated_case["head_files"].items():
            mod_content = content
            # Metamorphic mutation 1: variable identifier renaming
            for v in var_targets:
                if v in mod_content and f"def {v}" not in mod_content:
                    mod_content = mod_content.replace(v, f"{v}{suffix}")
            # Metamorphic mutation 2: benign comments & docstrings
            comment_marker = f"# verifyci-metamorphic: epoch={epoch} idx={i} salt={rng.randint(100, 999)}\n"
            mod_content = comment_marker + mod_content
            # Metamorphic mutation 3: inert helper function insertion
            inert_fn = f"\ndef _inert_helper_{suffix}():\n    return {rng.randint(1, 100)}\n"
            mod_content += inert_fn
            new_head[fname] = mod_content
        mutated_case["head_files"] = new_head
        scenarios.append(mutated_case)

    return scenarios, commitment, epoch
