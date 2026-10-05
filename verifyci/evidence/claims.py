"""Canonical, fail-closed predicates for empirical evidence claims.

The evidence bundle, regression tests, and CI evidence gate must derive claim
status from the same raw benchmark inputs.  Recorded gate booleans are retained
as provenance metadata, but never trusted for establishment.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CLAIM_RESULT_PATHS = {
    "H1_retrieval_fusion": Path("benchmarks/beir/results.json"),
    "patch_corpus_verifier": Path("benchmarks/patch_corpus/results.json"),
    "blast_radius_bounds": Path("benchmarks/blast_corpus/results.json"),
}

# Canonical establishment thresholds. Tests and bundle generation import these
# predicates rather than copying numeric gates into separate implementations.
H1_MIN_DELTA_NDCG = 0.05
H1_MIN_QUERIES = 50
PATCH_MIN_AGREEMENT = 0.90
PATCH_MIN_DETERMINISTIC_CATCH = 0.95
PATCH_MAX_SEMANTIC_FALSE_ACCEPT = 0.0
BLAST_MIN_SEEDED_COVERAGE = 0.95
BLAST_MIN_ALL_COVERAGE = 0.90


@dataclass(frozen=True)
class EvidenceLoad:
    """Result of loading one benchmark evidence file."""

    ok: bool
    data: dict[str, Any] | None = None
    error: str | None = None


def load_evidence(path: Path) -> EvidenceLoad:
    """Load a JSON evidence artifact fail-closed.

    Missing, unreadable, invalid-JSON, or non-object artifacts never become
    measurable/established claims; the caller receives a failed load result.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError) as exc:
        return EvidenceLoad(False, error=f"unavailable:{type(exc).__name__}")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return EvidenceLoad(False, error=f"invalid_json:{exc.msg}")

    if not isinstance(data, dict):
        return EvidenceLoad(False, error="invalid_shape:expected_object")
    return EvidenceLoad(True, data=data)


def _require_mapping(data: dict[str, Any], key: str) -> dict[str, Any] | None:
    value = data.get(key)
    return value if isinstance(value, dict) else None


def _require_number(data: dict[str, Any], key: str) -> float | None:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _missing_claim(error: str) -> dict[str, Any]:
    return {"status": "MISSING", "error": error}


def _evaluate_h1(data: dict[str, Any]) -> dict[str, Any]:
    metrics = _require_mapping(data, "metrics")
    run = _require_mapping(data, "run")
    validators = _require_mapping(data, "validators")
    if metrics is None or run is None or validators is None:
        return _missing_claim("missing_required_sections")

    dense_block = _require_mapping(metrics, "dense")
    hybrid_block = _require_mapping(metrics, "hybrid")
    queries = run.get("queries")
    errors = validators.get("errors")
    drift = validators.get("drift")
    dry_run = run.get("dry_run")

    dense_ndcg = _require_number(dense_block or {}, "ndcg")
    hybrid_ndcg = _require_number(hybrid_block or {}, "ndcg")
    if dense_ndcg is None or hybrid_ndcg is None:
        return _missing_claim("missing_required_metrics")
    if not isinstance(queries, int) or isinstance(queries, bool):
        return _missing_claim("missing_queries")
    if not isinstance(errors, list) or not isinstance(drift, bool) or not isinstance(dry_run, bool):
        return _missing_claim("missing_validator_state")

    # Derive the delta from the two underlying metric values; do not trust the
    # recorded metrics.delta_ndcg or gate.established fields for establishment.
    delta_ndcg = hybrid_ndcg - dense_ndcg
    established = (
        delta_ndcg >= H1_MIN_DELTA_NDCG
        and queries >= H1_MIN_QUERIES
        and not errors
        and not drift
        and not dry_run
    )
    gate = _require_mapping(data, "gate")
    return {
        "status": "ESTABLISHED" if established else "MEASURED",
        "metric": "nDCG@10 delta",
        "delta_ndcg": delta_ndcg,
        "recorded_delta_ndcg": metrics.get("delta_ndcg"),
        "dense_ndcg": dense_ndcg,
        "hybrid_ndcg": hybrid_ndcg,
        "queries": queries,
        "recorded_gate_established": gate.get("established") if gate is not None else None,
    }


def _evaluate_patch(data: dict[str, Any]) -> dict[str, Any]:
    metrics = _require_mapping(data, "metrics")
    if metrics is None:
        return _missing_claim("missing_required_sections")

    agreement = _require_number(metrics, "overall_agreement")
    catch_rate = _require_number(metrics, "deterministic_catch_rate")
    false_accept_rate = _require_number(metrics, "semantic_false_accept_rate")
    if agreement is None or catch_rate is None or false_accept_rate is None:
        return _missing_claim("missing_required_metrics")

    established = (
        agreement >= PATCH_MIN_AGREEMENT
        and catch_rate >= PATCH_MIN_DETERMINISTIC_CATCH
        and false_accept_rate <= PATCH_MAX_SEMANTIC_FALSE_ACCEPT
    )
    return {
        "status": "ESTABLISHED" if established else "MEASURED",
        "overall_agreement": agreement,
        "deterministic_catch_rate": catch_rate,
        "semantic_false_accept_rate": false_accept_rate,
        "n_correct": metrics.get("n_correct"),
        "n_wrong": metrics.get("n_wrong"),
    }


def _evaluate_blast(data: dict[str, Any]) -> dict[str, Any]:
    metrics = _require_mapping(data, "metrics")
    if metrics is None:
        return _missing_claim("missing_required_sections")

    cov_seeded = _require_number(metrics, "coverage_seeded_only")
    cov_all = _require_number(metrics, "coverage_all")
    if cov_seeded is None or cov_all is None:
        return _missing_claim("missing_required_metrics")

    established = cov_seeded >= BLAST_MIN_SEEDED_COVERAGE and cov_all >= BLAST_MIN_ALL_COVERAGE
    return {
        "status": "ESTABLISHED" if established else "MEASURED",
        "coverage_seeded_only": cov_seeded,
        "coverage_all": cov_all,
    }


def evaluate_claim(claim_name: str, evidence: EvidenceLoad | dict[str, Any] | None) -> dict[str, Any]:
    """Evaluate one named claim from raw benchmark evidence."""
    if isinstance(evidence, EvidenceLoad):
        if not evidence.ok or evidence.data is None:
            return _missing_claim(evidence.error or "evidence_unavailable")
        data = evidence.data
    elif isinstance(evidence, dict):
        data = evidence
    else:
        return _missing_claim("evidence_unavailable")

    evaluators = {
        "H1_retrieval_fusion": _evaluate_h1,
        "patch_corpus_verifier": _evaluate_patch,
        "blast_radius_bounds": _evaluate_blast,
    }
    evaluator = evaluators.get(claim_name)
    if evaluator is None:
        raise KeyError(f"unknown evidence claim: {claim_name}")
    return evaluator(data)


def is_established(claim_name: str, evidence: EvidenceLoad | dict[str, Any] | None) -> bool:
    """Return whether a claim is established by canonical evidence predicates."""
    return evaluate_claim(claim_name, evidence).get("status") == "ESTABLISHED"


def evaluate_claims(root: Path) -> dict[str, Any]:
    """Evaluate every canonical benchmark claim under ``root``."""
    claims: dict[str, dict[str, Any]] = {}
    missing_benchmarks: list[str] = []

    for claim_name, relative_path in CLAIM_RESULT_PATHS.items():
        result = evaluate_claim(claim_name, load_evidence(root / relative_path))
        claims[claim_name] = result
        if result.get("status") == "MISSING":
            missing_benchmarks.append(claim_name)

    statuses = [claim["status"] for claim in claims.values()]
    overall = "ESTABLISHED" if statuses and all(s == "ESTABLISHED" for s in statuses) else "UNESTABLISHED"
    return {
        "overall_status": overall,
        "claims": claims,
        "missing_benchmarks": missing_benchmarks,
    }
