"""Canonical, fail-closed predicates for empirical evidence claims.

The evidence bundle, regression tests, and CI evidence gate must derive claim
status from the same raw benchmark inputs.  Recorded gate booleans are retained
as provenance metadata, but never trusted for establishment.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CLAIM_RESULT_PATHS = {
    "H1_retrieval_fusion": Path("benchmarks/beir/results.json"),
    "H1_RR_reranked_hybrid": Path("benchmarks/beir/rerank_revision/results.json"),
    "patch_corpus_verifier": Path("benchmarks/patch_corpus/results.json"),
    "blast_radius_bounds": Path("benchmarks/blast_corpus/results.json"),
}

# Canonical establishment thresholds. Tests and bundle generation import these
# predicates rather than copying numeric gates into separate implementations.
H1_MIN_DELTA_NDCG = 0.05
H1_MIN_QUERIES = 50
H1_RR_MIN_DELTA_NDCG = 0.05
H1_RR_MIN_QUERIES = 50
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


def _evaluate_h1_rr(data: dict[str, Any]) -> dict[str, Any]:
    """H1-RR: reranked-hybrid claim. Same establishment shape as H1, but the
    hybrid arm includes the cross-encoder rerank stage recorded in the
    revision config. Recorded gate booleans are provenance only."""
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

    delta_ndcg = hybrid_ndcg - dense_ndcg
    established = (
        delta_ndcg >= H1_RR_MIN_DELTA_NDCG
        and queries >= H1_RR_MIN_QUERIES
        and not errors
        and not drift
        and not dry_run
    )
    frozen = _require_mapping(data, "frozen") or {}
    gate = _require_mapping(data, "gate")
    return {
        "status": "ESTABLISHED" if established else "MEASURED",
        "metric": "nDCG@10 delta (reranked hybrid)",
        "delta_ndcg": delta_ndcg,
        "recorded_delta_ndcg": metrics.get("delta_ndcg"),
        "dense_ndcg": dense_ndcg,
        "hybrid_ndcg": hybrid_ndcg,
        "queries": queries,
        "rerank_model": frozen.get("model_rerank"),
        "rerank_depth": frozen.get("rerank_depth"),
        "model_snapshot_commit": frozen.get("model_snapshot_commit"),
        "model_snapshot_sha256": frozen.get("model_snapshot_sha256"),
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
        "H1_RR_reranked_hybrid": _evaluate_h1_rr,
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


def _file_matches_hash(path: Path, expected: str) -> bool:
    """Check if file matches expected SHA-256 (supports raw bytes and LF-normalized)."""
    if not path.is_file():
        return False
    try:
        raw = path.read_bytes()
    except OSError:
        return False
    h1 = hashlib.sha256(raw).hexdigest()
    h2 = hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()
    if len(expected) <= 16:
        return h1.startswith(expected) or h2.startswith(expected)
    return h1 == expected or h2 == expected


def verify_claim_provenance(root: Path, claim_name: str, data: dict[str, Any]) -> tuple[bool, str | None]:
    """Verify protocol, corpus, and measured-source hashes for an evaluated claim."""
    frozen = _require_mapping(data, "frozen")
    if frozen is None:
        return True, None

    # Protocol & corpus checks
    if claim_name in ("H1_retrieval_fusion", "H1_RR_reranked_hybrid"):
        corpus_path = root / "benchmarks" / "beir" / "corpus.jsonl"
        qrels_path = root / "benchmarks" / "beir" / "qrels.jsonl"
        config_path = root / "benchmarks" / "beir" / "config.json"

        if "corpus_sha256" in frozen and not _file_matches_hash(corpus_path, frozen["corpus_sha256"]):
            return False, "corpus_hash_mismatch:corpus.jsonl"
        if "qrels_sha256" in frozen and not _file_matches_hash(qrels_path, frozen["qrels_sha256"]):
            return False, "corpus_hash_mismatch:qrels.jsonl"
        if "config_sha256" in frozen and not _file_matches_hash(config_path, frozen["config_sha256"]):
            return False, "protocol_hash_mismatch:config.json"

        if claim_name == "H1_RR_reranked_hybrid":
            rev_cfg = root / "benchmarks" / "beir" / "rerank_revision" / "config.json"
            if "revision_config_sha256" in frozen and not _file_matches_hash(rev_cfg, frozen["revision_config_sha256"]):
                return False, "protocol_hash_mismatch:revision_config.json"

        # Measured-source identity check for retrieval implementations
        retrieval_results = root / "benchmarks" / "retrieval" / "results.json"
        if retrieval_results.is_file():
            try:
                ret_data = json.loads(retrieval_results.read_text(encoding="utf-8"))
                frozen_sources = ret_data.get("frozen_sources", {})
                source_paths = {
                    "vector_store.py": "verifyci/contracts/vector_store.py",
                    "dense.py": "verifyci/retrieval/dense.py",
                    "sparse.py": "verifyci/retrieval/sparse.py",
                    "fusion.py": "verifyci/retrieval/fusion.py",
                }
                for name, exp_h in frozen_sources.items():
                    rel_src = source_paths.get(name)
                    if rel_src and not _file_matches_hash(root / rel_src, exp_h):
                        return False, f"source_hash_mismatch:{name}"
            except Exception:
                return False, "measured_source_read_error"

    elif claim_name == "patch_corpus_verifier":
        cases_path = root / "benchmarks" / "patch_corpus" / "cases.jsonl"
        if "cases_sha256" in frozen and not _file_matches_hash(cases_path, frozen["cases_sha256"]):
            return False, "corpus_hash_mismatch:cases.jsonl"

    elif claim_name == "blast_radius_bounds":
        cases_path = root / "benchmarks" / "blast_corpus" / "cases.jsonl"
        if "cases_sha256" in frozen and not _file_matches_hash(cases_path, frozen["cases_sha256"]):
            return False, "corpus_hash_mismatch:cases.jsonl"

    # Explicit frozen_sources in the claim artifact itself
    if "frozen_sources" in data and isinstance(data["frozen_sources"], dict):
        for src_name, exp_h in data["frozen_sources"].items():
            candidate = root / src_name
            if not candidate.is_file():
                candidate = root / "verifyci" / src_name
            if not _file_matches_hash(candidate, exp_h):
                return False, f"source_hash_mismatch:{src_name}"

    return True, None


def evaluate_claims(
    root: Path,
    clean_worktree: bool | None = None,
    allow_dirty: bool = False,
    verify_provenance: bool = True,
) -> dict[str, Any]:
    """Evaluate every canonical benchmark claim under ``root``.

    Provenance gate:
    1. Source state must be clean or explicitly approved (``allow_dirty=True``).
       If ``clean_worktree is False`` and not ``allow_dirty``, uncommitted source drift
       forces ``overall_status`` to ``UNESTABLISHED`` and downgrades established
       claims to ``PROVENANCE_MISMATCH``.
    2. Protocol and corpus hashes must match the recorded frozen hashes.
    3. Measured-source identity must match the frozen implementation hashes.
    """
    claims: dict[str, dict[str, Any]] = {}
    missing_benchmarks: list[str] = []
    provenance_failures: list[dict[str, str]] = []

    tree_is_clean_or_approved = (clean_worktree is not False) or allow_dirty

    for claim_name, relative_path in CLAIM_RESULT_PATHS.items():
        loaded = load_evidence(root / relative_path)
        result = evaluate_claim(claim_name, loaded)

        if loaded.ok and loaded.data is not None and verify_provenance:
            prov_ok, prov_err = verify_claim_provenance(root, claim_name, loaded.data)
            if not prov_ok:
                provenance_failures.append({"claim": claim_name, "error": prov_err or "provenance_mismatch"})
                if result.get("status") == "ESTABLISHED":
                    result = {**result, "status": "PROVENANCE_MISMATCH", "provenance_error": prov_err}
                else:
                    result = {**result, "provenance_error": prov_err}

        if not tree_is_clean_or_approved and result.get("status") == "ESTABLISHED":
            result = {**result, "status": "PROVENANCE_MISMATCH", "provenance_error": "dirty_worktree"}

        claims[claim_name] = result
        if result.get("status") == "MISSING":
            missing_benchmarks.append(claim_name)

    statuses = [claim["status"] for claim in claims.values()]
    all_established = bool(statuses) and all(s == "ESTABLISHED" for s in statuses)
    provenance_verified = tree_is_clean_or_approved and not provenance_failures

    overall = "ESTABLISHED" if (all_established and provenance_verified) else "UNESTABLISHED"

    return {
        "overall_status": overall,
        "claims": claims,
        "missing_benchmarks": missing_benchmarks,
        "provenance_verified": provenance_verified,
        "provenance_failures": provenance_failures,
    }

