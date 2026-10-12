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


REQUIRED_FROZEN_FIELDS: dict[str, tuple[str, ...]] = {
    "H1_retrieval_fusion": ("corpus_sha256", "qrels_sha256", "config_sha256"),
    "H1_RR_reranked_hybrid": (
        "corpus_sha256",
        "qrels_sha256",
        "config_sha256",
        "revision_config_sha256",
        "model_snapshot_sha256",
    ),
    "patch_corpus_verifier": ("cases_sha256",),
    "blast_radius_bounds": ("cases_sha256",),
}

TRUSTED_RESULT_HASHES: dict[str, str] = {
    "H1_retrieval_fusion": "9a14540ce93d74704095f43a36daf64cfcfa22dee9c78be49c94494071dd7553",
    "H1_RR_reranked_hybrid": "1c91144113e06ca8cc926eebb273b057c350176109e0f9789df6e982ceb7d701",
    "patch_corpus_verifier": "391e299ab29d4e1c826a15e9b42a04bc49b727430d9f2dbd6e8144e615a1fe5f",
    "blast_radius_bounds": "6df49c637aca2f1a2e8b60b3a0873338a55f69c115f3d0b1646b7287ac06972f",
    "retrieval_manifest": "41ebe364ba3732e71a285e638c7322da2cfa075bd8fb4bba8d88b03d352cad13",
}

MANDATORY_RETRIEVAL_SOURCES: dict[str, str] = {
    "vector_store.py": "verifyci/contracts/vector_store.py",
    "dense.py": "verifyci/retrieval/dense.py",
    "sparse.py": "verifyci/retrieval/sparse.py",
    "fusion.py": "verifyci/retrieval/fusion.py",
}

PINNED_RETRIEVAL_SOURCE_HASHES: dict[str, str] = {
    "vector_store.py": "f0d31cbc9594be0233950d4924cc3aac48f075757f7059921be6d85ea74483e9",
    "dense.py": "995fe2ab2f044bb8fec526c480cbf7ccc1466bc3ebb83c2401a16f3ac56a6d8b",
    "sparse.py": "d03e71ff682cd367092d7abbc85b6e6ab225eca788dcc85901c5718af34b8ee3",
    "fusion.py": "a212a8d220d6a5e283a0fad10973897214cf3a9653f66bb30344b56d18819084",
}

TRUSTED_RETRIEVAL_MANIFEST_HASH = TRUSTED_RESULT_HASHES["retrieval_manifest"]


def _evaluate_patch(data: dict[str, Any]) -> dict[str, Any]:
    verdicts = data.get("verdicts")
    if isinstance(verdicts, list) and verdicts:
        # Recompute aggregate metrics from per-case ground-truth records
        correct = [t for t in verdicts if isinstance(t, dict) and t.get("ground_truth") == "correct"]
        wrong = [t for t in verdicts if isinstance(t, dict) and t.get("ground_truth") == "wrong"]
        det = [
            t
            for t in wrong
            if t.get("category") in ("forbid_call", "forbid_import", "secret", "fabricated_removal")
        ]
        sem = [t for t in wrong if t.get("category") == "semantic"]

        agreement = (
            sum(1 for t in verdicts if isinstance(t, dict) and t.get("status") == t.get("expected")) / len(verdicts)
        )
        catch_rate = (sum(1 for t in det if t.get("status") == "FAIL") / len(det)) if det else 0.0
        false_accept_rate = (sum(1 for t in sem if t.get("status") == "PASS") / len(sem)) if sem else 0.0
        n_correct = len(correct)
        n_wrong = len(wrong)
        agreement = round(agreement, 4)
        catch_rate = round(catch_rate, 4)
        false_accept_rate = round(false_accept_rate, 4)
    else:
        metrics = _require_mapping(data, "metrics")
        if metrics is None:
            return _missing_claim("missing_required_sections")

        agreement = _require_number(metrics, "overall_agreement")
        catch_rate = _require_number(metrics, "deterministic_catch_rate")
        false_accept_rate = _require_number(metrics, "semantic_false_accept_rate")
        if agreement is None or catch_rate is None or false_accept_rate is None:
            return _missing_claim("missing_required_metrics")
        n_correct = metrics.get("n_correct")
        n_wrong = metrics.get("n_wrong")

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
        "n_correct": n_correct,
        "n_wrong": n_wrong,
        "recomputed_from_cases": bool(verdicts and isinstance(verdicts, list)),
    }


def _evaluate_blast(data: dict[str, Any]) -> dict[str, Any]:
    cases = data.get("cases")
    if isinstance(cases, list) and cases:
        # Recompute coverage metrics directly by deriving each case's recall
        # from underlying expected and detected entity sets:
        # Recall = |Expected & Detected| / |Expected|
        exp_cases: list[tuple[float, str | None]] = []
        for r in cases:
            if not isinstance(r, dict):
                return _missing_claim("malformed_case_record:expected_dict")
            expected = r.get("expected")
            detected = r.get("detected")
            if not isinstance(expected, list) or not isinstance(detected, list):
                return _missing_claim("malformed_case_record:expected_or_detected_not_list")
            if not all(isinstance(x, str) and x for x in expected):
                return _missing_claim("malformed_case_record:invalid_expected_entity_element")
            if not all(isinstance(x, str) and x for x in detected):
                return _missing_claim("malformed_case_record:invalid_detected_entity_element")
            # For cases with non-empty expected sets, compute derived recall directly
            if expected:
                exp_set = set(expected)
                det_set = set(detected)
                case_recall = len(exp_set & det_set) / len(exp_set)
                exp_cases.append((case_recall, r.get("mode")))

        if not exp_cases:
            return _missing_claim("missing_expected_cases")

        cov_all = sum(rec for rec, _ in exp_cases) / len(exp_cases)
        seeded = [rec for rec, mode in exp_cases if mode == "seeded"]
        cov_seeded = (sum(seeded) / len(seeded)) if seeded else 0.0
        cov_all = round(cov_all, 4)
        cov_seeded = round(cov_seeded, 4)
    else:
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
        "recomputed_from_cases": bool(cases and isinstance(cases, list)),
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
    """Check if file matches expected SHA-256 (supports raw bytes, LF-normalized, and CRLF-normalized)."""
    if not isinstance(expected, str) or len(expected) != 64:
        return False
    if not path.is_file():
        return False
    try:
        raw = path.read_bytes()
    except OSError:
        return False
    h1 = hashlib.sha256(raw).hexdigest()
    if h1 == expected:
        return True
    lf_raw = raw.replace(b"\r\n", b"\n")
    h2 = hashlib.sha256(lf_raw).hexdigest()
    if h2 == expected:
        return True
    crlf_raw = lf_raw.replace(b"\n", b"\r\n")
    h3 = hashlib.sha256(crlf_raw).hexdigest()
    return h3 == expected


def verify_claim_provenance(
    root: Path,
    claim_name: str,
    data: dict[str, Any],
    artifact_path: Path | None = None,
    bind_result_artifact: bool = True,
) -> tuple[bool, str | None]:
    """Verify protocol, corpus, measured-source, and result artifact hashes for a claim.

    Fail-closed:
    - Missing frozen metadata section -> fails.
    - Missing any required frozen field for the claim type -> fails.
    - Missing benchmark data file or implementation source file -> fails.
    - Hash mismatch -> fails.
    - Pinned result artifact tampering -> fails.
    """
    frozen = _require_mapping(data, "frozen")
    if frozen is None:
        return False, f"missing_provenance:{claim_name}:no_frozen_metadata"

    required_fields = REQUIRED_FROZEN_FIELDS.get(claim_name, ())
    for field in required_fields:
        val = frozen.get(field)
        if not isinstance(val, str) or len(val) != 64:
            return False, f"missing_provenance:{claim_name}:missing_{field}"

    # Protocol & corpus checks
    if claim_name in ("H1_retrieval_fusion", "H1_RR_reranked_hybrid"):
        corpus_path = root / "benchmarks" / "beir" / "corpus.jsonl"
        qrels_path = root / "benchmarks" / "beir" / "qrels.jsonl"
        config_path = root / "benchmarks" / "beir" / "config.json"

        if not corpus_path.is_file():
            return False, "missing_file:corpus.jsonl"
        if not qrels_path.is_file():
            return False, "missing_file:qrels.jsonl"
        if not config_path.is_file():
            return False, "missing_file:config.json"

        if not _file_matches_hash(corpus_path, frozen["corpus_sha256"]):
            return False, "corpus_hash_mismatch:corpus.jsonl"
        if not _file_matches_hash(qrels_path, frozen["qrels_sha256"]):
            return False, "corpus_hash_mismatch:qrels.jsonl"
        if not _file_matches_hash(config_path, frozen["config_sha256"]):
            return False, "protocol_hash_mismatch:config.json"

        if claim_name == "H1_RR_reranked_hybrid":
            rev_cfg = root / "benchmarks" / "beir" / "rerank_revision" / "config.json"
            if not rev_cfg.is_file():
                return False, "missing_file:revision_config.json"
            if not _file_matches_hash(rev_cfg, frozen["revision_config_sha256"]):
                return False, "protocol_hash_mismatch:revision_config.json"

        # Measured-source identity check for retrieval implementations
        retrieval_results = root / "benchmarks" / "retrieval" / "results.json"
        if not retrieval_results.is_file():
            return False, "missing_file:retrieval_results.json"
        if bind_result_artifact and not _file_matches_hash(retrieval_results, TRUSTED_RETRIEVAL_MANIFEST_HASH):
            return False, "result_artifact_hash_mismatch:retrieval_results.json"
        try:
            ret_data = json.loads(retrieval_results.read_text(encoding="utf-8"))
        except Exception:
            return False, "measured_source_read_error"

        frozen_sources = ret_data.get("frozen_sources")
        if not isinstance(frozen_sources, dict):
            return False, "missing_provenance:retrieval:no_frozen_sources"

        # Mandatory source set check: reject missing, unexpected, or malformed entries
        for name, rel_src in MANDATORY_RETRIEVAL_SOURCES.items():
            if name not in frozen_sources or not isinstance(frozen_sources[name], str):
                return False, f"missing_source_manifest_entry:{name}"
            exp_h = frozen_sources[name]
            pinned_h = PINNED_RETRIEVAL_SOURCE_HASHES.get(name)
            if pinned_h and exp_h != pinned_h:
                return False, f"source_manifest_hash_altered:{name}"
            src_file = root / rel_src
            if not src_file.is_file():
                return False, f"missing_source_file:{name}"
            if not _file_matches_hash(src_file, exp_h):
                return False, f"source_hash_mismatch:{name}"

        # Reject unexpected entries in frozen_sources
        for name in frozen_sources:
            if name not in MANDATORY_RETRIEVAL_SOURCES:
                return False, f"unexpected_source_manifest_entry:{name}"

    elif claim_name == "patch_corpus_verifier":
        cases_path = root / "benchmarks" / "patch_corpus" / "cases.jsonl"
        if not cases_path.is_file():
            return False, "missing_file:cases.jsonl"
        if not _file_matches_hash(cases_path, frozen["cases_sha256"]):
            return False, "corpus_hash_mismatch:cases.jsonl"

    elif claim_name == "blast_radius_bounds":
        cases_path = root / "benchmarks" / "blast_corpus" / "cases.jsonl"
        if not cases_path.is_file():
            return False, "missing_file:cases.jsonl"
        if not _file_matches_hash(cases_path, frozen["cases_sha256"]):
            return False, "corpus_hash_mismatch:cases.jsonl"

    # Explicit frozen_sources in the claim artifact itself
    if "frozen_sources" in data and isinstance(data["frozen_sources"], dict):
        for src_name, exp_h in data["frozen_sources"].items():
            candidate = root / src_name
            if not candidate.is_file():
                candidate = root / "verifyci" / src_name
            if not candidate.is_file():
                return False, f"missing_source_file:{src_name}"
            if not _file_matches_hash(candidate, exp_h):
                return False, f"source_hash_mismatch:{src_name}"

    # Cryptographic binding of result artifact to trusted hash
    if bind_result_artifact and artifact_path is not None and artifact_path.is_file():
        trusted_hash = TRUSTED_RESULT_HASHES.get(claim_name)
        if trusted_hash and not _file_matches_hash(artifact_path, trusted_hash):
            return False, f"result_artifact_hash_mismatch:{artifact_path.name}"

    return True, None


def evaluate_claims(
    root: Path,
    clean_worktree: bool | None = None,
    allow_dirty: bool = False,
    verify_provenance: bool = True,
    bind_result_artifacts: bool = True,
) -> dict[str, Any]:
    """Evaluate every canonical benchmark claim under ``root``.

    Provenance gate (strict fail-closed):
    1. Working-tree state:
       - If ``clean_worktree is None`` (unknown): state is unverified -> overall_status
         is UNESTABLISHED and claims cannot establish (provenance_error="unknown_worktree").
       - If ``clean_worktree is False`` (dirty):
         - without ``allow_dirty=True``: uncommitted drift downgrades established claims
           to PROVENANCE_MISMATCH (provenance_error="dirty_worktree").
         - with ``allow_dirty=True``: allowed only with explicit override recorded.
       - If ``clean_worktree is True`` (clean): verified clean source state.
    2. Mandatory frozen metadata: every claim requires full set of frozen hashes.
    3. Mandatory benchmark/source files: missing files fail provenance.
    4. Hash integrity: source/corpus/protocol differences trigger PROVENANCE_MISMATCH.
    5. Artifact binding: result artifacts must match trusted provenance record.
    """
    claims: dict[str, dict[str, Any]] = {}
    missing_benchmarks: list[str] = []
    provenance_failures: list[dict[str, str]] = []

    if clean_worktree is None:
        tree_status = "unknown"
        tree_ok = False
        tree_err = "unknown_worktree"
        dirty_override = False
    elif clean_worktree is False:
        tree_status = "dirty"
        if allow_dirty:
            tree_ok = True
            tree_err = None
            dirty_override = True
        else:
            tree_ok = False
            tree_err = "dirty_worktree"
            dirty_override = False
    else:
        tree_status = "clean"
        tree_ok = True
        tree_err = None
        dirty_override = False

    for claim_name, relative_path in CLAIM_RESULT_PATHS.items():
        artifact_file = root / relative_path
        loaded = load_evidence(artifact_file)
        result = evaluate_claim(claim_name, loaded)

        if loaded.ok and loaded.data is not None and verify_provenance:
            prov_ok, prov_err = verify_claim_provenance(
                root,
                claim_name,
                loaded.data,
                artifact_path=artifact_file,
                bind_result_artifact=bind_result_artifacts,
            )
            if not prov_ok:
                provenance_failures.append({"claim": claim_name, "error": prov_err or "provenance_mismatch"})
                if result.get("status") == "ESTABLISHED":
                    result = {**result, "status": "PROVENANCE_MISMATCH", "provenance_error": prov_err}
                else:
                    result = {**result, "provenance_error": prov_err}

        if not tree_ok and result.get("status") == "ESTABLISHED":
            result = {
                **result,
                "status": "PROVENANCE_MISMATCH",
                "provenance_error": tree_err,
            }

        if dirty_override and result.get("status") == "ESTABLISHED":
            result = {**result, "dirty_override_recorded": True}

        claims[claim_name] = result
        if result.get("status") == "MISSING":
            missing_benchmarks.append(claim_name)

    statuses = [claim["status"] for claim in claims.values()]
    all_established = bool(statuses) and all(s == "ESTABLISHED" for s in statuses)
    provenance_verified = tree_ok and not provenance_failures

    overall = "ESTABLISHED" if (all_established and provenance_verified) else "UNESTABLISHED"

    return {
        "overall_status": overall,
        "claims": claims,
        "missing_benchmarks": missing_benchmarks,
        "provenance_verified": provenance_verified,
        "provenance_failures": provenance_failures,
        "worktree_status": tree_status,
        "dirty_override_recorded": dirty_override,
    }


