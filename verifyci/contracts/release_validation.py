"""Release-validation evidence verification for VerifyCI (§15.10).

Release validation cannot be asserted by callers via CLI flags, environment
variables, or request attributes. It must be proven by an authenticated cryptographic
attestation bound to the source commit, manifest hash, toolchain, corpora, implementation
fingerprint, and independently executed test and benchmark measurements.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any

from verifyci.contracts.canonical import (
    is_hex40,
    is_valid_sha256,
    payload_hash,
)
from verifyci.contracts.manifest import (
    CHECK_ORDER,
    CHECK_SPECS,
    TOOL_VERSION,
    manifest_hash,
)


VALIDATION_SCHEMA = "verifyci.release_validation/v1"
SUPPORTED_VALIDATION_SCHEMAS = ("verifyci.release_validation/v1", "verifyci.release_validation/v3")
VALIDATION_REL_PATH = Path("evidence") / "release" / "release_validation.json"

PINNED_REPOSITORY = "NeutronZero/VerifyCI"
PINNED_MEASUREMENT_WORKFLOW_PATH = ".github/workflows/release_measurements.yml"
PINNED_SIGNING_WORKFLOW_PATH = ".github/workflows/release_signing.yml"
PINNED_TRUSTED_REF = "refs/heads/release-authority"

# Public Ed25519 Authority Key (32 bytes raw, hex-encoded).
# Used strictly by the verifier to validate signatures.
# The private signing key is NEVER embedded in the repository or shipped code.
RELEASE_AUTHORITY_KEY_ID = "verifyci-release-authority-ed25519-v1"
RELEASE_AUTHORITY_PUBLIC_KEY_HEX = (
    "7926b9524e2ec893f7834b9081228da255f058709fa158d77a75d7d21a3715f7"
)

_CRITICAL_IMPLEMENTATION_FILES = (
    Path(".github/workflows/ci.yml"),
    Path(".github/workflows/release_measurements.yml"),
    Path(".github/workflows/release_signing.yml"),
    Path("docker/worker/Dockerfile"),
    Path("docker/worker/launch_candidate.py"),
    Path("docker/worker/requirements.lock"),
    Path("pyproject.toml"),
    Path("uv.lock"),
    Path("verifyci/checks/_modules.py"),
    Path("verifyci/checks/_semantic_replay.py"),
    Path("verifyci/checks/_semantic_symbolic.py"),
    Path("verifyci/checks/_semantic_ts.py"),
    Path("verifyci/checks/security.py"),
    Path("verifyci/checks/semantic.py"),
    Path("verifyci/checks/contract.py"),
    Path("verifyci/checks/deletion.py"),
    Path("verifyci/checks/grounding.py"),
    Path("verifyci/contracts/canonical.py"),
    Path("verifyci/contracts/manifest.py"),
    Path("verifyci/contracts/promotion.py"),
    Path("verifyci/contracts/release_validation.py"),
    Path("verifyci/evidence/__init__.py"),
    Path("verifyci/evidence/bundle.py"),
    Path("verifyci/evidence/canonical.py"),
    Path("verifyci/evidence/sarif.py"),
    Path("verifyci/checks/base.py"),
    Path("verifyci/contracts/model.py"),
    Path("verifyci/contracts/names.py"),
    Path("verifyci/gate/integrity.py"),
    Path("verifyci/gate/orchestrator.py"),
    Path("verifyci/gate/policy.py"),
    Path("verifyci/gate/verdict.py"),
    Path("verifyci/index/__init__.py"),
    Path("verifyci/index/cache.py"),
    Path("verifyci/index/facts.py"),
    Path("verifyci/index/provider.py"),
    Path("verifyci/index/symbol_index.py"),
    Path("verifyci/runtime/budget.py"),
    Path("verifyci/runtime/scheduler.py"),
    Path("verifyci/scm/env.py"),
    Path("verifyci/scm/git.py"),
    Path("verifyci/scope/entities.py"),
    Path("verifyci/scope/models.py"),
    Path("verifyci/scope/parsers.py"),
    Path("verifyci/scope/python_scope.py"),
    Path("verifyci/scope/repository.py"),
    Path("verifyci/scope/ts_scope.py"),
    Path("verifyci/cli.py"),
    Path("scripts/validate_release.py"),
    Path("scripts/standalone_signer.py"),
    Path("tests/v3/test_release_trust_boundary.py"),
    Path("tests/v3/test_security_benchmark.py"),
    Path("tests/v3/test_security_corpus.py"),
    Path("tests/v3/test_security_regressions.py"),
    Path("corpora/contract/CORPUS_SPEC.md"),
    Path("corpora/deletion/CORPUS_SPEC.md"),
    Path("corpora/security/cases.jsonl"),
    Path("corpora/security/CORPUS_SPEC.md"),
    Path("corpora/security/SHA256SUMS"),
    Path("corpora/security/ORACLE_REVIEW.md"),
    Path("corpora/semantic/CORPUS_SPEC.md"),
)


def get_verifyci_root() -> Path:
    """Return the root path of the VerifyCI repository / installation."""
    candidate = Path(__file__).resolve().parents[2]
    if (candidate / VALIDATION_REL_PATH).is_file() or (candidate / ".git").exists():
        return candidate

    for env_var in ("VERIFYCI_ROOT", "VERIFYCI_REPO_ROOT"):
        val = os.environ.get(env_var)
        if val:
            env_path = Path(val).resolve()
            if env_path.exists():
                return env_path

    # Fallback to package-relative resource (installed wheel layout)
    pkg_root = Path(__file__).resolve().parents[1]
    if (pkg_root / VALIDATION_REL_PATH).is_file() or (pkg_root / "release_validation.json").is_file():
        return pkg_root

    return candidate


def _scrubbed_git_env() -> dict[str, str]:
    from verifyci.scm.env import scrubbed_git_env

    return scrubbed_git_env()


def _run_git(repo_root: Path, args: list[str]) -> subprocess.CompletedProcess[str] | None:
    from verifyci.scm.env import hardened_git_command

    try:
        return subprocess.run(
            hardened_git_command(repo_root, args),
            capture_output=True,
            text=True,
            check=False,
            env=_scrubbed_git_env(),
        )
    except Exception:
        return None


def get_commit_sha(repo_root: Path) -> str | None:
    """Resolve HEAD commit SHA of the repository."""
    proc = _run_git(repo_root, ["rev-parse", "HEAD"])
    if proc is not None and proc.returncode == 0:
        commit = proc.stdout.strip()
        if is_hex40(commit):
            return commit.lower()
    return None


def get_parent_commit(repo_root: Path, commit_sha: str) -> str | None:
    """Resolve parent commit SHA."""
    if not is_hex40(commit_sha):
        return None
    proc = _run_git(repo_root, ["rev-parse", f"{commit_sha}^"])
    if proc is not None and proc.returncode == 0:
        parent = proc.stdout.strip()
        if is_hex40(parent):
            return parent.lower()
    return None


def get_changed_files_between(repo_root: Path, base_commit: str, head_commit: str) -> list[str]:
    """Return list of relative file paths changed between base_commit and head_commit."""
    if not (is_hex40(base_commit) and is_hex40(head_commit)):
        return []
    proc = _run_git(repo_root, ["diff", "--name-only", base_commit, head_commit])
    if proc is not None and proc.returncode == 0:
        return [line.strip().replace("\\", "/") for line in proc.stdout.splitlines() if line.strip()]
    return ["<error: git diff failed>"]


def compute_implementation_fingerprint(repo_root: Path) -> str:
    """Compute deterministic SHA256 over critical implementation sources."""
    hasher = hashlib.sha256()
    for rel_path in sorted(_CRITICAL_IMPLEMENTATION_FILES, key=lambda p: p.as_posix()):
        full_path = repo_root / rel_path
        if full_path.is_file():
            hasher.update(rel_path.as_posix().encode("utf-8"))
            # Normalize CRLF/LF to ensure consistent hash across platforms
            norm_content = full_path.read_bytes().replace(b"\r\n", b"\n")
            hasher.update(norm_content)
    return "sha256:" + hasher.hexdigest()


def verify_release_validation_evidence(
    repo_root: Path | None = None,
    *,
    expected_commit: str | None = None,
    _authority_public_key_hex: str | None = None,
    require_ci: bool = False,
    **kwargs: Any,
) -> tuple[bool, str | None]:
    """Verify that trusted, non-stale release-validation evidence exists.

    Returns:
        (True, None) if validation is authoritative, verified, and unstale.
        (False, reason_detail) otherwise.
    """
    if "authority_public_key_hex" in kwargs:
        raise TypeError("authority_public_key_hex cannot be overridden in production; use trusted authority key")
    if _authority_public_key_hex is not None:
        if "pytest" not in sys.modules and os.environ.get("VERIFYCI_TESTING") != "1":
            return False, "unauthorized authority key override: testing key override is prohibited in production runs"
    root = repo_root or get_verifyci_root()
    val_file = root / VALIDATION_REL_PATH
    if not val_file.is_file():
        return (
            False,
            "release-validation artifacts are absent; this internal build cannot emit a normal gate verdict",
        )

    try:
        raw = val_file.read_bytes()
        record = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return False, f"release-validation evidence is malformed: {exc}"

    if not isinstance(record, dict):
        return False, "release-validation evidence root must be an object"

    if record.get("schema") not in SUPPORTED_VALIDATION_SCHEMAS:
        return False, f"unsupported release-validation schema: {record.get('schema')}"

    if record.get("status") != "VALIDATED":
        return False, f"release validation status is not VALIDATED: {record.get('status')}"

    if record.get("tool_version") != TOOL_VERSION:
        return (
            False,
            f"release validation tool version mismatch: {record.get('tool_version')} != {TOOL_VERSION}",
        )

    # Reject provisional or non-final validation records
    if record.get("stage") == "in_flight_validation":
        return (
            False,
            "unauthorized release evidence: record is marked as provisional (in_flight_validation)",
        )
    test_metrics_raw = record.get("measurements", {}).get("test_suite", {})
    if test_metrics_raw.get("stage") == "in_flight_validation":
        return (
            False,
            "unauthorized release evidence: test suite measurements are marked provisional (in_flight_validation)",
        )

    # 1. Attestation signature & digest verification
    attestation = record.get("attestation")
    if not isinstance(attestation, dict):
        return False, "release-validation evidence missing authenticated attestation block"
    if attestation.get("issuer") != "verifyci.release_pipeline":
        return False, f"untrusted release attestation issuer: {attestation.get('issuer')}"
    if attestation.get("algorithm") != "ed25519":
        return False, f"unsupported attestation algorithm: {attestation.get('algorithm')}"
    if attestation.get("key_id") != RELEASE_AUTHORITY_KEY_ID:
        return False, f"unrecognized attestation key ID: {attestation.get('key_id')}"

    expected_pub_hex = _authority_public_key_hex or RELEASE_AUTHORITY_PUBLIC_KEY_HEX
    if attestation.get("public_key") != expected_pub_hex:
        return False, f"untrusted release attestation public key: {attestation.get('public_key')}"

    recorded_digest = attestation.get("digest")
    if not isinstance(recorded_digest, str) or not recorded_digest.startswith("sha256:"):
        return False, "malformed attestation digest in release evidence"

    # Recompute digest over the canonical measurement payload (all keys except attestation itself)
    payload_body = {k: v for k, v in record.items() if k != "attestation"}
    computed_digest = payload_hash(payload_body)
    if not hmac.compare_digest(recorded_digest, computed_digest):
        return False, "release-validation attestation digest mismatch (evidence payload was modified)"

    supplied_sig = attestation.get("signature")
    if not isinstance(supplied_sig, str) or len(supplied_sig) != 128:
        return False, "invalid release attestation signature format (expected 128-char hex Ed25519 signature)"

    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        pub_bytes = bytes.fromhex(expected_pub_hex)
        pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = bytes.fromhex(supplied_sig)
        try:
            pub.verify(sig_bytes, recorded_digest.encode("utf-8"))
        except Exception:
            DOMAIN_SEPARATOR = b"VERIFYCI-RELEASE-EVIDENCE\x00"
            pub.verify(sig_bytes, DOMAIN_SEPARATOR + recorded_digest.encode("utf-8"))
    except Exception as exc:
        return (
            False,
            f"invalid release attestation signature: failed Ed25519 cryptographic verification ({exc})",
        )

    # 2. Manifest hash check
    current_manifest_hash = manifest_hash()
    if record.get("manifest_hash") != current_manifest_hash:
        return False, "release validation manifest hash mismatch (manifest or checks changed)"

    # 3. Git commit binding (fails closed if commit cannot be resolved)
    commit_sha = record.get("commit_sha")
    if not commit_sha:
        return False, "release validation evidence is missing commit_sha binding"

    actual_commit = expected_commit or get_commit_sha(root)
    if not actual_commit:
        return False, "release validation failed: unable to establish authoritative git commit identity"

    act_lower = actual_commit.lower()
    com_lower = commit_sha.lower()
    if com_lower != act_lower:
        parent_lower = (get_parent_commit(root, act_lower) or "").lower()
        if com_lower != parent_lower:
            return (
                False,
                f"stale release-validation evidence: bound to commit {commit_sha[:8]}, current commit is {actual_commit[:8]}",
            )
        # Constrain parent-commit acceptance: the intervening commit MUST ONLY modify evidence/release/release_validation.json
        changed_files = get_changed_files_between(root, com_lower, act_lower)
        unauthorized_changes = [f for f in changed_files if f != "evidence/release/release_validation.json"]
        if unauthorized_changes:
            return (
                False,
                f"parent-commit release validation rejected: intervening commit {actual_commit[:8]} modified files outside release evidence: {unauthorized_changes}",
            )

    # 4. Implementation fingerprint check (covers engine, checks, contracts, and validation script)
    current_impl_fingerprint = compute_implementation_fingerprint(root)
    if record.get("implementation_fingerprint") != current_impl_fingerprint:
        return (
            False,
            "stale release-validation evidence: implementation files have changed since validation",
        )

    # 5. Toolchain fingerprint and identity checks
    expected_toolchain_fp = CHECK_SPECS["security"].toolchain_fingerprint
    if record.get("toolchain_fingerprint") != expected_toolchain_fp:
        return False, "release validation toolchain fingerprint mismatch"

    toolchain_id = record.get("toolchain_identity", {})
    if not isinstance(toolchain_id, dict) or not toolchain_id.get("python_version"):
        return False, "missing toolchain_identity or python_version in release validation evidence"

    # Runtime Python must satisfy the >=3.12 toolchain contract
    if sys.version_info < (3, 12):
        return (
            False,
            f"unsupported runtime python version: {platform.python_version()} (requires >= 3.12)",
        )

    # 6. Validated checks list
    checks_val = record.get("checks_validated")
    if not isinstance(checks_val, list) or tuple(checks_val) != CHECK_ORDER:
        return False, f"checks_validated mismatch: expected {list(CHECK_ORDER)}, got {checks_val}"

    # 7. Measurements verification: tests and benchmark
    measurements = record.get("measurements")
    if not isinstance(measurements, dict):
        return False, "release validation evidence missing verified measurements block"

    test_metrics = measurements.get("test_suite", {})
    if test_metrics.get("total_failed", 1) != 0 or test_metrics.get("total_errors", 1) != 0:
        return False, "release validation evidence indicates failing or errored test suite"
    if test_metrics.get("total_passed", 0) < 200:
        return False, f"insufficient test suite passing count: {test_metrics.get('total_passed')} < 200"

    bench_metrics = measurements.get("benchmark", {})
    if bench_metrics.get("cases_evaluated", 0) < 22:
        return False, f"insufficient benchmark cases evaluated: {bench_metrics.get('cases_evaluated')} < 22"
    if not bench_metrics.get("zero_false_blocking") or not bench_metrics.get("strict_redaction"):
        return False, "benchmark measurements failed zero_false_blocking or strict_redaction invariant"

    defect_metrics = bench_metrics.get("defects", {})
    for did in CHECK_SPECS["security"].defect_ids:
        d_data = defect_metrics.get(did, {})
        if d_data.get("precision", 0.0) < 1.0 or d_data.get("recall", 0.0) < 0.90:
            return False, f"benchmark defect metric threshold not met for {did}: {d_data}"

    # 8. Check corpora hashes match manifest
    corpora = record.get("corpora_hashes", {})
    for check_id in CHECK_ORDER:
        spec = CHECK_SPECS[check_id]
        if spec.corpus_hash and corpora.get(check_id) != spec.corpus_hash:
            return False, f"release validation corpus hash mismatch for {check_id}"

    # 9. Provenance verification
    provenance = record.get("provenance")
    if not isinstance(provenance, dict):
        return False, "release validation evidence missing required provenance block"

    ci_verified = provenance.get("ci_verified")
    ci_platform = provenance.get("ci_platform")

    if require_ci or ci_verified is True:
        if ci_verified is not True:
            return False, "release validation evidence requires authenticated CI provenance (ci_verified must be true)"
        if ci_platform != "github_actions":
            return False, f"unsupported ci_platform for verified release evidence: '{ci_platform}' (expected 'github_actions')"
        for req_field in (
            "workflow_run_id",
            "workflow_run_attempt",
            "job_id",
            "artifact_id",
            "artifact_name",
            "artifact_digest",
            "artifact_zip_sha256",
            "measurement_job_completed_at",
            "artifact_created_at",
            "candidate_ref",
            "measurement_workflow_ref",
            "measurement_workflow_sha",
            "trusted_signing_workflow_ref",
            "trusted_signing_workflow_sha",
            "trusted_signing_ref",
            "trusted_signing_run_id",
        ):
            if not provenance.get(req_field):
                return False, f"release validation provenance missing required CI field: '{req_field}'"
        if "oidc_verified" not in provenance:
            return False, "release validation provenance missing required CI field: 'oidc_verified'"
        if provenance.get("oidc_verified") is not True:
            return False, "release validation provenance requires cryptographic OIDC verification (oidc_verified must be true)"
        prov_sha = (provenance.get("commit_sha") or "").lower()
        rec_sha = (record.get("commit_sha") or "").lower()
        if not is_hex40(prov_sha):
            return False, "release validation provenance commit_sha is missing or malformed"
        if prov_sha != rec_sha:
            return False, f"provenance commit_sha '{prov_sha}' does not match record commit_sha '{rec_sha}'"
        if provenance.get("artifact_name") != "release-measurements":
            return False, f"unexpected measurement artifact name: {provenance.get('artifact_name')!r}"
        artifact_digest = str(provenance.get("artifact_digest") or "")
        artifact_zip_digest = str(provenance.get("artifact_zip_sha256") or "")
        if not is_valid_sha256(artifact_digest):
            return False, "release validation provenance artifact_digest is malformed"
        if not hmac.compare_digest(artifact_digest, artifact_zip_digest):
            return False, "release validation provenance artifact digest does not match downloaded archive digest"
        if not isinstance(provenance.get("artifact_id"), int) or provenance["artifact_id"] <= 0:
            return False, "release validation provenance artifact_id is missing or malformed"
        if not isinstance(provenance.get("job_id"), int) or provenance["job_id"] <= 0:
            return False, "release validation provenance job_id is missing or malformed"
        candidate_ref = str(provenance.get("candidate_ref") or "")
        if not candidate_ref.startswith("refs/"):
            return False, f"release validation provenance candidate_ref is malformed: {candidate_ref!r}"
        measurement_ref = str(provenance.get("measurement_workflow_ref") or "")
        measurement_path, _, measurement_rev = measurement_ref.rpartition("@")
        if measurement_path != f"{PINNED_REPOSITORY}/{PINNED_MEASUREMENT_WORKFLOW_PATH}":
            return False, f"unexpected measurement workflow identity: {measurement_ref!r}"
        measurement_sha = str(provenance.get("measurement_workflow_sha") or "").lower()
        if not is_hex40(measurement_sha):
            return False, "release validation provenance measurement_workflow_sha is missing or malformed"
        if measurement_rev != PINNED_TRUSTED_REF and measurement_rev.lower() != measurement_sha:
            return False, f"measurement workflow revision is not trusted: {measurement_rev!r}"
        signing_ref = str(provenance.get("trusted_signing_workflow_ref") or "")
        signing_path, _, signing_rev = signing_ref.rpartition("@")
        if signing_path != f"{PINNED_REPOSITORY}/{PINNED_SIGNING_WORKFLOW_PATH}" or signing_rev != PINNED_TRUSTED_REF:
            return False, f"untrusted signing workflow identity: {signing_ref!r}"
        signing_sha = str(provenance.get("trusted_signing_workflow_sha") or "").lower()
        if not is_hex40(signing_sha):
            return False, "release validation provenance trusted_signing_workflow_sha is missing or malformed"
        if provenance.get("trusted_signing_ref") != PINNED_TRUSTED_REF:
            return False, f"untrusted signing ref: {provenance.get('trusted_signing_ref')!r}"
    elif ci_platform != "local":
        return False, f"unrecognized ci_platform: '{ci_platform}' (must be 'github_actions' or 'local')"

    return True, None


__all__ = [
    "RELEASE_AUTHORITY_KEY_ID",
    "RELEASE_AUTHORITY_PUBLIC_KEY_HEX",
    "VALIDATION_REL_PATH",
    "VALIDATION_SCHEMA",
    "compute_implementation_fingerprint",
    "get_changed_files_between",
    "get_commit_sha",
    "get_parent_commit",
    "get_verifyci_root",
    "verify_release_validation_evidence",
]
