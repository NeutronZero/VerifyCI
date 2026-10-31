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

from verifyci.contracts.manifest import (
    CHECK_ORDER,
    CHECK_SPECS,
    TOOL_VERSION,
    manifest_hash,
)
from verifyci.evidence.canonical import canonical_json_bytes

VALIDATION_SCHEMA = "verifyci.release_validation/v1"
VALIDATION_REL_PATH = Path("evidence") / "release" / "release_validation.json"

# Public Ed25519 Authority Key (32 bytes raw, hex-encoded).
# Used strictly by the verifier to validate signatures.
# The private signing key is NEVER embedded in the repository or shipped code.
RELEASE_AUTHORITY_KEY_ID = "verifyci-release-authority-ed25519-v1"
RELEASE_AUTHORITY_PUBLIC_KEY_HEX = (
    "7926b9524e2ec893f7834b9081228da255f058709fa158d77a75d7d21a3715f7"
)

_CRITICAL_IMPLEMENTATION_FILES = (
    Path(".github/workflows/ci.yml"),
    Path(".github/workflows/release_signing.yml"),
    Path("pyproject.toml"),
    Path("uv.lock"),
    Path("verifyci/checks/security.py"),
    Path("verifyci/checks/semantic.py"),
    Path("verifyci/checks/contract.py"),
    Path("verifyci/checks/deletion.py"),
    Path("verifyci/checks/grounding.py"),
    Path("verifyci/gate/orchestrator.py"),
    Path("verifyci/gate/policy.py"),
    Path("verifyci/gate/integrity.py"),
    Path("verifyci/contracts/manifest.py"),
    Path("verifyci/contracts/promotion.py"),
    Path("verifyci/contracts/release_validation.py"),
    Path("verifyci/cli.py"),
    Path("scripts/validate_release.py"),
    Path("scripts/standalone_signer.py"),
    Path("tests/v3/test_security_benchmark.py"),
    Path("tests/v3/test_security_corpus.py"),
    Path("tests/v3/test_security_regressions.py"),
    Path("corpora/security/cases.jsonl"),
    Path("corpora/security/CORPUS_SPEC.md"),
    Path("corpora/security/SHA256SUMS"),
    Path("corpora/security/ORACLE_REVIEW.md"),
)


def get_verifyci_root() -> Path:
    """Return the root path of the VerifyCI repository / installation."""
    return Path(__file__).resolve().parents[2]


def get_commit_sha(repo_root: Path) -> str | None:
    """Resolve HEAD commit SHA of the repository."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            commit = proc.stdout.strip()
            if len(commit) == 40 and all(c in "0123456789abcdef" for c in commit.lower()):
                return commit.lower()
    except Exception:
        pass
    return None


def get_parent_commit(repo_root: Path, commit_sha: str) -> str | None:
    """Resolve parent commit SHA."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", f"{commit_sha}^"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            parent = proc.stdout.strip()
            if len(parent) == 40 and all(c in "0123456789abcdef" for c in parent.lower()):
                return parent.lower()
    except Exception:
        pass
    return None


def get_changed_files_between(repo_root: Path, base_commit: str, head_commit: str) -> list[str]:
    """Return list of relative file paths changed between base_commit and head_commit."""
    try:
        proc = subprocess.run(
            ["git", "diff", "--name-only", base_commit, head_commit],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            return [line.strip().replace("\\", "/") for line in proc.stdout.splitlines() if line.strip()]
    except Exception:
        pass
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


def compute_attestation_signature(digest: str, private_key_hex: str | None = None) -> str:
    """Compute Ed25519 signature over canonical attestation digest using protected private key.

    The private key must be provided via the private_key_hex argument or the
    VERIFYCI_RELEASE_SIGNING_KEY environment variable. If no private key is available,
    it fails closed.
    """
    key_hex = private_key_hex or os.environ.get("VERIFYCI_RELEASE_SIGNING_KEY")
    if not key_hex:
        raise RuntimeError(
            "Release attestation signing authority unavailable: no private key provided "
            "and VERIFYCI_RELEASE_SIGNING_KEY is unset."
        )
    key_hex = key_hex.strip()
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv_bytes = bytes.fromhex(key_hex)
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        sig = priv.sign(digest.encode("utf-8"))
        return sig.hex()
    except Exception as exc:
        raise RuntimeError(f"Failed to generate Ed25519 attestation signature: {exc}") from exc


def verify_release_validation_evidence(
    repo_root: Path | None = None,
    *,
    expected_commit: str | None = None,
    authority_public_key_hex: str | None = None,
    require_ci: bool = False,
) -> tuple[bool, str | None]:
    """Verify that trusted, non-stale release-validation evidence exists.

    Returns:
        (True, None) if validation is authoritative, verified, and unstale.
        (False, reason_detail) otherwise.
    """
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

    if record.get("schema") != VALIDATION_SCHEMA:
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

    expected_pub_hex = authority_public_key_hex or RELEASE_AUTHORITY_PUBLIC_KEY_HEX
    if attestation.get("public_key") != expected_pub_hex:
        return False, f"untrusted release attestation public key: {attestation.get('public_key')}"

    recorded_digest = attestation.get("digest")
    if not isinstance(recorded_digest, str) or not recorded_digest.startswith("sha256:"):
        return False, "malformed attestation digest in release evidence"

    # Recompute digest over the canonical measurement payload (all keys except attestation itself)
    payload_body = {k: v for k, v in record.items() if k != "attestation"}
    computed_digest = "sha256:" + hashlib.sha256(canonical_json_bytes(payload_body)).hexdigest()
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
        pub.verify(sig_bytes, recorded_digest.encode("utf-8"))
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
    required_defects = ("SEC-SECRET", "SEC-SECRET-TO-SINK", "SEC-DANGEROUS-CALL", "SEC-TAINT-TO-SINK")
    for did in required_defects:
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
            "job_id",
            "artifact_id",
            "measurement_job_completed_at",
            "artifact_created_at",
        ):
            if not provenance.get(req_field):
                return False, f"release validation provenance missing required CI field: '{req_field}'"
        if "oidc_verified" not in provenance:
            return False, "release validation provenance missing required CI field: 'oidc_verified'"
        if provenance.get("oidc_verified") is not True:
            return False, "release validation provenance requires cryptographic OIDC verification (oidc_verified must be true)"
        prov_sha = (provenance.get("commit_sha") or "").lower()
        rec_sha = (record.get("commit_sha") or "").lower()
        if prov_sha and rec_sha and prov_sha != rec_sha:
            return False, f"provenance commit_sha '{prov_sha}' does not match record commit_sha '{rec_sha}'"
    elif ci_platform != "local":
        return False, f"unrecognized ci_platform: '{ci_platform}' (must be 'github_actions' or 'local')"

    return True, None


def generate_release_validation_record(
    repo_root: Path,
    commit_sha: str,
    measurements: dict[str, Any],
    signing_key_hex: str | None = None,
) -> dict[str, Any]:
    """Generate, sign with Ed25519, and atomically write authoritative release-validation evidence."""
    payload_body = {
        "schema": VALIDATION_SCHEMA,
        "tool_version": TOOL_VERSION,
        "status": "VALIDATED",
        "stage": "final",
        "commit_sha": commit_sha.lower(),
        "manifest_hash": manifest_hash(),
        "toolchain_fingerprint": CHECK_SPECS["security"].toolchain_fingerprint,
        "toolchain_identity": {
            "python_version": platform.python_version(),
            "platform": platform.system(),
            "arch": platform.machine(),
        },
        "corpora_hashes": {
            check_id: spec.corpus_hash
            for check_id, spec in CHECK_SPECS.items()
            if spec.corpus_hash
        },
        "implementation_fingerprint": compute_implementation_fingerprint(repo_root),
        "checks_validated": list(CHECK_ORDER),
        "measurements": measurements,
    }

    # Compute canonical RFC 8785 digest and Ed25519 signature
    canonical_bytes = canonical_json_bytes(payload_body)
    digest = "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
    signature = compute_attestation_signature(digest, private_key_hex=signing_key_hex)

    record = dict(payload_body)
    record["attestation"] = {
        "issuer": "verifyci.release_pipeline",
        "algorithm": "ed25519",
        "key_id": RELEASE_AUTHORITY_KEY_ID,
        "public_key": RELEASE_AUTHORITY_PUBLIC_KEY_HEX,
        "digest": digest,
        "signature": signature,
    }

    val_file = repo_root / VALIDATION_REL_PATH
    val_file.parent.mkdir(parents=True, exist_ok=True)

    # Atomic write via temporary file
    temp_file = val_file.with_name(f"{val_file.name}.tmp.{os.getpid()}")
    try:
        temp_file.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temp_file, val_file)
    except Exception:
        if temp_file.is_file():
            temp_file.unlink(missing_ok=True)
        raise

    return record


__all__ = [
    "RELEASE_AUTHORITY_KEY_ID",
    "RELEASE_AUTHORITY_PUBLIC_KEY_HEX",
    "VALIDATION_REL_PATH",
    "VALIDATION_SCHEMA",
    "compute_attestation_signature",
    "compute_implementation_fingerprint",
    "generate_release_validation_record",
    "get_changed_files_between",
    "get_commit_sha",
    "get_parent_commit",
    "get_verifyci_root",
    "verify_release_validation_evidence",
]
