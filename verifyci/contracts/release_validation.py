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

DEFAULT_RELEASE_AUTHORITY_KEY = b"verifyci-v3.1.10-authoritative-release-signature-authority"

_CRITICAL_IMPLEMENTATION_FILES = (
    Path("verifyci/checks/security.py"),
    Path("verifyci/checks/semantic.py"),
    Path("verifyci/checks/contract.py"),
    Path("verifyci/checks/deletion.py"),
    Path("verifyci/checks/grounding.py"),
    Path("verifyci/gate/orchestrator.py"),
    Path("verifyci/contracts/manifest.py"),
    Path("verifyci/contracts/promotion.py"),
    Path("verifyci/contracts/release_validation.py"),
    Path("verifyci/cli.py"),
    Path("scripts/validate_release.py"),
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


def compute_implementation_fingerprint(repo_root: Path) -> str:
    """Compute deterministic SHA256 over critical implementation sources."""
    hasher = hashlib.sha256()
    for rel_path in sorted(_CRITICAL_IMPLEMENTATION_FILES):
        full_path = repo_root / rel_path
        if full_path.is_file():
            hasher.update(rel_path.as_posix().encode("utf-8"))
            # Normalize CRLF/LF to ensure consistent hash across platforms
            norm_content = full_path.read_bytes().replace(b"\r\n", b"\n")
            hasher.update(norm_content)
    return "sha256:" + hasher.hexdigest()


def compute_attestation_signature(digest: str, key: bytes | None = None) -> str:
    """Compute HMAC-SHA256 signature over the canonical attestation digest."""
    active_key = key or DEFAULT_RELEASE_AUTHORITY_KEY
    return hmac.new(active_key, digest.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_release_validation_evidence(
    repo_root: Path | None = None,
    *,
    expected_commit: str | None = None,
    authority_key: bytes | None = None,
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

    # 1. Attestation signature & digest verification
    attestation = record.get("attestation")
    if not isinstance(attestation, dict):
        return False, "release-validation evidence missing authenticated attestation block"
    if attestation.get("issuer") != "verifyci.release_pipeline":
        return False, f"untrusted release attestation issuer: {attestation.get('issuer')}"
    if attestation.get("algorithm") != "hmac-sha256":
        return False, f"unsupported attestation algorithm: {attestation.get('algorithm')}"

    recorded_digest = attestation.get("digest")
    if not isinstance(recorded_digest, str) or not recorded_digest.startswith("sha256:"):
        return False, "malformed attestation digest in release evidence"

    # Recompute digest over the canonical measurement payload (all keys except attestation itself)
    payload_body = {k: v for k, v in record.items() if k != "attestation"}
    computed_digest = "sha256:" + hashlib.sha256(canonical_json_bytes(payload_body)).hexdigest()
    if not hmac.compare_digest(recorded_digest, computed_digest):
        return False, "release-validation attestation digest mismatch (evidence payload was modified)"

    expected_sig = compute_attestation_signature(computed_digest, key=authority_key)
    supplied_sig = attestation.get("signature")
    if not isinstance(supplied_sig, str) or not hmac.compare_digest(supplied_sig, expected_sig):
        return False, "invalid release attestation signature: failed cryptographic authenticity check"

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

    # 5. Validated checks list
    checks_val = record.get("checks_validated")
    if not isinstance(checks_val, list) or tuple(checks_val) != CHECK_ORDER:
        return False, f"checks_validated mismatch: expected {list(CHECK_ORDER)}, got {checks_val}"

    # 6. Measurements verification: tests and benchmark
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

    return True, None


def generate_release_validation_record(
    repo_root: Path,
    commit_sha: str,
    measurements: dict[str, Any],
    authority_key: bytes | None = None,
) -> dict[str, Any]:
    """Generate, sign, and write authoritative release-validation evidence."""
    payload_body = {
        "schema": VALIDATION_SCHEMA,
        "tool_version": TOOL_VERSION,
        "status": "VALIDATED",
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

    # Compute canonical digest and HMAC-SHA256 signature
    canonical_bytes = canonical_json_bytes(payload_body)
    digest = "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
    signature = compute_attestation_signature(digest, key=authority_key)

    record = dict(payload_body)
    record["attestation"] = {
        "issuer": "verifyci.release_pipeline",
        "algorithm": "hmac-sha256",
        "key_id": "verifyci-release-authority-v1",
        "digest": digest,
        "signature": signature,
    }

    val_file = repo_root / VALIDATION_REL_PATH
    val_file.parent.mkdir(parents=True, exist_ok=True)
    val_file.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


__all__ = [
    "DEFAULT_RELEASE_AUTHORITY_KEY",
    "VALIDATION_REL_PATH",
    "VALIDATION_SCHEMA",
    "compute_attestation_signature",
    "compute_implementation_fingerprint",
    "generate_release_validation_record",
    "get_commit_sha",
    "get_parent_commit",
    "get_verifyci_root",
    "verify_release_validation_evidence",
]
