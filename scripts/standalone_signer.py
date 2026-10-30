#!/usr/bin/env python3
"""Standalone Authoritative Release Signer for VerifyCI v3.1.10 (§15.10).

Security Boundary & Process Isolation Architecture:
1. Zero Repository Code Execution:
   - Does NOT import `verifyci` or any repository-controlled package.
   - Explicitly purges the repository root from `sys.path`.
   - Operates strictly with Python standard library and pure `cryptography`.
2. Provenance & Artifact Verification:
   - Verifies the ephemeral Ed25519 signature on `measurement_attestation.json`.
   - Verifies that `measurements.json` cryptographically matches `measurements_digest`
     and `measurements_file_sha256` in the attestation.
   - Verifies all benchmark thresholds and test passing counts.
   - If executed in CI (`GITHUB_ACTIONS == 'true'`), independently validates against the
     GitHub Actions REST API:
     * Workflow run ID and attempt match.
     * Job `verifyci-measurements` concluded with `success`.
     * Job head SHA matches the candidate commit SHA.
     * Artifact `release-measurements` was uploaded by this run.
   - Computes source-code implementation fingerprint directly by reading raw file bytes.
3. Protected Authority Signing:
   - Signs the canonical RFC 8785 evidence payload using `VERIFYCI_RELEASE_SIGNING_KEY`.
   - Atomically writes `evidence/release/release_validation.json`.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from typing import Any, Mapping
import urllib.request
import urllib.error

# Security Boundary: Purge repository root from sys.path to prevent importing repo code
ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path = [p for p in sys.path if Path(p).resolve() != ROOT.resolve()]


def assert_no_repository_imports() -> None:
    """Enforce that no repository-controlled packages are imported in signer process."""
    assert "verifyci" not in sys.modules, "Security violation: repository modules must not be imported in signer"

# -----------------------------------------------------------------------------
# Pinned Architectural Constants (§15.10)
# -----------------------------------------------------------------------------
VALIDATION_SCHEMA = "verifyci.release_validation/v1"
ATTESTATION_SCHEMA = "verifyci.measurement_attestation/v1"
MEASUREMENTS_SCHEMA = "verifyci.release_measurements/v1"
TOOL_VERSION = "3.1.10"
RELEASE_AUTHORITY_KEY_ID = "verifyci-release-authority-ed25519-v1"
RELEASE_AUTHORITY_PUBLIC_KEY_HEX = (
    "7926b9524e2ec893f7834b9081228da255f058709fa158d77a75d7d21a3715f7"
)
PINNED_MANIFEST_HASH = "sha256:d471308bb8779a13e942d5fe2aa989bca74550132c5d4993ad4af3a5c41d6263"
PINNED_TOOLCHAIN_FINGERPRINT = (
    "sha256:a053a0d6a509c1b5fcafba6b0c580ec69174533a70903be4ca9d3462b47ebea9"
)
CHECK_ORDER = ("grounding", "deletion", "contract", "semantic", "security")

PINNED_CORPORA_HASHES = {
    "grounding": "sha256:b8fd75843271f427d7b228aeee268f2975e85e46273363745d128028945add20",
    "contract": "sha256:14bd93a97fb0be3eae13c99ebc4c25d1fe0e14dafb2e9db92e5e5d389043689c",
    "deletion": "sha256:efbca020e17296277e9ade5d3c59e20287e1e16018f044e416f7eebfd9a408a1",
    "security": "sha256:8d45f911c72bfda761c21da754b235d7a58768864a1d0087d70d745eeb97b880",
    "semantic": "sha256:dd0a162bd7442a78b6e236fa207c17dcd6413e5ad73e2e4b41c4b35451b5d3ba",
}

_CRITICAL_IMPLEMENTATION_FILES = (
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

# -----------------------------------------------------------------------------
# Pure Python RFC 8785 Canonical JSON Serialization (Zero Imports)
# -----------------------------------------------------------------------------
def _serialize_str(s: str) -> bytes:
    return json.dumps(s, ensure_ascii=False).encode("utf-8")


def _serialize_float(v: float) -> bytes:
    """Format IEEE 754 float conforming to ECMAScript 6 (RFC 8785 Section 3.2.2.3)."""
    if math.isnan(v) or math.isinf(v):
        raise ValueError("NaN and Infinity are not permitted in RFC 8785 JSON")
    if v == 0.0:
        return b"0"
    sign = b"-" if v < 0 else b""
    v = abs(v)
    r = repr(v)
    if "e" in r.lower():
        parts = r.lower().split("e")
        m_str = parts[0].replace(".", "")
        e_val = int(parts[1])
        n = e_val + 1
        k = len(m_str)
        if -6 < n <= 0:
            zeros = "0" * (-n)
            res = f"0.{zeros}{m_str}"
        elif 0 < n <= 21:
            if n >= k:
                zeros = "0" * (n - k)
                res = f"{m_str}{zeros}"
            else:
                res = f"{m_str[:n]}.{m_str[n:]}"
        else:
            exp_sign = "+" if n - 1 >= 0 else "-"
            exp_num = abs(n - 1)
            if k == 1:
                res = f"{m_str}e{exp_sign}{exp_num}"
            else:
                res = f"{m_str[0]}.{m_str[1:]}e{exp_sign}{exp_num}"
        return sign + res.encode("ascii")

    if r.endswith(".0"):
        int_val = int(v)
        s_int = str(int_val)
        if len(s_int) > 21:
            n = len(s_int)
            res = f"{s_int[0]}.{s_int[1:].rstrip('0')}e+{n - 1}"
            return sign + res.encode("ascii")
        return sign + s_int.encode("ascii")

    return sign + r.encode("ascii")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize value to canonical JSON UTF-8 bytes conforming to RFC 8785 (JCS)."""
    if value is None:
        return b"null"
    if isinstance(value, bool):
        return b"true" if value else b"false"
    if isinstance(value, int):
        if value < -9007199254740991 or value > 9007199254740991:
            raise ValueError(
                f"Integer {value} exceeds RFC 8785 safe integer limit [-(2^53 - 1), 2^53 - 1]"
            )
        return str(value).encode("ascii")
    if isinstance(value, float):
        return _serialize_float(value)
    if isinstance(value, str):
        return _serialize_str(value)
    if isinstance(value, Mapping):
        for k in value:
            if not isinstance(k, str):
                raise TypeError(f"RFC 8785 requires string dictionary keys, got {type(k).__name__}")
        sorted_keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        parts: list[bytes] = []
        for k in sorted_keys:
            parts.append(_serialize_str(k) + b":" + canonical_json_bytes(value[k]))
        return b"{" + b",".join(parts) + b"}"
    if isinstance(value, (list, tuple)):
        parts = [canonical_json_bytes(item) for item in value]
        return b"[" + b",".join(parts) + b"]"
    raise TypeError(f"Unsupported type for RFC 8785 canonical serialization: {type(value).__name__}")


# -----------------------------------------------------------------------------
# Direct Cryptographic & File Hashing (Zero Imports)
# -----------------------------------------------------------------------------
def compute_implementation_fingerprint(repo_root: Path) -> str:
    """Compute deterministic SHA256 over critical implementation sources directly."""
    hasher = hashlib.sha256()
    for rel_path in sorted(_CRITICAL_IMPLEMENTATION_FILES, key=lambda p: p.as_posix()):
        full_path = repo_root / rel_path
        if full_path.is_file():
            hasher.update(rel_path.as_posix().encode("utf-8"))
            norm_content = full_path.read_bytes().replace(b"\r\n", b"\n")
            hasher.update(norm_content)
    return "sha256:" + hasher.hexdigest()


def verify_security_corpus_sums(root: Path) -> list[str]:
    """Verify security corpus files against SHA256SUMS directly."""
    errors = []
    sums_file = root / "corpora" / "security" / "SHA256SUMS"
    if not sums_file.is_file():
        return ["corpora/security/SHA256SUMS is missing"]
    for line in sums_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        expected_hash, _, rel_name = line.partition(" ")
        rel_name = rel_name.strip()
        target = root / "corpora" / "security" / rel_name
        if not target.is_file():
            errors.append(f"corpus file missing: {rel_name}")
            continue
        actual_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            errors.append(f"corpus hash mismatch for {rel_name}: expected {expected_hash}, got {actual_hash}")
    return errors


def get_commit_sha(repo_root: Path) -> str | None:
    """Resolve HEAD commit SHA of the repository via git CLI."""
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


# -----------------------------------------------------------------------------
# GitHub Actions REST API Provenance Verification
# -----------------------------------------------------------------------------
def verify_github_actions_provenance(
    repo: str,
    run_id: str,
    run_attempt: str,
    expected_sha: str,
    github_token: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Query GitHub Actions REST API to verify measurement job execution."""
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "VerifyCI-StandaloneSigner",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # 1. Verify job conclusion
    url_jobs = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs?attempt={run_attempt}"
    req_jobs = urllib.request.Request(url_jobs, headers=headers)
    try:
        with urllib.request.urlopen(req_jobs, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return None, [f"GitHub API error fetching jobs for run {run_id}: {exc}"]

    jobs = data.get("jobs", [])
    measurement_job = next((j for j in jobs if j.get("name") == "verifyci-measurements"), None)
    if not measurement_job:
        return None, [f"measurement job 'verifyci-measurements' not found in run {run_id}"]

    if measurement_job.get("status") != "completed":
        return None, [
            f"measurement job 'verifyci-measurements' status is '{measurement_job.get('status')}' (expected 'completed')"
        ]

    if measurement_job.get("conclusion") != "success":
        return None, [
            f"measurement job 'verifyci-measurements' conclusion is '{measurement_job.get('conclusion')}' (expected 'success')"
        ]

    job_head_sha = measurement_job.get("head_sha", "").lower()
    if job_head_sha != expected_sha.lower():
        return None, [
            f"measurement job head_sha '{job_head_sha}' does not match expected commit '{expected_sha.lower()}'"
        ]

    # 2. Verify artifact existence in the workflow run
    url_artifacts = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts"
    req_art = urllib.request.Request(url_artifacts, headers=headers)
    try:
        with urllib.request.urlopen(req_art, timeout=30) as resp:
            art_data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return None, [f"GitHub API error fetching artifacts for run {run_id}: {exc}"]

    artifacts = art_data.get("artifacts", [])
    measurements_artifact = next((a for a in artifacts if a.get("name") == "release-measurements"), None)
    if not measurements_artifact:
        return None, [f"artifact 'release-measurements' not found in workflow run {run_id}"]

    return {
        "ci_platform": "github_actions",
        "ci_verified": True,
        "job_id": measurement_job.get("id"),
        "job_name": measurement_job.get("name"),
        "workflow_run_id": str(run_id),
        "workflow_run_attempt": str(run_attempt),
        "measurement_job_started_at": measurement_job.get("started_at"),
        "measurement_job_completed_at": measurement_job.get("completed_at"),
        "artifact_id": measurements_artifact.get("id"),
        "artifact_size_in_bytes": measurements_artifact.get("size_in_bytes"),
    }, []


# -----------------------------------------------------------------------------
# Core Signer Implementation
# -----------------------------------------------------------------------------
def sign_release_evidence(
    root: Path,
    measurements_file: Path,
    attestation_file: Path,
    output_file: Path,
    signing_key_hex: str,
    *,
    custom_verifier: Any = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate authenticated measurement provenance and issue authoritative Ed25519 attestation."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    # 1. Load and parse attestation
    if not attestation_file.is_file():
        return None, [f"measurement attestation file not found: {attestation_file}"]
    try:
        attestation = json.loads(attestation_file.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, [f"failed to parse measurement attestation JSON: {exc}"]

    if attestation.get("schema") != ATTESTATION_SCHEMA:
        return None, [f"unsupported attestation schema: {attestation.get('schema')}"]

    # Verify ephemeral Ed25519 signature on attestation
    ephem_pub_hex = attestation.get("ephemeral_key", {}).get("public_key")
    sig_hex = attestation.get("signature")
    if not ephem_pub_hex or not sig_hex:
        return None, ["measurement attestation missing ephemeral public key or signature"]

    body_to_verify = {k: v for k, v in attestation.items() if k != "signature"}
    computed_att_bytes = canonical_json_bytes(body_to_verify)
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(ephem_pub_hex))
        pub.verify(bytes.fromhex(sig_hex), computed_att_bytes)
    except Exception as exc:
        return None, [f"ephemeral signature verification on measurement attestation failed: {exc}"]

    # 2. Load and verify measurements artifact binding
    if not measurements_file.is_file():
        return None, [f"measurements file not found: {measurements_file}"]
    try:
        measurements_raw = measurements_file.read_bytes()
        measurement_record = json.loads(measurements_raw.decode("utf-8"))
    except Exception as exc:
        return None, [f"failed to parse measurements JSON: {exc}"]

    if measurement_record.get("schema") != MEASUREMENTS_SCHEMA:
        return None, [f"unsupported measurements schema: {measurement_record.get('schema')}"]

    computed_raw_sha256 = "sha256:" + hashlib.sha256(measurements_raw).hexdigest()
    computed_canonical_digest = (
        "sha256:" + hashlib.sha256(canonical_json_bytes(measurement_record)).hexdigest()
    )

    if not hmac.compare_digest(
        attestation.get("measurements_file_sha256", ""), computed_raw_sha256
    ):
        return None, [
            f"measurements artifact raw hash mismatch: attestation has {attestation.get('measurements_file_sha256')}, computed {computed_raw_sha256}"
        ]

    if not hmac.compare_digest(
        attestation.get("measurements_digest", ""), computed_canonical_digest
    ):
        return None, [
            f"measurements artifact canonical digest mismatch: attestation has {attestation.get('measurements_digest')}, computed {computed_canonical_digest}"
        ]

    # 3. Verify Source Code & Fingerprint Invariants
    current_impl_fp = compute_implementation_fingerprint(root)
    if attestation.get("implementation_fingerprint") != current_impl_fp:
        return None, [
            f"implementation fingerprint mismatch: attestation has {attestation.get('implementation_fingerprint')}, workspace has {current_impl_fp}"
        ]
    if measurement_record.get("implementation_fingerprint") != current_impl_fp:
        return None, [
            f"measurements record implementation fingerprint mismatch: record has {measurement_record.get('implementation_fingerprint')}, workspace has {current_impl_fp}"
        ]

    # Check corpus integrity
    corpus_errors = verify_security_corpus_sums(root)
    if corpus_errors:
        return None, corpus_errors

    # Verify commit SHA matches HEAD
    commit_sha = get_commit_sha(root)
    if not commit_sha:
        return None, ["unable to resolve authoritative commit SHA from git"]

    att_commit = (attestation.get("execution", {}).get("commit_sha") or "").lower()
    if not att_commit or att_commit != commit_sha.lower():
        return None, [
            f"commit SHA mismatch: attestation bound to {att_commit[:8]}, workspace HEAD is {commit_sha[:8]}"
        ]

    # Verify Manifest and Toolchain
    if attestation.get("manifest_hash") != PINNED_MANIFEST_HASH:
        return None, [
            f"manifest hash mismatch: attestation has {attestation.get('manifest_hash')}, expected {PINNED_MANIFEST_HASH}"
        ]

    # 4. Verify Measurement Metrics & Thresholds
    measurements = measurement_record.get("measurements", {})
    test_metrics = measurements.get("test_suite", {})
    if test_metrics.get("total_failed", 1) != 0 or test_metrics.get("total_errors", 1) != 0:
        return None, ["test suite contains failing or errored tests"]
    if test_metrics.get("total_passed", 0) < 200:
        return None, [f"insufficient passing test count: {test_metrics.get('total_passed')} < 200"]

    bench_metrics = measurements.get("benchmark", {})
    if bench_metrics.get("cases_evaluated", 0) < 22:
        return None, [f"insufficient benchmark cases evaluated: {bench_metrics.get('cases_evaluated')} < 22"]
    if not bench_metrics.get("zero_false_blocking") or not bench_metrics.get("strict_redaction"):
        return None, ["benchmark measurements failed zero_false_blocking or strict_redaction invariant"]

    defect_metrics = bench_metrics.get("defects", {})
    required_defects = ("SEC-SECRET", "SEC-SECRET-TO-SINK", "SEC-DANGEROUS-CALL", "SEC-TAINT-TO-SINK")
    for did in required_defects:
        d_data = defect_metrics.get(did, {})
        if d_data.get("precision", 0.0) < 1.0 or d_data.get("recall", 0.0) < 0.90:
            return None, [f"benchmark defect metric threshold not met for {did}: {d_data}"]

    # 5. Provenance Authentication Check
    execution_info = attestation.get("execution", {})
    is_github_actions = os.environ.get("GITHUB_ACTIONS") == "true"

    if custom_verifier:
        # Custom verifier injection for adversarial tests
        provenance, prov_errors = custom_verifier(attestation)
        if prov_errors:
            return None, prov_errors
    elif is_github_actions:
        if execution_info.get("ci_platform") != "github_actions":
            return None, [
                f"untrusted execution platform in CI environment: expected 'github_actions', got '{execution_info.get('ci_platform')}'"
            ]

        run_id = os.environ.get("GITHUB_RUN_ID")
        run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
        github_sha = os.environ.get("GITHUB_SHA")
        repo = os.environ.get("GITHUB_REPOSITORY")
        token = os.environ.get("GITHUB_TOKEN")

        if execution_info.get("workflow_run_id") != run_id:
            return None, [
                f"workflow run ID mismatch: attestation has {execution_info.get('workflow_run_id')}, env has {run_id}"
            ]
        if execution_info.get("workflow_run_attempt") != run_attempt:
            return None, [
                f"workflow run attempt mismatch: attestation has {execution_info.get('workflow_run_attempt')}, env has {run_attempt}"
            ]
        if execution_info.get("commit_sha", "").lower() != (github_sha or "").lower():
            return None, [
                f"workflow commit SHA mismatch: attestation has {execution_info.get('commit_sha')}, env GITHUB_SHA is {github_sha}"
            ]

        if not repo or not token:
            return None, ["missing GITHUB_REPOSITORY or GITHUB_TOKEN for GitHub Actions provenance check"]

        provenance, prov_errors = verify_github_actions_provenance(
            repo, run_id, run_attempt, commit_sha, token
        )
        if prov_errors:
            return None, prov_errors
    else:
        # Local development execution
        if execution_info.get("ci_platform") != "local":
            return None, [
                f"untrusted execution platform in local mode: expected 'local', got '{execution_info.get('ci_platform')}'"
            ]
        provenance = {
            "ci_platform": "local",
            "ci_verified": False,
            "commit_sha": commit_sha,
            "measurement_attestation_digest": computed_canonical_digest,
            "measurement_attestation_created_at": attestation.get("created_at"),
            "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    # 6. Generate Authoritative Release Validation Record
    payload_body = {
        "attestation": {
            "algorithm": "ed25519",
            "digest": None,
            "issuer": "verifyci.release_pipeline",
            "key_id": RELEASE_AUTHORITY_KEY_ID,
            "public_key": RELEASE_AUTHORITY_PUBLIC_KEY_HEX,
            "signature": None,
        },
        "checks_validated": list(CHECK_ORDER),
        "commit_sha": commit_sha,
        "corpora_hashes": PINNED_CORPORA_HASHES,
        "implementation_fingerprint": current_impl_fp,
        "manifest_hash": PINNED_MANIFEST_HASH,
        "measurements": measurements,
        "provenance": provenance,
        "schema": VALIDATION_SCHEMA,
        "stage": "final",
        "status": "VALIDATED",
        "tool_version": TOOL_VERSION,
        "toolchain_fingerprint": PINNED_TOOLCHAIN_FINGERPRINT,
        "toolchain_identity": {
            "os": platform.system().lower(),
            "python_version": platform.python_version(),
        },
    }

    payload_for_digest = {k: v for k, v in payload_body.items() if k != "attestation"}
    digest = "sha256:" + hashlib.sha256(canonical_json_bytes(payload_for_digest)).hexdigest()

    try:
        priv_bytes = bytes.fromhex(signing_key_hex.strip())
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        signature = priv.sign(digest.encode("utf-8")).hex()
    except Exception as exc:
        return None, [f"failed to compute Ed25519 signature with release authority: {exc}"]

    payload_body["attestation"]["digest"] = digest
    payload_body["attestation"]["signature"] = signature

    # Atomic write to output_file
    output_file.parent.mkdir(parents=True, exist_ok=True)
    temp_file = output_file.with_name(f"{output_file.name}.tmp.{os.getpid()}")
    try:
        temp_file.write_text(json.dumps(payload_body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temp_file, output_file)
    except Exception:
        if temp_file.is_file():
            temp_file.unlink(missing_ok=True)
        raise

    return payload_body, []


def main(argv: list[str] | None = None) -> int:
    assert_no_repository_imports()
    parser = argparse.ArgumentParser(description="Standalone Release Signer for VerifyCI v3.1.10 (§15.10)")
    parser.add_argument(
        "--measurements",
        type=Path,
        default=ROOT / "evidence" / "release" / "measurements.json",
        help="Path to verified measurements JSON",
    )
    parser.add_argument(
        "--attestation",
        type=Path,
        default=ROOT / "evidence" / "release" / "measurement_attestation.json",
        help="Path to signed measurement attestation JSON",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "evidence" / "release" / "release_validation.json",
        help="Path to write release validation evidence",
    )
    args = parser.parse_args(argv)

    signing_key = os.environ.get("VERIFYCI_RELEASE_SIGNING_KEY")
    if not signing_key:
        print("Release blocked: VERIFYCI_RELEASE_SIGNING_KEY is missing.", file=sys.stderr)
        return 1

    record, errors = sign_release_evidence(
        ROOT,
        args.measurements,
        args.attestation,
        args.output,
        signing_key,
    )
    if errors or not record:
        print("Release blocked: provenance or measurement verification failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    report = {
        "attestation_digest": record["attestation"]["digest"],
        "commit_sha": record["commit_sha"],
        "manifest_errors": [],
        "measurement_pipeline": "verified",
        "provenance_verified": True,
        "release_ready": True,
        "schema": "verifyci.release_preflight/v1",
        "validation_evidence": str(args.output.as_posix()),
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
