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

# Security Boundary: Purge candidate repository paths from sys.path to prevent importing repo code
ROOT = Path(__file__).resolve().parents[1]


def isolate_execution_environment(repo_root: Path) -> None:
    """Enforce strict process isolation by purging all repository-controlled paths from sys.path."""
    resolved_root = repo_root.resolve()
    cleaned_path: list[str] = []
    for entry in sys.path:
        if not entry or entry == ".":
            try:
                cwd_res = Path.cwd().resolve()
                if (cwd_res == resolved_root or cwd_res.is_relative_to(resolved_root)) and "site-packages" not in cwd_res.parts and "dist-packages" not in cwd_res.parts:
                    continue
            except Exception:
                continue
        try:
            p_res = Path(entry).resolve()
            if (p_res == resolved_root or p_res.is_relative_to(resolved_root)) and "site-packages" not in p_res.parts and "dist-packages" not in p_res.parts:
                continue
        except Exception:
            continue
        cleaned_path.append(entry)
    sys.path = cleaned_path


def verify_imported_module_origins(repo_root: Path) -> None:
    """Verify that no imported module in sys.modules originates from candidate repository code."""
    resolved_root = repo_root.resolve()
    this_file = Path(__file__).resolve()
    for name, module in list(sys.modules.items()):
        if module is None:
            continue
        mod_file = getattr(module, "__file__", None)
        if not mod_file:
            continue
        try:
            mod_path = Path(mod_file).resolve()
        except Exception:
            continue
        if mod_path == this_file:
            continue
        if (mod_path == resolved_root or mod_path.is_relative_to(resolved_root)) and "site-packages" not in mod_path.parts and "dist-packages" not in mod_path.parts:
            raise RuntimeError(
                f"Security violation: module '{name}' ({mod_path}) was imported from candidate repository path"
            )


if __name__ == "__main__":
    isolate_execution_environment(ROOT)


def assert_no_repository_imports() -> None:
    """Enforce that no repository-controlled packages are imported in signer process."""
    assert "verifyci" not in sys.modules, "Security violation: repository modules must not be imported in signer"
    isolate_execution_environment(ROOT)
    verify_imported_module_origins(ROOT)

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

PINNED_REPOSITORY = "NeutronZero/VerifyCI"
PINNED_WORKFLOW_PATH = ".github/workflows/ci.yml"
PINNED_WORKFLOW_NAME = "ci"
PINNED_MEASUREMENT_JOB = "verifyci-measurements"
# Reusable workflow jobs may be reported as the called job name alone or with the
# caller job prefix. Both exact forms are accepted; any additional match is a
# duplicate and fails closed.
PINNED_MEASUREMENT_JOB_NAMES = (
    PINNED_MEASUREMENT_JOB,
    f"trusted-measurements / {PINNED_MEASUREMENT_JOB}",
)
PINNED_MEASUREMENT_WORKFLOW_PATH = ".github/workflows/release_measurements.yml"
PINNED_SIGNING_WORKFLOW_PATH = ".github/workflows/release_signing.yml"
PINNED_TRUSTED_REF = "refs/heads/release-authority"
PINNED_ARTIFACT_NAME = "release-measurements"
PINNED_MEASUREMENT_STEPS = (
    "Checkout Candidate Source",
    "Verify Trusted Measurement Harness Integrity",
    "Run Trusted Measurement Pipeline",
    "Upload Release Measurements Artifact",
)

_CRITICAL_IMPLEMENTATION_FILES = (
    Path(".github/workflows/ci.yml"),
    Path(".github/workflows/release_measurements.yml"),
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
    Path("tests/v3/test_release_trust_boundary.py"),
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


def fetch_github_oidc_jwks(timeout: int = 15) -> dict[str, Any]:
    """Fetch GitHub Actions published RSA public keys (JWKS)."""
    url = "https://token.actions.githubusercontent.com/.well-known/jwks"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "VerifyCI-StandaloneSigner",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _b64url_to_int(s: str) -> int:
    import base64
    padded = s + "=" * (-len(s) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    return int.from_bytes(raw, byteorder="big")


def _is_full_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(c in "0123456789abcdef" for c in value.lower())


def _split_workflow_ref(value: Any) -> tuple[str, str] | None:
    if not isinstance(value, str) or "@" not in value:
        return None
    path, _, suffix = value.rpartition("@")
    if not path or not suffix:
        return None
    return path, suffix


def verify_github_oidc_token(
    token: str,
    expected_repo: str,
    expected_sha: str,
    expected_run_id: str,
    expected_run_attempt: str,
    *,
    expected_workflow_path: str = PINNED_MEASUREMENT_WORKFLOW_PATH,
    expected_workflow_sha: str | None = None,
    expected_ref: str | None = None,
    jwks: dict[str, Any] | None = None,
    current_time: float | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Cryptographically verify GitHub Actions RS256 OIDC token against GitHub's JWKS.

    The token must be signed by GitHub and must identify the *trusted measurement
    workflow revision*, not merely a string prefix:

    - ``job_workflow_ref`` path must equal ``expected_workflow_path`` exactly.
    - ``job_workflow_ref`` suffix must be the protected trusted ref or the exact
      immutable trusted commit SHA.
    - ``job_workflow_sha`` must equal the exact trusted commit SHA.
    - ``sha``, ``ref``, ``run_id`` and ``run_attempt`` must match the measured
      candidate run exactly.

    A valid token issued to candidate-controlled ``ci.yml`` therefore cannot
    authorize signing.
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    if not expected_workflow_sha or not _is_full_sha(expected_workflow_sha):
        return None, ["trusted measurement workflow SHA is not pinned to a full commit SHA"]

    parts = token.strip().split(".")
    if len(parts) != 3:
        return None, ["malformed OIDC JWT: expected 3 dot-separated segments"]
    header_b64, payload_b64, sig_b64 = parts

    try:
        header_padded = header_b64 + "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_padded.encode("ascii")).decode("utf-8"))
    except Exception as exc:
        return None, [f"failed to decode OIDC header: {exc}"]

    if not isinstance(header, dict):
        return None, ["malformed OIDC header: expected JSON object"]
    if header.get("alg") != "RS256":
        return None, [f"unsupported OIDC algorithm: expected RS256, got {header.get('alg')}"]
    kid = header.get("kid")
    if not kid:
        return None, ["OIDC JWT header missing 'kid'"]

    if jwks is None:
        try:
            jwks = fetch_github_oidc_jwks()
        except Exception as exc:
            return None, [f"failed to fetch GitHub OIDC JWKS: {exc}"]

    keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
    key_entry = next((k for k in keys if isinstance(k, dict) and k.get("kid") == kid), None)
    if not key_entry:
        return None, [f"OIDC signing key '{kid}' not found in GitHub JWKS"]
    if key_entry.get("kty") != "RSA":
        return None, [f"unsupported key type in JWKS: {key_entry.get('kty')}"]

    try:
        pub_numbers = RSAPublicNumbers(
            e=_b64url_to_int(key_entry["e"]),
            n=_b64url_to_int(key_entry["n"]),
        )
        pub_key = pub_numbers.public_key()
    except Exception as exc:
        return None, [f"failed to construct RSA public key from JWKS: {exc}"]

    try:
        sig_padded = sig_b64 + "=" * (-len(sig_b64) % 4)
        sig_bytes = base64.urlsafe_b64decode(sig_padded.encode("ascii"))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        pub_key.verify(sig_bytes, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        return None, [f"OIDC cryptographic signature verification failed: {exc}"]

    try:
        payload_padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_padded.encode("ascii")).decode("utf-8"))
    except Exception as exc:
        return None, [f"failed to decode OIDC payload: {exc}"]

    if not isinstance(claims, dict):
        return None, ["malformed OIDC payload: expected JSON object"]

    now = time.time() if current_time is None else current_time
    skew = 60.0

    if claims.get("iss") != "https://token.actions.githubusercontent.com":
        return None, [f"untrusted OIDC issuer: {claims.get('iss')}"]
    if claims.get("aud") != "verifyci-release-authority":
        return None, [f"untrusted OIDC audience: {claims.get('aud')} (expected 'verifyci-release-authority')"]

    for time_claim in ("exp", "nbf", "iat"):
        value = claims.get(time_claim)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None, [f"OIDC claim '{time_claim}' is missing or malformed"]

    if now > float(claims["exp"]) + skew:
        return None, [f"OIDC token expired (exp: {claims['exp']}, now: {now})"]
    if now < float(claims["nbf"]) - skew:
        return None, [f"OIDC token not yet valid (nbf: {claims['nbf']}, now: {now})"]
    if float(claims["iat"]) > now + skew:
        return None, [f"OIDC token issued in the future (iat: {claims['iat']}, now: {now})"]

    repo_claim = claims.get("repository", "")
    if not isinstance(repo_claim, str) or repo_claim.lower() != expected_repo.lower():
        return None, [f"OIDC repository mismatch: expected '{expected_repo}', got '{repo_claim}'"]

    owner_claim = claims.get("repository_owner", "")
    expected_owner = expected_repo.split("/", 1)[0]
    if not isinstance(owner_claim, str) or owner_claim.lower() != expected_owner.lower():
        return None, [f"OIDC repository_owner mismatch: expected '{expected_owner}', got '{owner_claim}'"]

    sha_claim = claims.get("sha", "")
    if not _is_full_sha(sha_claim) or sha_claim.lower() != expected_sha.lower():
        return None, [f"OIDC commit SHA mismatch: expected '{expected_sha}', got '{sha_claim}'"]

    run_id_claim = str(claims.get("run_id", ""))
    if run_id_claim != str(expected_run_id):
        return None, [f"OIDC run_id mismatch: expected '{expected_run_id}', got '{run_id_claim}'"]

    run_att_claim = str(claims.get("run_attempt", ""))
    if run_att_claim != str(expected_run_attempt):
        return None, [f"OIDC run_attempt mismatch: expected '{expected_run_attempt}', got '{run_att_claim}'"]

    ref_claim = claims.get("ref")
    if not isinstance(ref_claim, str) or not ref_claim.startswith("refs/"):
        return None, [f"OIDC ref is missing or malformed: {ref_claim}"]
    if expected_ref is not None and ref_claim != expected_ref:
        return None, [f"OIDC ref mismatch: expected '{expected_ref}', got '{ref_claim}'"]
    if claims.get("ref_type") != "branch":
        return None, [f"OIDC ref_type mismatch: expected 'branch', got '{claims.get('ref_type')}'"]

    event_name = claims.get("event_name")
    if event_name not in ("push", "workflow_dispatch"):
        return None, [f"OIDC event_name is not an allowed measurement event: {event_name}"]

    workflow_ref = claims.get("workflow_ref")
    parsed_workflow_ref = _split_workflow_ref(workflow_ref)
    if parsed_workflow_ref is None:
        return None, [f"OIDC workflow_ref is missing or malformed: {workflow_ref}"]
    expected_caller_path = f"{expected_repo}/{PINNED_WORKFLOW_PATH}"
    if parsed_workflow_ref[0].lower() != expected_caller_path.lower():
        return None, [
            f"OIDC workflow_ref path mismatch: expected '{expected_caller_path}', got '{parsed_workflow_ref[0]}'"
        ]
    if parsed_workflow_ref[1] != ref_claim and parsed_workflow_ref[1].lower() != expected_sha.lower():
        return None, [
            f"OIDC workflow_ref revision does not match candidate run: {parsed_workflow_ref[1]}"
        ]
    workflow_sha = claims.get("workflow_sha")
    if not _is_full_sha(workflow_sha) or workflow_sha.lower() != expected_sha.lower():
        return None, [f"OIDC workflow_sha mismatch: expected '{expected_sha}', got '{workflow_sha}'"]

    job_workflow_ref = claims.get("job_workflow_ref")
    parsed_job_ref = _split_workflow_ref(job_workflow_ref)
    if parsed_job_ref is None:
        return None, [f"OIDC job_workflow_ref is missing or malformed: {job_workflow_ref}"]
    expected_job_path = f"{expected_repo}/{expected_workflow_path}"
    if parsed_job_ref[0].lower() != expected_job_path.lower():
        return None, [
            f"OIDC job_workflow_ref mismatch: expected exact path '{expected_job_path}', got '{parsed_job_ref[0]}'"
        ]
    trusted_suffix = parsed_job_ref[1]
    if trusted_suffix != PINNED_TRUSTED_REF and trusted_suffix.lower() != expected_workflow_sha.lower():
        return None, [
            "OIDC job_workflow_ref revision is not the protected trusted ref or pinned commit: "
            f"{trusted_suffix}"
        ]

    job_workflow_sha = claims.get("job_workflow_sha")
    if not _is_full_sha(job_workflow_sha) or job_workflow_sha.lower() != expected_workflow_sha.lower():
        return None, [
            f"OIDC job_workflow_sha mismatch: expected '{expected_workflow_sha.lower()}', got '{job_workflow_sha}'"
        ]

    sub_claim = claims.get("sub")
    if not isinstance(sub_claim, str) or not sub_claim.startswith("repo:") or ":ref:" not in sub_claim:
        return None, [f"OIDC sub claim is missing or malformed: {sub_claim}"]
    if sub_claim.rsplit(":ref:", 1)[1] != ref_claim:
        return None, [f"OIDC sub claim ref does not match ref claim: {sub_claim}"]

    return claims, []


def parse_jwt_claims_unverified(token: str) -> dict[str, Any] | None:
    """Parse JWT claims without third-party dependencies."""
    try:
        import base64
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        padded = payload + "=" * (-len(payload) % 4)
        raw_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
        return json.loads(raw_bytes.decode("utf-8"))
    except Exception:
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
    *,
    expected_ref: str | None = None,
    expected_artifact_id: int | None = None,
    expected_artifact_digest: str | None = None,
    artifact_zip_sha256: str | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Query the GitHub Actions REST API and bind the exact measurement upload.

    This is deliberately strict: the measurement job must exist exactly once, every
    mandated step (including the artifact upload step) must have succeeded, and the
    artifact record must match the artifact downloaded by the trusted signer by ID,
    name, run, attempt, commit, ref and SHA-256 digest.
    """
    import datetime
    import re

    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "VerifyCI-StandaloneSigner",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    def _api_get(url: str, label: str) -> tuple[dict[str, Any] | None, list[str]]:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            return None, [f"GitHub API error fetching {label}: {exc}"]
        if not isinstance(payload, dict):
            return None, [f"GitHub API returned malformed {label}: expected object"]
        return payload, []

    # 1. Workflow run identity
    run_data, errors = _api_get(
        f"https://api.github.com/repos/{repo}/actions/runs/{run_id}", f"run {run_id}"
    )
    if errors:
        return None, errors

    if str(run_data.get("id", "")) != str(run_id):
        return None, [f"workflow run id mismatch: expected '{run_id}', got '{run_data.get('id')}'"]
    if "run_attempt" not in run_data:
        return None, ["workflow run metadata is incomplete: run_attempt missing"]
    if str(run_data.get("run_attempt")) != str(run_attempt):
        return None, [
            f"workflow run attempt mismatch: expected '{run_attempt}', got '{run_data.get('run_attempt')}'"
        ]
    run_head_sha = str(run_data.get("head_sha", "")).lower()
    if run_head_sha != expected_sha.lower():
        return None, [
            f"workflow run head_sha '{run_head_sha}' does not match expected commit '{expected_sha.lower()}'"
        ]
    if run_data.get("path") != PINNED_WORKFLOW_PATH:
        return None, [
            f"untrusted workflow path: expected '{PINNED_WORKFLOW_PATH}', got '{run_data.get('path')}'"
        ]
    if run_data.get("status") != "completed":
        return None, [f"workflow run status is '{run_data.get('status')}' (expected 'completed')"]
    if run_data.get("conclusion") != "success":
        return None, [f"workflow run conclusion is '{run_data.get('conclusion')}' (expected 'success')"]
    if run_data.get("event") not in ("push", "workflow_dispatch"):
        return None, [f"unexpected workflow run event: {run_data.get('event')}"]
    run_repo = run_data.get("repository", {}).get("full_name") if isinstance(run_data.get("repository"), dict) else None
    if run_repo and str(run_repo).lower() != repo.lower():
        return None, [f"workflow run repository mismatch: expected '{repo}', got '{run_repo}'"]

    head_branch = run_data.get("head_branch")
    if not isinstance(head_branch, str) or not head_branch:
        return None, ["workflow run head_branch is missing"]
    run_ref = f"refs/heads/{head_branch}"
    if expected_ref is not None and run_ref != expected_ref:
        return None, [f"workflow run ref mismatch: expected '{expected_ref}', got '{run_ref}'"]

    # 2. Jobs and mandatory upload step
    jobs_data, errors = _api_get(
        f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs?attempt={run_attempt}&per_page=100",
        f"jobs for run {run_id}",
    )
    if errors:
        return None, errors

    jobs = jobs_data.get("jobs")
    if not isinstance(jobs, list):
        return None, ["GitHub API jobs response is incomplete: 'jobs' list missing"]
    if "total_count" not in jobs_data or jobs_data.get("total_count") != len(jobs):
        return None, [
            "GitHub API jobs response is incomplete: total_count does not match returned jobs"
        ]

    named_jobs = [
        j for j in jobs if isinstance(j, dict) and j.get("name") in PINNED_MEASUREMENT_JOB_NAMES
    ]
    if len(named_jobs) > 1:
        return None, [
            f"duplicate measurement jobs named {PINNED_MEASUREMENT_JOB_NAMES} in run {run_id}"
        ]
    if not named_jobs:
        return None, [
            f"measurement job {PINNED_MEASUREMENT_JOB_NAMES} not found in run {run_id}"
        ]
    measurement_job = named_jobs[0]

    if measurement_job.get("status") != "completed":
        return None, [
            f"measurement job '{PINNED_MEASUREMENT_JOB}' status is '{measurement_job.get('status')}' (expected 'completed')"
        ]
    if measurement_job.get("conclusion") != "success":
        return None, [
            f"measurement job '{PINNED_MEASUREMENT_JOB}' conclusion is '{measurement_job.get('conclusion')}' (expected 'success')"
        ]
    job_head_sha = str(measurement_job.get("head_sha", "")).lower()
    if job_head_sha != expected_sha.lower():
        return None, [
            f"measurement job head_sha '{job_head_sha}' does not match expected commit '{expected_sha.lower()}'"
        ]
    if not measurement_job.get("started_at") or not measurement_job.get("completed_at"):
        return None, ["measurement job timestamps are incomplete"]

    steps = measurement_job.get("steps")
    if not isinstance(steps, list) or not steps:
        return None, ["measurement job steps are missing or incomplete"]
    step_names = [s.get("name") for s in steps if isinstance(s, dict)]
    if len(step_names) != len(set(step_names)):
        return None, ["measurement job contains duplicate step names (ambiguous provenance)"]

    step_positions: dict[str, int] = {}
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            return None, ["measurement job contains a malformed step entry"]
        name = step.get("name")
        if name in PINNED_MEASUREMENT_STEPS:
            step_positions[name] = index
            if step.get("status") != "completed":
                return None, [f"required measurement step '{name}' status is '{step.get('status')}' (expected 'completed')"]
            if step.get("conclusion") != "success":
                return None, [
                    f"required measurement step '{name}' conclusion is '{step.get('conclusion')}' (expected 'success')"
                ]

    for required_step in PINNED_MEASUREMENT_STEPS:
        if required_step not in step_positions:
            return None, [f"required measurement step '{required_step}' not found in job {measurement_job.get('id')}"]

    if step_positions["Upload Release Measurements Artifact"] <= step_positions["Run Trusted Measurement Pipeline"]:
        return None, ["artifact upload step is not ordered after the trusted measurement step"]

    # 3. Artifact record: exact ID, name, digest, run, attempt and commit
    artifacts_data, errors = _api_get(
        f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100",
        f"artifacts for run {run_id}",
    )
    if errors:
        return None, errors

    artifacts = artifacts_data.get("artifacts")
    if not isinstance(artifacts, list):
        return None, ["GitHub API artifacts response is incomplete: 'artifacts' list missing"]
    if "total_count" not in artifacts_data or artifacts_data.get("total_count") != len(artifacts):
        return None, [
            "GitHub API artifacts response is incomplete: total_count does not match returned artifacts"
        ]

    matching = [
        a for a in artifacts if isinstance(a, dict) and a.get("name") == PINNED_ARTIFACT_NAME
    ]
    if len(matching) > 1:
        return None, [f"duplicate artifacts named '{PINNED_ARTIFACT_NAME}' in run {run_id}"]
    if not matching:
        return None, [f"artifact '{PINNED_ARTIFACT_NAME}' not found in workflow run {run_id}"]
    artifact = matching[0]

    artifact_id = artifact.get("id")
    if not isinstance(artifact_id, int) or artifact_id <= 0:
        return None, ["artifact ID is missing or malformed"]
    if expected_artifact_id is not None and int(artifact_id) != int(expected_artifact_id):
        return None, [
            f"artifact id mismatch: expected '{expected_artifact_id}', got '{artifact_id}'"
        ]
    if int(artifact.get("size_in_bytes", 0) or 0) <= 0:
        return None, [f"artifact '{PINNED_ARTIFACT_NAME}' size is 0 bytes"]
    if artifact.get("expired") is not False:
        return None, [f"artifact '{PINNED_ARTIFACT_NAME}' is expired or expiry state is unknown"]

    api_digest = artifact.get("digest")
    if not isinstance(api_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", api_digest):
        return None, ["artifact digest is missing or malformed in GitHub API metadata"]
    if expected_artifact_digest and not hmac.compare_digest(api_digest, expected_artifact_digest):
        return None, [
            f"artifact digest mismatch: expected '{expected_artifact_digest}', got '{api_digest}'"
        ]
    if not artifact_zip_sha256:
        return None, ["downloaded artifact SHA-256 digest is missing; cannot bind archive bytes"]
    if not hmac.compare_digest(api_digest, artifact_zip_sha256):
        return None, [
            f"downloaded artifact digest mismatch: API has '{api_digest}', local zip has '{artifact_zip_sha256}'"
        ]

    artifact_run = artifact.get("workflow_run") if isinstance(artifact.get("workflow_run"), dict) else {}
    if str(artifact_run.get("id", "")) != str(run_id):
        return None, [
            f"artifact run mismatch: expected '{run_id}', got '{artifact_run.get('id')}'"
        ]
    if str(artifact_run.get("head_sha", "")).lower() != expected_sha.lower():
        return None, [
            f"artifact head_sha mismatch: expected '{expected_sha.lower()}', got '{artifact_run.get('head_sha')}'"
        ]
    if artifact_run.get("head_branch") != head_branch:
        return None, [
            f"artifact head_branch mismatch: expected '{head_branch}', got '{artifact_run.get('head_branch')}'"
        ]

    # 4. Artifact creation must fall inside the measurement job window
    art_created_raw = artifact.get("created_at")
    job_started_raw = measurement_job.get("started_at")
    job_completed_raw = measurement_job.get("completed_at")
    if not art_created_raw:
        return None, ["artifact created_at is missing"]
    try:
        art_dt = datetime.datetime.fromisoformat(str(art_created_raw).replace("Z", "+00:00"))
        job_start_dt = datetime.datetime.fromisoformat(str(job_started_raw).replace("Z", "+00:00"))
        job_comp_dt = datetime.datetime.fromisoformat(str(job_completed_raw).replace("Z", "+00:00"))
        tolerance = datetime.timedelta(seconds=120)
        if art_dt < (job_start_dt - tolerance) or art_dt > (job_comp_dt + tolerance):
            return None, [
                f"artifact '{PINNED_ARTIFACT_NAME}' creation timestamp {art_created_raw} is outside job execution window [{job_started_raw}, {job_completed_raw}]"
            ]
    except Exception as exc:
        return None, [f"failed to parse timestamps for artifact window validation: {exc}"]

    return {
        "ci_platform": "github_actions",
        "ci_verified": True,
        "job_id": measurement_job.get("id"),
        "job_name": measurement_job.get("name"),
        "measurement_steps": [s.get("name") for s in steps if isinstance(s, dict)],
        "workflow_run_id": str(run_id),
        "workflow_run_attempt": str(run_attempt),
        "workflow_path": PINNED_WORKFLOW_PATH,
        "candidate_ref": run_ref,
        "measurement_job_started_at": measurement_job.get("started_at"),
        "measurement_job_completed_at": measurement_job.get("completed_at"),
        "artifact_id": artifact_id,
        "artifact_name": artifact.get("name"),
        "artifact_size_in_bytes": artifact.get("size_in_bytes"),
        "artifact_digest": api_digest,
        "artifact_zip_sha256": artifact_zip_sha256,
        "artifact_created_at": artifact.get("created_at"),
        "oidc_verified": True,
    }, []


# -----------------------------------------------------------------------------
# Core Signer Implementation
# -----------------------------------------------------------------------------
def load_measurement_artifact(
    zip_path: Path,
    *,
    expected_sha256: str | None = None,
    max_entry_bytes: int = 1_048_576,
    max_total_bytes: int = 4_194_304,
) -> tuple[bytes | None, bytes | None, list[str]]:
    """Read the exact two-file measurement artifact from an untrusted zip archive.

    The archive is treated strictly as data. Only the two expected top-level files
    are accepted; directories, symlinks, duplicate names, oversized entries and
    extra payloads are rejected before JSON parsing.
    """
    import zipfile

    errors: list[str] = []
    if not zip_path.is_file():
        return None, None, [f"measurement artifact archive not found: {zip_path}"]

    raw = zip_path.read_bytes()
    actual_sha256 = "sha256:" + hashlib.sha256(raw).hexdigest()
    if expected_sha256 and not hmac.compare_digest(expected_sha256, actual_sha256):
        return None, None, [
            f"measurement artifact digest mismatch: expected {expected_sha256}, computed {actual_sha256}"
        ]

    expected_names = {"measurements.json", "measurement_attestation.json"}
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = zf.infolist()
            names = [info.filename for info in infos]

            if len(names) != len(set(names)):
                errors.append("measurement artifact contains duplicate zip entries")
            unexpected = sorted(set(names) - expected_names)
            if unexpected:
                errors.append(f"measurement artifact contains unexpected entries: {unexpected}")
            missing = sorted(expected_names - set(names))
            if missing:
                errors.append(f"measurement artifact is missing required entries: {missing}")

            total_size = 0
            payloads: dict[str, bytes] = {}
            for info in infos:
                if info.is_dir() or info.filename not in expected_names:
                    continue
                if info.file_size <= 0:
                    errors.append(f"measurement artifact entry '{info.filename}' is empty")
                    continue
                if info.file_size > max_entry_bytes:
                    errors.append(
                        f"measurement artifact entry '{info.filename}' exceeds size limit ({info.file_size} bytes)"
                    )
                    continue
                total_size += info.file_size
                if total_size > max_total_bytes:
                    errors.append("measurement artifact exceeds total uncompressed size limit")
                    break
                payloads[info.filename] = zf.read(info)
    except zipfile.BadZipFile as exc:
        return None, None, [f"measurement artifact is not a valid zip archive: {exc}"]
    except Exception as exc:
        return None, None, [f"failed to read measurement artifact archive: {exc}"]

    if errors:
        return None, None, errors
    return payloads["measurements.json"], payloads["measurement_attestation.json"], []


def sign_release_evidence(
    root: Path,
    measurements_file: Path | None,
    attestation_file: Path | None,
    output_file: Path,
    signing_key_hex: str,
    *,
    source_root: Path | None = None,
    commit_sha: str | None = None,
    expected_measurement_run_id: str | None = None,
    expected_measurement_run_attempt: str | None = None,
    expected_artifact_id: int | None = None,
    expected_artifact_digest: str | None = None,
    artifact_zip: Path | None = None,
    trusted_measurement_workflow_sha: str | None = None,
    trusted_measurement_workflow_ref: str | None = None,
    trusted_signing_workflow_sha: str | None = None,
    trusted_signing_workflow_ref: str | None = None,
    custom_verifier: Any = None,
    custom_jwks: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate authenticated measurement provenance and issue authoritative Ed25519 attestation.

    In GitHub Actions this function never executes or imports candidate code. The
    candidate source tree is consumed only as data for fingerprint recomputation.
    """
    isolate_execution_environment(root)
    if "pytest" not in sys.modules:
        assert_no_repository_imports()
        verify_imported_module_origins(root)

    source_root = source_root or root
    artifact_zip_sha256: str | None = None

    # 1. Load the downloaded artifact archive (untrusted input, data only)
    if artifact_zip is not None:
        measurements_raw, attestation_raw, archive_errors = load_measurement_artifact(
            artifact_zip, expected_sha256=expected_artifact_digest
        )
        if archive_errors:
            return None, archive_errors
        assert measurements_raw is not None and attestation_raw is not None
        artifact_zip_sha256 = "sha256:" + hashlib.sha256(artifact_zip.read_bytes()).hexdigest()
        try:
            attestation = json.loads(attestation_raw.decode("utf-8"))
            measurement_record = json.loads(measurements_raw.decode("utf-8"))
        except Exception as exc:
            return None, [f"failed to parse measurement artifact JSON: {exc}"]
    else:
        if measurements_file is None or attestation_file is None:
            return None, ["measurement artifact archive or explicit measurement files are required"]
        if not attestation_file.is_file():
            return None, [f"measurement attestation file not found: {attestation_file}"]
        if not measurements_file.is_file():
            return None, [f"measurements file not found: {measurements_file}"]
        try:
            attestation = json.loads(attestation_file.read_text(encoding="utf-8"))
            measurements_raw = measurements_file.read_bytes()
            measurement_record = json.loads(measurements_raw.decode("utf-8"))
        except Exception as exc:
            return None, [f"failed to parse measurement artifact JSON: {exc}"]

    if not isinstance(attestation, dict):
        return None, ["measurement attestation root must be an object"]
    if not isinstance(measurement_record, dict):
        return None, ["measurements root must be an object"]

    if attestation.get("schema") != ATTESTATION_SCHEMA:
        return None, [f"unsupported attestation schema: {attestation.get('schema')}"]
    if attestation.get("issuer") != "verifyci.measurement_pipeline":
        return None, [f"unsupported attestation issuer: {attestation.get('issuer')}"]
    if measurement_record.get("schema") != MEASUREMENTS_SCHEMA:
        return None, [f"unsupported measurements schema: {measurement_record.get('schema')}"]

    # 2. Verify attestation binding to the exact measurement bytes
    computed_raw_sha256 = "sha256:" + hashlib.sha256(measurements_raw).hexdigest()
    computed_canonical_digest = (
        "sha256:" + hashlib.sha256(canonical_json_bytes(measurement_record)).hexdigest()
    )

    if not hmac.compare_digest(
        str(attestation.get("measurements_file_sha256", "")), computed_raw_sha256
    ):
        return None, [
            f"measurements artifact raw hash mismatch: attestation has {attestation.get('measurements_file_sha256')}, computed {computed_raw_sha256}"
        ]
    if not hmac.compare_digest(
        str(attestation.get("measurements_digest", "")), computed_canonical_digest
    ):
        return None, [
            f"measurements artifact canonical digest mismatch: attestation has {attestation.get('measurements_digest')}, computed {computed_canonical_digest}"
        ]

    # 3. Verify source fingerprint and corpus integrity against candidate data
    current_impl_fp = compute_implementation_fingerprint(source_root)
    if attestation.get("implementation_fingerprint") != current_impl_fp:
        return None, [
            f"implementation fingerprint mismatch: attestation has {attestation.get('implementation_fingerprint')}, candidate source has {current_impl_fp}"
        ]
    if measurement_record.get("implementation_fingerprint") != current_impl_fp:
        return None, [
            f"measurements record implementation fingerprint mismatch: record has {measurement_record.get('implementation_fingerprint')}, candidate source has {current_impl_fp}"
        ]

    corpus_errors = verify_security_corpus_sums(source_root)
    if corpus_errors:
        return None, corpus_errors

    commit_sha = (commit_sha or get_commit_sha(source_root) or "").lower()
    if not _is_full_sha(commit_sha):
        return None, ["unable to establish authoritative candidate commit SHA"]

    execution_info = attestation.get("execution", {})
    if not isinstance(execution_info, dict):
        return None, ["measurement attestation execution block is malformed"]
    att_commit = str(execution_info.get("commit_sha") or "").lower()
    if att_commit != commit_sha:
        return None, [
            f"commit SHA mismatch: attestation bound to {att_commit[:8]}, expected candidate is {commit_sha[:8]}"
        ]

    if attestation.get("manifest_hash") != PINNED_MANIFEST_HASH:
        return None, [
            f"manifest hash mismatch: attestation has {attestation.get('manifest_hash')}, expected {PINNED_MANIFEST_HASH}"
        ]

    # 4. Verify measurement metrics and thresholds
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

    # 5. Provenance authentication
    is_github_actions = os.environ.get("GITHUB_ACTIONS") == "true"

    if custom_verifier:
        provenance, prov_errors = custom_verifier(attestation)
        if prov_errors:
            return None, prov_errors
        if not isinstance(provenance, dict):
            return None, ["custom provenance verifier returned malformed provenance"]
    elif is_github_actions:
        if execution_info.get("ci_platform") != "github_actions":
            return None, [
                f"untrusted execution platform in CI environment: expected 'github_actions', got '{execution_info.get('ci_platform')}'"
            ]

        repo = os.environ.get("GITHUB_REPOSITORY")
        token = os.environ.get("GITHUB_TOKEN")
        signing_ref = os.environ.get("GITHUB_REF")
        signing_workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
        signing_workflow_sha = trusted_signing_workflow_sha or os.environ.get("GITHUB_WORKFLOW_SHA", "")
        signing_run_id = os.environ.get("GITHUB_RUN_ID", "")
        signing_run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")

        if not repo or not token:
            return None, ["missing GITHUB_REPOSITORY or GITHUB_TOKEN for GitHub Actions provenance check"]
        if repo.lower() != PINNED_REPOSITORY.lower():
            return None, [f"untrusted GitHub repository: expected '{PINNED_REPOSITORY}', got '{repo}'"]

        # The signing job itself must have run from the protected trusted ref.
        if signing_ref != PINNED_TRUSTED_REF:
            return None, [
                f"signing job ref is not the protected trusted ref: expected '{PINNED_TRUSTED_REF}', got '{signing_ref}'"
            ]
        expected_signing_path = f"{PINNED_REPOSITORY}/{PINNED_SIGNING_WORKFLOW_PATH}"
        parsed_signing_ref = _split_workflow_ref(signing_workflow_ref)
        if parsed_signing_ref is None or parsed_signing_ref[0].lower() != expected_signing_path.lower():
            return None, [
                f"signing workflow ref is not the trusted signing workflow: {signing_workflow_ref}"
            ]
        if parsed_signing_ref[1] != PINNED_TRUSTED_REF:
            return None, [
                f"signing workflow ref is not protected: {signing_workflow_ref}"
            ]
        if not _is_full_sha(signing_workflow_sha):
            return None, ["trusted signing workflow SHA is missing or malformed"]

        measurement_run_id = (
            expected_measurement_run_id
            or os.environ.get("VERIFYCI_MEASUREMENT_RUN_ID")
            or os.environ.get("GITHUB_RUN_ID")
        )
        measurement_run_attempt = (
            expected_measurement_run_attempt
            or os.environ.get("VERIFYCI_MEASUREMENT_RUN_ATTEMPT")
            or os.environ.get("GITHUB_RUN_ATTEMPT")
            or "1"
        )
        trusted_sha = trusted_measurement_workflow_sha or os.environ.get("VERIFYCI_TRUSTED_WORKFLOW_SHA")
        trusted_ref = trusted_measurement_workflow_ref or os.environ.get("VERIFYCI_TRUSTED_WORKFLOW_REF")

        if not measurement_run_id:
            return None, ["measurement workflow run ID is required for CI signing"]
        if execution_info.get("workflow_run_id") != str(measurement_run_id):
            return None, [
                f"workflow run ID mismatch: attestation has {execution_info.get('workflow_run_id')}, expected {measurement_run_id}"
            ]
        if execution_info.get("workflow_run_attempt") != str(measurement_run_attempt):
            return None, [
                f"workflow run attempt mismatch: attestation has {execution_info.get('workflow_run_attempt')}, expected {measurement_run_attempt}"
            ]
        if not _is_full_sha(trusted_sha):
            return None, ["trusted measurement workflow SHA is not pinned to a full commit SHA"]
        if trusted_ref is not None and trusted_ref != PINNED_TRUSTED_REF and not _is_full_sha(trusted_ref):
            return None, [f"trusted measurement workflow ref is malformed: {trusted_ref}"]

        candidate_ref = execution_info.get("ref")
        if not isinstance(candidate_ref, str) or not candidate_ref.startswith("refs/"):
            return None, ["measurement attestation is missing candidate ref binding"]

        workflow_ident = attestation.get("workflow_identity", {})
        if not isinstance(workflow_ident, dict):
            return None, ["measurement attestation workflow_identity is malformed"]
        oidc_tok = workflow_ident.get("oidc_token")
        if not oidc_tok:
            return None, ["measurement attestation missing required OIDC token in CI environment"]

        oidc_claims, oidc_errors = verify_github_oidc_token(
            oidc_tok,
            repo,
            commit_sha,
            str(measurement_run_id),
            str(measurement_run_attempt),
            expected_workflow_path=PINNED_MEASUREMENT_WORKFLOW_PATH,
            expected_workflow_sha=trusted_sha,
            expected_ref=candidate_ref,
            jwks=custom_jwks,
        )
        if oidc_errors or not oidc_claims:
            return None, [f"cryptographic OIDC verification failed: {e}" for e in oidc_errors]

        for claim_name, expected_value in (
            ("repository", repo),
            ("sha", commit_sha),
            ("run_id", str(measurement_run_id)),
            ("run_attempt", str(measurement_run_attempt)),
        ):
            claim_value = str(oidc_claims.get(claim_name, ""))
            if claim_name in ("repository", "sha"):
                claim_value = claim_value.lower()
                expected_value = expected_value.lower()
            if claim_value != expected_value:
                return None, [
                    f"OIDC {claim_name} mismatch: expected '{expected_value}', got '{claim_value}'"
                ]

        if artifact_zip is None or not artifact_zip_sha256:
            return None, ["CI signing requires a downloaded measurement artifact archive"]
        if expected_artifact_id is None:
            return None, ["expected measurement artifact ID is required for CI signing"]
        if not expected_artifact_digest:
            return None, ["expected measurement artifact digest is required for CI signing"]

        provenance, prov_errors = verify_github_actions_provenance(
            repo,
            str(measurement_run_id),
            str(measurement_run_attempt),
            commit_sha,
            token,
            expected_ref=candidate_ref,
            expected_artifact_id=expected_artifact_id,
            expected_artifact_digest=expected_artifact_digest,
            artifact_zip_sha256=artifact_zip_sha256,
        )
        if prov_errors:
            return None, prov_errors
        if provenance["candidate_ref"] != candidate_ref:
            return None, [
                f"provenance ref mismatch: expected '{candidate_ref}', got '{provenance['candidate_ref']}'"
            ]

        provenance["commit_sha"] = commit_sha
        provenance["measurement_workflow_ref"] = oidc_claims["job_workflow_ref"]
        provenance["measurement_workflow_sha"] = oidc_claims["job_workflow_sha"]
        provenance["trusted_signing_workflow_ref"] = signing_workflow_ref
        provenance["trusted_signing_workflow_sha"] = signing_workflow_sha
        provenance["trusted_signing_ref"] = signing_ref
        provenance["trusted_signing_run_id"] = str(signing_run_id)
        provenance["trusted_signing_run_attempt"] = str(signing_run_attempt)
        provenance["verified_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    else:
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

    # 6. Generate authoritative release-validation record
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
        if "pytest" not in sys.modules:
            verify_imported_module_origins(root)
        from cryptography.hazmat.primitives.asymmetric import ed25519
        if "pytest" not in sys.modules:
            verify_imported_module_origins(root)

        priv_bytes = bytes.fromhex(signing_key_hex.strip())
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        signature = priv.sign(digest.encode("utf-8")).hex()
    except Exception as exc:
        return None, [f"failed to compute Ed25519 signature with release authority: {exc}"]

    payload_body["attestation"]["digest"] = digest
    payload_body["attestation"]["signature"] = signature

    # Persist the exact validated artifact bytes alongside the signed evidence so
    # the uploaded evidence bundle is the measured payload, not stale checkout data.
    if artifact_zip is not None:
        evidence_dir = root / "evidence" / "release"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "measurements.json").write_bytes(measurements_raw)
        (evidence_dir / "measurement_attestation.json").write_bytes(attestation_raw)

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
        help="Path to verified measurements JSON (ignored when --artifact-zip is supplied)",
    )
    parser.add_argument(
        "--attestation",
        type=Path,
        default=ROOT / "evidence" / "release" / "measurement_attestation.json",
        help="Path to signed measurement attestation JSON (ignored when --artifact-zip is supplied)",
    )
    parser.add_argument(
        "--artifact-zip",
        type=Path,
        default=Path(os.environ["VERIFYCI_ARTIFACT_ZIP"]) if os.environ.get("VERIFYCI_ARTIFACT_ZIP") else None,
        help="Downloaded GitHub Actions measurement artifact archive (untrusted data)",
    )
    parser.add_argument(
        "--artifact-id",
        type=int,
        default=int(os.environ["VERIFYCI_ARTIFACT_ID"]) if os.environ.get("VERIFYCI_ARTIFACT_ID") else None,
        help="Expected GitHub Actions measurement artifact ID",
    )
    parser.add_argument(
        "--artifact-digest",
        default=os.environ.get("VERIFYCI_ARTIFACT_DIGEST"),
        help="Expected GitHub Actions artifact digest (sha256:...)",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path(os.environ["VERIFYCI_SOURCE_ROOT"]) if os.environ.get("VERIFYCI_SOURCE_ROOT") else None,
        help="Candidate source tree consumed as data for fingerprint verification",
    )
    parser.add_argument(
        "--commit-sha",
        default=os.environ.get("VERIFYCI_COMMIT_SHA"),
        help="Expected candidate commit SHA",
    )
    parser.add_argument(
        "--measurement-run-id",
        default=os.environ.get("VERIFYCI_MEASUREMENT_RUN_ID"),
        help="GitHub Actions measurement workflow run ID",
    )
    parser.add_argument(
        "--measurement-run-attempt",
        default=os.environ.get("VERIFYCI_MEASUREMENT_RUN_ATTEMPT"),
        help="GitHub Actions measurement workflow run attempt",
    )
    parser.add_argument(
        "--trusted-workflow-sha",
        default=os.environ.get("VERIFYCI_TRUSTED_WORKFLOW_SHA"),
        help="Immutable commit SHA of the trusted measurement workflow",
    )
    parser.add_argument(
        "--trusted-workflow-ref",
        default=os.environ.get("VERIFYCI_TRUSTED_WORKFLOW_REF"),
        help="Protected ref of the trusted measurement workflow",
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
        source_root=args.source_root,
        commit_sha=args.commit_sha,
        expected_measurement_run_id=args.measurement_run_id,
        expected_measurement_run_attempt=args.measurement_run_attempt,
        expected_artifact_id=args.artifact_id,
        expected_artifact_digest=args.artifact_digest,
        artifact_zip=args.artifact_zip,
        trusted_measurement_workflow_sha=args.trusted_workflow_sha,
        trusted_measurement_workflow_ref=args.trusted_workflow_ref,
    )
    if errors or not record:
        print("Release blocked: provenance or measurement verification failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    report = {
        "artifact_digest": record.get("provenance", {}).get("artifact_digest"),
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
