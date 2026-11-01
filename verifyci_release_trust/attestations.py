"""Cryptographic Verification of OCI Image Provenance and GitHub Actions OIDC (§15.10 Components A & E).

Provides independent verification of:
1. Signed GitHub Artifact Attestations for worker container images.
2. Signed GitHub Actions RS256 OIDC tokens for trusted attestation jobs.
3. Check-run record associations and historical issuance timing boundaries.
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from typing import Any, NamedTuple
import urllib.request


class OIDCTokenClaims(NamedTuple):
    header: dict[str, Any]
    claims: dict[str, Any]
    raw_jwt: str
    jwt_sha256: str
    jti: str
    iat: int
    exp: int
    check_run_id: str
    job_workflow_sha: str
    job_workflow_ref: str
    workflow_sha: str
    workflow_ref: str


def fetch_github_jwks(timeout: int = 15) -> dict[str, Any]:
    url = "https://token.actions.githubusercontent.com/.well-known/jwks"
    req = urllib.request.Request(url, headers={"User-Agent": "VerifyCI-TrustVerifier"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_and_verify_oidc_token(
    raw_jwt: str,
    jwks: dict[str, Any] | None = None,
    *,
    expected_repo: str,
    expected_repo_id: str,
    expected_candidate_sha: str,
    expected_reusable_workflow_sha: str,
    expected_caller_workflow_sha: str,
    expected_run_id: str,
    expected_run_attempt: str,
    expected_check_run_id: str,
    job_started_at: float | None = None,
    job_completed_at: float | None = None,
    artifact_created_at: float | None = None,
) -> tuple[OIDCTokenClaims | None, list[str]]:
    """Cryptographically verify OIDC token against GitHub JWKS and validate all claims."""
    errors: list[str] = []
    parts = raw_jwt.strip().split(".")
    if len(parts) != 3:
        return None, ["malformed JWT: expected 3 dot-separated segments"]

    header_b64, payload_b64, sig_b64 = parts

    def _b64decode(seg: str) -> bytes:
        padded = seg + "=" * ((4 - len(seg) % 4) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))

    try:
        header = json.loads(_b64decode(header_b64).decode("utf-8"))
        claims = json.loads(_b64decode(payload_b64).decode("utf-8"))
        sig_bytes = _b64decode(sig_b64)
    except Exception as exc:
        return None, [f"failed to decode JWT segments: {exc}"]

    # 1. Verify RS256 signature using JWKS
    kid = header.get("kid")
    if not kid:
        return None, ["JWT header missing 'kid'"]
    if header.get("alg") != "RS256":
        return None, [f"unsupported JWT alg: {header.get('alg')}"]

    active_jwks = jwks or fetch_github_jwks()
    key_entry = next((k for k in active_jwks.get("keys", []) if k.get("kid") == kid), None)
    if not key_entry:
        return None, [f"signing key ID '{kid}' not found in GitHub JWKS"]

    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa

        def _b64_int(s: str) -> int:
            return int.from_bytes(_b64decode(s), "big")

        pub_num = rsa.RSAPublicNumbers(e=_b64_int(key_entry["e"]), n=_b64_int(key_entry["n"]))
        pub_key = pub_num.public_key()
        signed_data = f"{header_b64}.{payload_b64}".encode("ascii")
        pub_key.verify(sig_bytes, signed_data, padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        return None, [f"cryptographic signature verification failed: {exc}"]

    # 2. Claims validation
    if claims.get("iss") != "https://token.actions.githubusercontent.com":
        errors.append(f"invalid issuer: {claims.get('iss')}")
    if claims.get("aud") != "verifyci-release-authority":
        errors.append(f"invalid audience: {claims.get('aud')}")

    if claims.get("repository", "").lower() != expected_repo.lower():
        errors.append(f"repository mismatch: expected '{expected_repo}', got '{claims.get('repository')}'")
    if str(claims.get("repository_id", "")) != str(expected_repo_id):
        errors.append(f"repository_id mismatch: expected '{expected_repo_id}', got '{claims.get('repository_id')}'")

    if claims.get("sha", "").lower() != expected_candidate_sha.lower():
        errors.append(f"candidate SHA mismatch: expected '{expected_candidate_sha}', got '{claims.get('sha')}'")

    if str(claims.get("run_id", "")) != str(expected_run_id):
        errors.append(f"run_id mismatch: expected '{expected_run_id}', got '{claims.get('run_id')}'")
    if str(claims.get("run_attempt", "")) != str(expected_run_attempt):
        errors.append(f"run_attempt mismatch: expected '{expected_run_attempt}', got '{claims.get('run_attempt')}'")

    cand_check_run_id = str(claims.get("check_run_id", ""))
    if cand_check_run_id != str(expected_check_run_id):
        errors.append(f"check_run_id mismatch: expected '{expected_check_run_id}', got '{cand_check_run_id}'")

    job_wf_sha = claims.get("job_workflow_sha", "").lower()
    if job_wf_sha != expected_reusable_workflow_sha.lower():
        errors.append(f"job_workflow_sha mismatch: expected '{expected_reusable_workflow_sha}', got '{job_wf_sha}'")

    caller_wf_sha = claims.get("workflow_sha", "").lower()
    if caller_wf_sha != expected_caller_workflow_sha.lower():
        errors.append(f"caller workflow_sha mismatch: expected '{expected_caller_workflow_sha}', got '{caller_wf_sha}'")

    # 3. Temporal boundaries
    nbf = int(claims.get("nbf", 0))
    iat = int(claims.get("iat", 0))
    exp = int(claims.get("exp", 0))
    jti = str(claims.get("jti", ""))

    if not (nbf <= iat <= exp):
        errors.append(f"invalid token temporal claims: nbf={nbf}, iat={iat}, exp={exp}")

    if job_started_at is not None and job_completed_at is not None:
        if iat < (job_started_at - 30) or iat > (job_completed_at + 30):
            errors.append(f"token iat {iat} outside job execution window [{job_started_at - 30}, {job_completed_at + 30}]")

    if artifact_created_at is not None:
        if artifact_created_at < (exp + 60):
            errors.append(f"attestation artifact created before expiration safe margin (created_at {artifact_created_at} < exp+60 {exp + 60})")

    if errors:
        return None, errors

    jwt_sha256 = "sha256:" + hashlib.sha256(raw_jwt.encode("ascii")).hexdigest()

    return OIDCTokenClaims(
        header=header,
        claims=claims,
        raw_jwt=raw_jwt,
        jwt_sha256=jwt_sha256,
        jti=jti,
        iat=iat,
        exp=exp,
        check_run_id=cand_check_run_id,
        job_workflow_sha=job_wf_sha,
        job_workflow_ref=claims.get("job_workflow_ref", ""),
        workflow_sha=caller_wf_sha,
        workflow_ref=claims.get("workflow_ref", ""),
    ), []


def verify_image_attestation_cli(
    image_uri: str,
    expected_image_digest: str,
    expected_builder_workflow_sha: str,
    expected_source_commit: str,
) -> tuple[bool, str | None]:
    """Execute gh attestation verify on OCI image and parse structured JSON result."""
    cmd = [
        "gh", "attestation", "verify",
        image_uri,
        "--owner", "NeutronZero",
        "--format", "json",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return False, f"gh attestation verify failed (exit {proc.returncode}): {proc.stderr.strip()}"
        records = json.loads(proc.stdout)
        if not isinstance(records, list) or not records:
            return False, "empty attestation record list"

        matched = False
        clean_digest = expected_image_digest.removeprefix("sha256:").lower()
        for rec in records:
            stmt = rec.get("verificationResult", {}).get("statement", {})
            pred = stmt.get("predicate", {})
            subjects = stmt.get("subject", [])
            has_sub = any(
                str(s.get("digest", {}).get("sha256", "")).lower() == clean_digest for s in subjects
            )
            if not has_sub:
                continue

            wf_sha = (
                pred.get("buildDefinition", {})
                .get("internalParameters", {})
                .get("workflow", {})
                .get("sha", "")
                .lower()
            )
            if wf_sha != expected_builder_workflow_sha.lower():
                continue

            deps = pred.get("buildDefinition", {}).get("resolvedDependencies", [])
            src_dep = next((d for d in deps if d.get("uri", "").endswith("/VerifyCI")), None)
            if not src_dep:
                continue
            git_commit = str(src_dep.get("digest", {}).get("gitCommit", "")).lower()
            if git_commit != expected_source_commit.lower():
                continue

            matched = True
            break

        if not matched:
            return False, "no attestation record matched image digest, builder SHA, and Commit A"
        return True, None
    except Exception as exc:
        return False, f"image attestation verification exception: {exc}"


def verify_attestation_timing_window(
    published_at_iso: str,
    jwt_exp: int,
    min_delay_seconds: int = 60,
) -> tuple[bool, list[str]]:
    """Verify that attestation was published strictly after jwt_exp + min_delay_seconds."""
    import datetime
    try:
        dt = datetime.datetime.fromisoformat(published_at_iso)
        published_ts = dt.timestamp()
    except Exception as exc:
        return False, [f"invalid publication timestamp format: {exc}"]

    required_ts = jwt_exp + min_delay_seconds
    if published_ts < required_ts:
        return False, [
            f"attestation published before mandatory delay: published at {published_ts}, required >= {required_ts}"
        ]
    return True, []
