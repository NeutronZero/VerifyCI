#!/usr/bin/env python3
"""Authoritative Attestation Generator for VerifyCI (§15.10 Component 6.3 Job 2).

Executed strictly in the trusted-attestation job (zero candidate code execution).
Validates measurement job provenance, computes artifact digests, acquires GitHub OIDC token,
waits until token expiration + 60s safety margin, and emits measurement_attestation.json.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import sys
import time
import urllib.request

from verifyci import __version__ as TOOL_VERSION
from verifyci_release_trust.evidence import (
    canonical_jcs_digest,
    compute_file_sha256,
)


def _api_get(url: str, token: str) -> dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "VerifyCI-AttestationGenerator",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_args():
    parser = argparse.ArgumentParser(description="Generate authenticated release attestation")
    parser.add_argument("--candidate-sha", required=True, help="Candidate commit SHA")
    parser.add_argument("--measurement-run-id", default=os.environ.get("GITHUB_RUN_ID"), help="GitHub Actions run ID for measurements")
    parser.add_argument("--measurement-run-attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT", "1"), help="Measurement run attempt")
    parser.add_argument("--measurements", "--measurements-file", dest="measurements_file", type=Path, default=Path("evidence/release/measurements.json"))
    parser.add_argument("--output", "--output-attestation", dest="output_attestation", type=Path, default=Path("evidence/release/measurement_attestation.json"))
    return parser.parse_args()


def main():
    args = parse_args()
    cand_sha = args.candidate_sha.lower()
    if len(cand_sha) != 40 or any(c not in "0123456789abcdef" for c in cand_sha):
        sys.exit(f"invalid candidate SHA: {cand_sha}")

    if not args.measurements_file.is_file():
        sys.exit(f"measurements file missing: {args.measurements_file}")

    # Compute raw file SHA256 and canonical JCS digest
    raw_measurements = args.measurements_file.read_bytes()
    raw_file_sha256 = compute_file_sha256(args.measurements_file)
    parsed_measurements = json.loads(raw_measurements.decode("utf-8"))
    canonical_digest = canonical_jcs_digest(parsed_measurements)

    # In CI, verify via GitHub Actions API and acquire OIDC token
    gh_token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY", "NeutronZero/VerifyCI")
    is_ci = os.environ.get("GITHUB_ACTIONS") == "true"

    measurement_job_id = None
    measurement_check_run_id = None
    measurement_artifact_id = None
    measurement_artifact_digest = None
    attestation_check_run_id = None
    oidc_token = None
    caller_sha = None

    if is_ci and gh_token:
        if not args.measurement_run_id:
            sys.exit("measurement run ID missing in CI environment")

        # Query jobs for measurement run
        jobs_url = f"https://api.github.com/repos/{repo}/actions/runs/{args.measurement_run_id}/jobs?attempt={args.measurement_run_attempt}"
        jobs_data = _api_get(jobs_url, gh_token)
        jobs = jobs_data.get("jobs", [])
        m_job = next((j for j in jobs if j.get("name") in ("verifyci-measurements", "trusted-measurements / verifyci-measurements")), None)
        if not m_job:
            sys.exit(f"measurement job not found in run {args.measurement_run_id}")
        if m_job.get("status") != "completed" or m_job.get("conclusion") != "success":
            sys.exit(f"measurement job failed or not completed: status={m_job.get('status')}, conclusion={m_job.get('conclusion')}")

        # In manual-dispatch, m_job.head_sha is the caller commit on release-authority,
        # while parsed_measurements records the measured candidate_sha.
        m_rec_cand_sha = parsed_measurements.get("candidate_sha", "").lower()
        if m_rec_cand_sha and m_rec_cand_sha != cand_sha:
            sys.exit(f"measurement record candidate_sha mismatch: {m_rec_cand_sha} != {cand_sha}")
        caller_sha = m_job.get("head_sha", "").lower()

        measurement_job_id = m_job.get("id")
        measurement_check_run_id = m_job.get("check_run_url", "").split("/")[-1] if m_job.get("check_run_url") else None

        # Query artifact metadata
        arts_url = f"https://api.github.com/repos/{repo}/actions/runs/{args.measurement_run_id}/artifacts"
        arts_data = _api_get(arts_url, gh_token)
        m_art = next((a for a in arts_data.get("artifacts", []) if a.get("name") == "release-measurements"), None)
        if not m_art:
            sys.exit("release-measurements artifact not found in run")
        measurement_artifact_id = m_art.get("id")
        measurement_artifact_digest = m_art.get("digest")

        # Acquire OIDC Token
        id_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
        id_req_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        if not id_url or not id_req_token:
            sys.exit("OIDC token request credentials missing from environment")

        req = urllib.request.Request(
            f"{id_url}&audience=verifyci-release-authority",
            headers={"Authorization": f"Bearer {id_req_token}"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            oidc_token = data.get("value")

        if not oidc_token:
            sys.exit("failed to acquire GitHub OIDC token")

        # Parse unverified token claims
        parts = oidc_token.split(".")
        if len(parts) == 3:
            padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
            claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
            attestation_check_run_id = str(claims.get("check_run_id", ""))
            exp = int(claims.get("exp", 0))

            # Delay publication until exp + 60s
            now = time.time()
            if now < (exp + 60):
                wait_sec = int((exp + 60) - now) + 1
                sys.stderr.write(f"Sleeping {wait_sec}s until OIDC token expires with safety margin...\n")
                time.sleep(wait_sec)

    created_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    impl_fp = (
        parsed_measurements.get("candidate_implementation_fingerprint")
        or parsed_measurements.get("implementation_fingerprint")
    )
    manifest_h = parsed_measurements.get("manifest_hash")

    attestation_record = {
        "schema": "verifyci.measurement_attestation/v3",
        "issuer": "verifyci.measurement_pipeline",
        "tool_version": TOOL_VERSION,
        "created_at": created_iso,
        "candidate_sha": cand_sha,
        "caller_workflow_sha": caller_sha,
        "implementation_fingerprint": impl_fp,
        "manifest_hash": manifest_h,
        "measurement_run_id": str(args.measurement_run_id) if args.measurement_run_id else None,
        "measurement_run_attempt": str(args.measurement_run_attempt),
        "measurement_job_id": measurement_job_id,
        "measurement_check_run_id": str(measurement_check_run_id) if measurement_check_run_id else None,
        "measurement_artifact_id": measurement_artifact_id,
        "measurement_artifact_digest": measurement_artifact_digest,
        "measurements_file_sha256": raw_file_sha256,
        "measurements_canonical_digest": canonical_digest,
        "measurements_digest": canonical_digest,
        "attestation_check_run_id": attestation_check_run_id,
        "raw_oidc_jwt": oidc_token,
        "execution": {
            "ci_platform": "github_actions" if is_ci else "local",
            "workflow_run_id": str(args.measurement_run_id) if args.measurement_run_id else None,
            "workflow_run_attempt": str(args.measurement_run_attempt),
            "commit_sha": cand_sha,
        },
        "workflow_identity": {
            "platform": "github_actions" if is_ci else "local",
            "repository": repo,
            "commit_sha": cand_sha,
            "oidc_token": oidc_token,
        },
    }

    args.output_attestation.parent.mkdir(parents=True, exist_ok=True)
    tmp_out = args.output_attestation.with_name(f"{args.output_attestation.name}.tmp.{os.getpid()}")
    tmp_out.write_text(json.dumps(attestation_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp_out, args.output_attestation)
    sys.stdout.write("SUCCESS: measurement attestation emitted\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
