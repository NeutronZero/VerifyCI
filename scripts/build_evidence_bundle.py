#!/usr/bin/env python3
"""Builds and anchors the canonical RFC 8785 source-bound evidence bundle for VerifyCI v3.1."""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

from verifyci.contracts.manifest import manifest_hash
from verifyci.contracts.model import Verdict, VerdictResult
from verifyci.evidence.bundle import build_bundle, build_payload, toolchain_fingerprint
from verifyci.evidence.canonical import canonical_json_bytes


def _git(*args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except Exception:
        return ""


def main() -> int:
    evidence_dir = Path("evidence")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = evidence_dir / "evidence-bundle.json"

    # Git repository inspection for source binding
    commit_sha = os.environ.get("GITHUB_SHA") or _git("rev-parse", "HEAD") or "unknown"
    branch_ref = os.environ.get("GITHUB_REF_NAME") or _git("rev-parse", "--abbrev-ref", "HEAD") or "unknown"
    git_status = _git("status", "--porcelain")
    tree_clean = len(git_status) == 0
    git_ver = _git("--version")

    # Run the v3 test suite first to ensure gate integrity
    started = time.monotonic()
    test_proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/v3/", "-q"],
        capture_output=True,
        text=True,
    )
    duration_ms = int((time.monotonic() - started) * 1000)

    if test_proc.returncode != 0:
        print("Tests failed:\n", test_proc.stderr or test_proc.stdout)
        return test_proc.returncode

    test_digest = "sha256:" + sha256(test_proc.stdout.encode("utf-8")).hexdigest()
    toolchain = toolchain_fingerprint(git_version=git_ver)

    # Build schema-conforming source-bound payload
    payload = build_payload(
        inputs={
            "milestone": "M0",
            "commit_sha": commit_sha,
            "branch_ref": branch_ref,
            "test_digest": test_digest,
            "tree_clean": tree_clean,
            "release_validated": False,
        },
        scope={
            "test_suite": "tests/v3/",
            "tree_clean": tree_clean,
        },
        check_results=[],
        findings=[],
        waivers=[],
        accepted_gaps=[],
        diagnostics=[],
        assumptions=[
            {
                "id": "release_validation_not_established",
                "detail": "this build is an implementation candidate, not a release-validated artifact",
            },
            {
                "id": "m0_verification_record",
                "detail": "source-bound verification record demonstrating v3 gate infrastructure",
            },
        ],
        excluded_scope=[],
        verdict=VerdictResult(
            status=Verdict.PASS if test_proc.returncode == 0 else Verdict.FAIL,
            exit_code=test_proc.returncode,
            blocking_findings_present=False,
        ),
        toolchain=toolchain,
        policy={},
        gate_integrity={
            "clean": tree_clean,
            "source_bound_commit": commit_sha,
            "branch_ref": branch_ref,
            "release_validated": False,
        },
        manifest_extra={
            "release_validated": False,
            "source_bound_commit": commit_sha,
            "test_digest": test_digest,
        },
    )

    bundle = build_bundle(
        payload,
        duration_ms=duration_ms,
        environment={
            "python": platform.python_version(),
            "platform": platform.system(),
            "machine": platform.machine(),
            "git": git_ver,
            "commit_sha": commit_sha,
            "branch_ref": branch_ref,
        },
    )

    bundle_dict = bundle.to_dict()
    bundle_bytes = canonical_json_bytes(bundle_dict)
    bundle_path.write_bytes(bundle_bytes)

    envelope = bundle_dict["envelope"]
    print(f"Evidence bundle written to {bundle_path}")
    print(f"  Commit:    {commit_sha} ({branch_ref})")
    print(f"  Payload:   {envelope['payload_hash']}")
    print(f"  Toolchain: {toolchain}")
    print(f"  Manifest:  {manifest_hash()}")
    print(f"  Duration:  {duration_ms}ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
