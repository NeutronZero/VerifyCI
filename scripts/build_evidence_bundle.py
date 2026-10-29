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
import xml.etree.ElementTree as ET

from verifyci.contracts.manifest import manifest_hash
from verifyci.contracts.model import Verdict, VerdictResult
from verifyci.contracts.release_validation import verify_release_validation_evidence
from verifyci.evidence.bundle import build_bundle, build_payload, toolchain_fingerprint
from verifyci.evidence.canonical import canonical_json_bytes


def _git(*args: str) -> str:
    """Execute a git command with fail-closed provenance verification."""
    proc = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Git command failed (exit code {proc.returncode}): git {' '.join(args)}\n"
            f"stderr: {proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def main() -> int:
    evidence_dir = Path("evidence")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = evidence_dir / "evidence-bundle.json"
    xml_report_path = evidence_dir / "m0-junit-report.xml"

    # Fail-closed git provenance collection
    git_head = _git("rev-parse", "HEAD")
    env_sha = os.environ.get("GITHUB_SHA")
    if env_sha and git_head and env_sha != git_head:
        raise RuntimeError(
            f"Commit SHA mismatch: GITHUB_SHA ({env_sha}) does not match HEAD ({git_head})"
        )
    commit_sha = env_sha or git_head
    if not commit_sha:
        raise RuntimeError("Failed to resolve commit SHA for evidence provenance")

    branch_ref = os.environ.get("GITHUB_REF_NAME") or _git("rev-parse", "--abbrev-ref", "HEAD")
    if not branch_ref:
        raise RuntimeError("Failed to resolve branch reference for evidence provenance")

    git_status = _git("status", "--porcelain")
    uncommitted = [
        line
        for line in git_status.splitlines()
        if line.strip()
        and not line.strip().endswith("evidence/release/release_validation.json")
    ]
    if uncommitted:
        raise RuntimeError(
            f"Working tree is dirty; strict source-to-commit binding requires a clean tree.\n"
            f"Uncommitted changes:\n{chr(10).join(uncommitted)}"
        )

    git_ver = _git("--version")
    if not git_ver:
        raise RuntimeError("Failed to determine git version for toolchain fingerprint")

    # Run the v3 test suite first to ensure gate integrity and produce structured report
    started = time.monotonic()
    test_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/v3/",
            "-q",
            f"--junitxml={xml_report_path}",
        ],
        capture_output=True,
        text=True,
    )
    duration_ms = int((time.monotonic() - started) * 1000)

    if not xml_report_path.exists():
        print("Test execution failed to produce a structured report:\n", test_proc.stderr or test_proc.stdout)
        return test_proc.returncode if test_proc.returncode != 0 else 1

    # Parse normalized test report for reproducible hashing
    try:
        tree = ET.parse(xml_report_path)
        root = tree.getroot()
        cases: list[dict[str, str]] = []
        for tc in root.iter("testcase"):
            name = tc.attrib.get("name", "")
            classname = tc.attrib.get("classname", "")
            status = "PASSED"
            if tc.find("failure") is not None:
                status = "FAILED"
            elif tc.find("error") is not None:
                status = "ERROR"
            elif tc.find("skipped") is not None:
                status = "SKIPPED"
            cases.append({"id": f"{classname}::{name}", "status": status})
        cases.sort(key=lambda x: x["id"])

        total_tests = len(cases)
        total_passed = sum(1 for c in cases if c["status"] == "PASSED")
        total_failed = sum(1 for c in cases if c["status"] in ("FAILED", "ERROR"))
        total_skipped = sum(1 for c in cases if c["status"] == "SKIPPED")
    finally:
        xml_report_path.unlink(missing_ok=True)

    if test_proc.returncode != 0 or total_failed > 0:
        print("Tests failed:\n", test_proc.stderr or test_proc.stdout)
        return test_proc.returncode if test_proc.returncode != 0 else 1

    test_report = {
        "total": total_tests,
        "passed": total_passed,
        "failed": total_failed,
        "skipped": total_skipped,
        "tests": cases,
    }
    test_digest = "sha256:" + sha256(canonical_json_bytes(test_report)).hexdigest()
    toolchain = toolchain_fingerprint(git_version=git_ver)

    # Authoritative release validation check
    is_release_validated, val_diag = verify_release_validation_evidence()

    # Build schema-conforming source-bound payload explicitly identifying this
    # as an M0 test-verification record rather than a PR gate diff verdict.
    payload = build_payload(
        inputs={
            "record_type": "m0_test_verification_record",
            "evaluation_type": "test_suite_execution",
            "gate_evaluation": False,
            "milestone": "M0",
            "commit_sha": commit_sha,
            "branch_ref": branch_ref,
            "test_digest": test_digest,
            "test_summary": {
                "total": total_tests,
                "passed": total_passed,
                "failed": total_failed,
                "skipped": total_skipped,
            },
            "tree_clean": tree_clean,
            "release_validated": is_release_validated,
        },
        scope={
            "record_type": "m0_test_verification_record",
            "evaluation_type": "test_suite_execution",
            "test_suite": "tests/v3/",
            "gate_diff_evaluated": False,
            "checks_executed": [],
            "tree_clean": tree_clean,
            "test_count": total_tests,
            "test_passed": total_passed,
        },
        check_results=[],
        findings=[],
        waivers=[],
        accepted_gaps=[],
        diagnostics=[],
        assumptions=[
            {
                "id": "not_a_gate_verdict",
                "detail": (
                    "this record validates M0 test-suite passing status and toolchain state; "
                    "it is NOT a VerifyCI pull-request gate evaluation or code review verdict"
                ),
            },
            (
                {
                    "id": "release_validation_established",
                    "detail": "this build is release-validated by authoritative §15.10 attestation",
                }
                if is_release_validated
                else {
                    "id": "release_validation_not_established",
                    "detail": f"this build is an implementation candidate, not a release-validated artifact ({val_diag})",
                }
            ),
            {
                "id": "m0_verification_record",
                "detail": "source-bound verification record demonstrating v3 gate infrastructure",
            },
        ],
        excluded_scope=[],
        verdict=VerdictResult(
            status=Verdict.PASS,
            exit_code=0,
            blocking_findings_present=False,
        ),
        toolchain=toolchain,
        policy={},
        gate_integrity={
            "clean": tree_clean,
            "source_bound_commit": commit_sha,
            "branch_ref": branch_ref,
            "gate_evaluation": False,
            "evaluation_target": "test_suite_only",
            "release_validated": is_release_validated,
        },
        manifest_extra={
            "record_type": "m0_test_verification_record",
            "release_validated": is_release_validated,
            "source_bound_commit": commit_sha,
            "test_digest": test_digest,
        },
    )

    # Annotate payload dictionary to guarantee consumer clarity
    payload["record_type"] = "m0_test_verification_record"
    payload["verdict"]["evaluation_target"] = "test_suite_only"
    payload["verdict"]["is_gate_evaluation"] = False

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
            "record_type": "m0_test_verification_record",
        },
    )

    bundle_dict = bundle.to_dict()
    bundle_bytes = canonical_json_bytes(bundle_dict)
    bundle_path.write_bytes(bundle_bytes)

    envelope = bundle_dict["envelope"]
    print(f"Evidence bundle written to {bundle_path}")
    print("  Record Type: m0_test_verification_record (not a gate verdict)")
    print(f"  Commit:      {commit_sha} ({branch_ref})")
    print(f"  Payload:     {envelope['payload_hash']}")
    print(f"  Toolchain:   {toolchain}")
    print(f"  Test Digest: {test_digest} ({total_passed}/{total_tests} passed)")
    print(f"  Manifest:    {manifest_hash()}")
    print(f"  Duration:    {duration_ms}ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
