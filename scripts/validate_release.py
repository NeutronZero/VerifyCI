#!/usr/bin/env python3
"""Authoritative release-validation pipeline for VerifyCI v3 (§15.10).

Executes independent measurement verification, checks frozen corpora integrity,
validates manifest and promotion chains, executes the frozen security corpus
benchmark and full test suite, verifies all defect metrics, and cryptographically
binds the authenticated attestation to the git commit, toolchain, and implementation fingerprint.

Security Architecture:
- Benchmark execution and test suite execution run in isolated subprocesses with
  VERIFYCI_RELEASE_SIGNING_KEY scrubbed from the process environment.
- Supports decoupled operation:
    --measure-only: Executes preflight, benchmark, and test suites unprivileged, emitting verified measurements.
    --sign-only: Consumes verified measurements and applies Ed25519 signature in a protected release environment
                 without executing candidate benchmark or test code while holding the signing key.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))


def verify_security_corpus_sums(root: Path) -> list[str]:
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
        if actual_hash != expected_hash.strip():
            errors.append(f"corpus checksum mismatch for {rel_name}")
    return errors


def verify_corpus_cases(root: Path) -> list[str]:
    errors = []
    cases_file = root / "corpora" / "security" / "cases.jsonl"
    if not cases_file.is_file():
        return ["corpora/security/cases.jsonl is missing"]
    seen_ids = set()
    defect_families = set()
    for line in cases_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            case = json.loads(line)
            cid = case.get("case_id")
            if not cid or cid in seen_ids:
                errors.append(f"invalid or duplicate case_id: {cid}")
            seen_ids.add(cid)
            for f in case.get("expected", {}).get("findings", []):
                if "defect_id" in f:
                    defect_families.add(f["defect_id"])
        except Exception as exc:
            errors.append(f"malformed JSON in cases.jsonl: {exc}")
    if len(seen_ids) < 22:
        errors.append(f"expected at least 22 security cases, found {len(seen_ids)}")
    from verifyci_release_trust.evaluator import REQUIRED_DEFECT_FAMILIES

    required_defects = set(REQUIRED_DEFECT_FAMILIES)
    missing_defects = required_defects - defect_families
    if missing_defects:
        errors.append(f"security corpus missing defect families: {missing_defects}")
    return errors


def _run_benchmark_cases(root: Path) -> tuple[dict[str, Any] | None, list[str]]:
    """Internal benchmark evaluation engine.

    Security Constraint:
    Must execute strictly in an isolated worker process without access to signing credentials.
    """
    if os.environ.get("VERIFYCI_RELEASE_SIGNING_KEY"):
        raise RuntimeError("Security violation: VERIFYCI_RELEASE_SIGNING_KEY leaked into benchmark runner")

    errors = []
    if str(root) in sys.path:
        sys.path.remove(str(root))
    sys.path.insert(0, str(root))
    import importlib

    benchmark_mod = importlib.import_module("tests.v3.test_security_benchmark")
    _execute_case = benchmark_mod._execute_case
    load_security_cases = benchmark_mod.load_security_cases

    tmp_dir = Path(tempfile.mkdtemp(prefix="vc_bench_"))
    try:
        cases = load_security_cases()
    except Exception as exc:
        return None, [f"failed to load security cases: {exc}"]

    if len(cases) < 22:
        return None, [f"expected 22 security benchmark cases, got {len(cases)}"]

    from verifyci_release_trust.evaluator import (
        REQUIRED_DEFECT_FAMILIES,
        aggregate_benchmark_metrics,
        grade_case_result,
    )

    outcome_matches = 0
    reason_matches = 0
    findings_matches = 0
    case_records: list[dict[str, Any]] = []

    for case in cases:
        cid = case["case_id"]
        exp = case["expected"]
        try:
            res = _execute_case(case, tmp_dir)
        except Exception as exc:
            errors.append(f"{cid}: execution failed with exception: {exc}")
            continue

        cand_payload = {
            "outcome": res.outcome.value,
            "coverage": res.coverage.value,
            "reason_codes": list(res.reason_codes),
            "findings": [{"defect_id": f.defect_id, "message": f.message} for f in res.findings],
        }
        _, case_errors, case_metrics = grade_case_result(case, cand_payload)
        errors.extend(case_errors)

        if res.outcome.value == exp["outcome"]:
            outcome_matches += 1
        if sorted(res.reason_codes) == sorted(exp.get("reason_codes", [])):
            reason_matches += 1
        if sorted(f.defect_id for f in res.findings) == sorted(f["defect_id"] for f in exp.get("findings", [])):
            findings_matches += 1

        # Also verify redacted evidence payload fields and sample secrets
        for finding in res.findings:
            if finding.defect_id in ("SEC-SECRET", "SEC-SECRET-TO-SINK"):
                payload = finding.evidence.payload
                redacted = (
                    payload.get("redacted")
                    or payload.get("source", {}).get("redacted", "")
                )
                if "…" not in redacted and "***" not in redacted:
                    case_metrics["strict_redaction"] = False
                    errors.append(f"{cid}: missing redacted token representation in evidence payload")
                for secret_sample in (
                    "AKIA1234567890ABCDEF",
                    "ghp_123456789012345678901234",
                    "xoxb-1234567890-1234567890123",
                ):
                    if secret_sample in finding.message or secret_sample in json.dumps(payload):
                        case_metrics["strict_redaction"] = False
                        errors.append(f"{cid}: unredacted secret leaked in finding output")
        case_records.append(case_metrics)

    benchmark_data = aggregate_benchmark_metrics(case_records)
    for did in REQUIRED_DEFECT_FAMILIES:
        d_m = benchmark_data["defects"][did]
        if d_m["precision"] < 1.0:
            errors.append(f"defect {did} precision {d_m['precision']:.2f} < 1.0")
        if d_m["recall"] < 0.90:
            errors.append(f"defect {did} recall {d_m['recall']:.2f} < 0.90")

    if not benchmark_data["zero_false_blocking"]:
        errors.append("benchmark violated zero_false_blocking requirement")
    if not benchmark_data["strict_redaction"]:
        errors.append("benchmark violated strict_redaction requirement")

    benchmark_data["outcome_matches"] = outcome_matches
    benchmark_data["reason_code_matches"] = reason_matches
    benchmark_data["findings_matches"] = findings_matches
    return benchmark_data, errors


def _run_benchmark_worker(root: Path) -> int:
    """Benchmark worker process entrypoint."""
    if os.environ.get("VERIFYCI_RELEASE_SIGNING_KEY"):
        err = "Security violation: VERIFYCI_RELEASE_SIGNING_KEY leaked into benchmark runner process"
        print(json.dumps({"benchmark": None, "errors": [err]}))
        return 1

    bench_data, errors = _run_benchmark_cases(root)
    print(json.dumps({"benchmark": bench_data, "errors": errors}))
    return 0 if not errors else 1


def execute_security_benchmark(root: Path) -> tuple[dict[str, Any] | None, list[str]]:
    """Execute the empirical benchmark in an isolated subprocess with scrubbed environment.

    Security Boundary:
    The benchmark subprocess executes repository-controlled cases and AST analysis.
    VERIFYCI_RELEASE_SIGNING_KEY is strictly scrubbed from the child environment so
    benchmark code cannot access or exfiltrate signing credentials.
    """
    env = os.environ.copy()
    env.pop("VERIFYCI_RELEASE_SIGNING_KEY", None)
    env.pop("VERIFYCI_RELEASE_VALIDATION_PATH", None)
    env["PYTHONPATH"] = str(root) + (os.pathsep + env["PYTHONPATH"] if "PYTHONPATH" in env else "")

    cmd = [
        sys.executable,
        str(root / "scripts" / "validate_release.py"),
        "--benchmark-worker",
    ]
    proc = subprocess.run(cmd, cwd=str(root), env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        return None, [
            f"benchmark worker failed (exit {proc.returncode}):\n{proc.stderr}\n{proc.stdout}"
        ]

    try:
        out = json.loads(proc.stdout)
        return out.get("benchmark"), out.get("errors", [])
    except Exception as exc:
        return None, [
            f"failed to parse benchmark worker output: {exc}\nSTDOUT: {proc.stdout}\nSTDERR: {proc.stderr}"
        ]


def execute_test_suite(
    root: Path,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Execute the v3 test suite via pytest and capture authoritative pass metrics.

    Security Boundary:
    The test suite subprocess executes repository code and tests. It MUST NOT inherit
    the release signing secret (VERIFYCI_RELEASE_SIGNING_KEY) to prevent test code
    from having access to or exfiltrating the signing authority.
    """
    errors = []
    started = time.monotonic()
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "tests/v3",
        "-q",
        "--tb=short",
        # The signed-evidence integration test requires evidence that can only be
        # produced after this measurement run. It is executed by the normal CI
        # matrix at the evidence commit, where the signed record is present.
        "-m",
        "not benchmark and not performance and not requires_release_evidence",
    ]
    env = os.environ.copy()
    # Explicitly scrub signing key from test subprocess environment
    env.pop("VERIFYCI_RELEASE_SIGNING_KEY", None)
    env.pop("VERIFYCI_RELEASE_VALIDATION_PATH", None)
    env["PYTHONPATH"] = str(root) + (os.pathsep + env["PYTHONPATH"] if "PYTHONPATH" in env else "")
    proc = subprocess.run(cmd, cwd=str(root), env=env, capture_output=True, text=True)
    duration = time.monotonic() - started
    stdout = proc.stdout
    stderr = proc.stderr

    if proc.returncode != 0:
        errors.append(f"test suite execution failed with returncode {proc.returncode}:\n{stderr}\n{stdout[-1000:]}")
        return None, errors

    # Parse pass/fail count from output (e.g., '201 passed in 134.25s')
    passed_count = 0
    failed_count = 0
    m_pass = re.search(r"(\d+)\s+passed", stdout)
    if m_pass:
        passed_count = int(m_pass.group(1))
    m_fail = re.search(r"(\d+)\s+failed", stdout)
    if m_fail:
        failed_count = int(m_fail.group(1))

    if passed_count < 200:
        errors.append(f"test suite reported only {passed_count} passed tests (expected >= 200)")
    if failed_count > 0:
        errors.append(f"test suite reported {failed_count} failing tests")

    metrics = {
        "total_passed": passed_count,
        "total_failed": failed_count,
        "total_errors": 0,
        "duration_seconds": round(duration, 2),
        "test_target": "tests/v3",
    }
    return metrics, errors


def collect_measurements(root: Path) -> tuple[dict[str, Any] | None, list[str]]:
    """Execute preflight validations, benchmark, and test suites unprivileged."""
    from verifyci.contracts.manifest import (
        CHECK_ORDER,
        CHECK_SPECS,
        manifest_hash,
        validate_manifest,
    )
    from verifyci.contracts.promotion import validate_promotion_chain
    from verifyci.contracts.release_validation import (
        compute_implementation_fingerprint,
        get_commit_sha,
    )

    errors: list[str] = []

    # 1. Validate manifest contract and promotion records
    errors.extend(validate_manifest())
    for check_id in CHECK_ORDER:
        spec = CHECK_SPECS[check_id]
        chain_errors = validate_promotion_chain(spec)
        for err in chain_errors:
            if err not in errors:
                errors.append(err)

    # 2. Verify frozen corpus checksums and defect coverage
    errors.extend(verify_security_corpus_sums(root))
    errors.extend(verify_corpus_cases(root))

    # 3. Resolve git commit identity (fails closed if unresolvable)
    commit_sha = get_commit_sha(root)
    if not commit_sha:
        errors.append("unable to resolve authoritative HEAD commit SHA from git")

    if errors:
        return None, errors

    # 4. Execute security benchmark in scrubbed subprocess
    bench_data, bench_errors = execute_security_benchmark(root)
    errors.extend(bench_errors)

    # 5. Execute test suite in scrubbed subprocess
    test_data, test_errors = execute_test_suite(root)
    errors.extend(test_errors)

    if errors or not bench_data or not test_data or not commit_sha:
        return None, errors

    test_data["stage"] = "final"
    bench_data["stage"] = "final"

    measurement_record = {
        "schema": "verifyci.release_measurements/v1",
        "commit_sha": commit_sha,
        "manifest_hash": manifest_hash(),
        "implementation_fingerprint": compute_implementation_fingerprint(root),
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
        "checks_validated": list(CHECK_ORDER),
        "measurements": {
            "benchmark": bench_data,
            "test_suite": test_data,
        },
    }
    return measurement_record, []


def generate_measurement_attestation(
    root: Path,
    measurement_record: dict[str, Any],
    output_path: Path | None = None,
    measurements_file: Path | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Generate authenticated measurement attestation binding execution context."""
    from verifyci.contracts.canonical import canonical_json_bytes
    from verifyci.contracts.release_validation import get_commit_sha
    import datetime

    errors: list[str] = []

    if measurements_file and measurements_file.is_file():
        raw_sha256 = "sha256:" + hashlib.sha256(measurements_file.read_bytes()).hexdigest()
    else:
        measurements_json_bytes = (json.dumps(measurement_record, indent=2, sort_keys=True) + "\n").encode("utf-8")
        raw_sha256 = "sha256:" + hashlib.sha256(measurements_json_bytes).hexdigest()
    canonical_digest = "sha256:" + hashlib.sha256(canonical_json_bytes(measurement_record)).hexdigest()

    is_ci = os.environ.get("GITHUB_ACTIONS") == "true"
    run_id = os.environ.get("GITHUB_RUN_ID")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    job_name = os.environ.get("GITHUB_JOB", "verifyci-measurements")
    github_sha = (
        os.environ.get("GITHUB_SHA")
        or measurement_record.get("commit_sha")
        or get_commit_sha(root)
    )

    execution = {
        "ci_platform": "github_actions" if is_ci else "local",
        "workflow_run_id": str(run_id) if run_id else None,
        "workflow_run_attempt": str(run_attempt) if run_attempt else "1",
        "job_name": str(job_name),
        "commit_sha": github_sha,
        "ref": os.environ.get("GITHUB_REF") if is_ci else None,
    }

    oidc_token = None
    id_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    id_req_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if id_url and id_req_token:
        try:
            import urllib.request
            sep = "&" if "?" in id_url else "?"
            full_url = f"{id_url}{sep}audience=verifyci-release-authority"
            req = urllib.request.Request(
                full_url,
                headers={
                    "Authorization": f"Bearer {id_req_token}",
                    "Accept": "application/json",
                    "User-Agent": "VerifyCI-MeasurementPipeline",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                oidc_token = data.get("value")
        except Exception as exc:
            if is_ci:
                errors.append(f"failed to obtain GitHub Actions OIDC token in CI: {exc}")
    elif is_ci:
        errors.append("ACTIONS_ID_TOKEN_REQUEST_URL or ACTIONS_ID_TOKEN_REQUEST_TOKEN missing in CI environment")

    if is_ci and not oidc_token and not errors:
        errors.append("required GitHub Actions OIDC token is missing or empty in CI environment")

    if errors:
        return None, errors

    workflow_identity = {
        "platform": "github_actions" if is_ci else "local",
        "repository": os.environ.get("GITHUB_REPOSITORY", "NeutronZero/VerifyCI"),
        "workflow_name": "release_measurements",
        "workflow_path": ".github/workflows/release_measurements.yml",
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF") if is_ci else None,
        "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA") if is_ci else None,
        "job_name": str(job_name),
        "run_id": str(run_id) if run_id else None,
        "run_attempt": str(run_attempt) if run_attempt else "1",
        "commit_sha": github_sha,
        "ref": os.environ.get("GITHUB_REF") if is_ci else None,
        "oidc_token": oidc_token,
    }

    attestation_body = {
        "schema": "verifyci.measurement_attestation/v1",
        "issuer": "verifyci.measurement_pipeline",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "execution": execution,
        "workflow_identity": workflow_identity,
        "measurements_digest": canonical_digest,
        "measurements_file_sha256": raw_sha256,
        "implementation_fingerprint": measurement_record.get("implementation_fingerprint"),
        "manifest_hash": measurement_record.get("manifest_hash"),
        "corpora_hashes": measurement_record.get("corpora_hashes"),
        "summary": {
            "benchmark_cases": measurement_record.get("measurements", {}).get("benchmark", {}).get("cases_evaluated"),
            "test_suite_passed": measurement_record.get("measurements", {}).get("test_suite", {}).get("total_passed"),
            "test_suite_failed": measurement_record.get("measurements", {}).get("test_suite", {}).get("total_failed"),
            "test_suite_errors": measurement_record.get("measurements", {}).get("test_suite", {}).get("total_errors"),
        },
    }

    att_file = output_path or (root / "evidence" / "release" / "measurement_attestation.json")
    att_file.parent.mkdir(parents=True, exist_ok=True)
    temp_file = att_file.with_name(f"{att_file.name}.tmp.{os.getpid()}")
    try:
        temp_file.write_text(json.dumps(attestation_body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temp_file, att_file)
    except Exception:
        if temp_file.is_file():
            temp_file.unlink(missing_ok=True)
        raise

    return attestation_body, []


def sign_measurements(
    root: Path,
    measurements_file: Path,
    attestation_file: Path,
    signing_key: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Sign verified measurements via standalone signer subprocess with zero repo imports."""
    env = os.environ.copy()
    env["VERIFYCI_RELEASE_SIGNING_KEY"] = signing_key
    cmd = [
        sys.executable,
        str(root / "scripts" / "standalone_signer.py"),
        "--measurements",
        str(measurements_file),
        "--attestation",
        str(attestation_file),
        "--output",
        str(root / "evidence" / "release" / "release_validation.json"),
    ]
    proc = subprocess.run(cmd, cwd=str(root), env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        return None, [f"standalone signer failed (exit {proc.returncode}):\n{proc.stderr}\n{proc.stdout}"]
    try:
        val_file = root / "evidence" / "release" / "release_validation.json"
        return json.loads(val_file.read_text(encoding="utf-8")), []
    except Exception as exc:
        return None, [f"failed to load signed release validation record: {exc}\n{proc.stdout}"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authoritative release-validation pipeline for VerifyCI v3 (§15.10)")
    parser.add_argument("--benchmark-worker", action="store_true", help="Internal benchmark worker entrypoint")
    parser.add_argument("--measure-only", action="store_true", help="Execute preflight, benchmark, and test suites unprivileged")
    parser.add_argument(
        "--output-measurements",
        type=Path,
        default=ROOT / "evidence" / "release" / "measurements.json",
        help="Path to write measurements artifact",
    )
    parser.add_argument(
        "--output-attestation",
        type=Path,
        default=ROOT / "evidence" / "release" / "measurement_attestation.json",
        help="Path to write measurement attestation artifact",
    )
    parser.add_argument("--sign-only", action="store_true", help="Consume verified measurements and apply Ed25519 signature in protected release environment")
    parser.add_argument(
        "--input-measurements",
        type=Path,
        default=ROOT / "evidence" / "release" / "measurements.json",
        help="Path to read verified measurements artifact",
    )
    parser.add_argument(
        "--input-attestation",
        type=Path,
        default=ROOT / "evidence" / "release" / "measurement_attestation.json",
        help="Path to read signed measurement attestation artifact",
    )
    if argv is None and "pytest" in sys.modules:
        argv = []
    args = parser.parse_args(argv)

    if getattr(args, "benchmark_worker", False):
        return _run_benchmark_worker(ROOT)

    from verifyci.contracts.manifest import CHECK_ORDER, CHECK_SPECS
    from verifyci.contracts.model import Maturity

    shadow = [
        check_id
        for check_id in CHECK_ORDER
        if CHECK_SPECS[check_id].maturity == Maturity.SHADOW
    ]

    def _emit_failure(errors: list[str], stderr_msg: str = "") -> int:
        report = {
            "manifest_errors": errors,
            "measurement_pipeline": "failed",
            "release_ready": False,
            "schema": "verifyci.release_preflight/v1",
            "shadow_checks": shadow,
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        if stderr_msg:
            print(stderr_msg, file=sys.stderr)
        return 1

    def _run_measure() -> tuple[dict[str, Any] | None, int]:
        measurement_record, errors = collect_measurements(ROOT)
        if errors or not measurement_record:
            return None, _emit_failure(errors, "Release blocked: measurement pipeline failed.")
        args.output_measurements.parent.mkdir(parents=True, exist_ok=True)
        temp_file = args.output_measurements.with_name(f"{args.output_measurements.name}.tmp.{os.getpid()}")
        try:
            temp_file.write_text(json.dumps(measurement_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            os.replace(temp_file, args.output_measurements)
        except Exception:
            if temp_file.is_file():
                temp_file.unlink(missing_ok=True)
            raise
        att_record, att_errors = generate_measurement_attestation(
            ROOT,
            measurement_record,
            args.output_attestation,
            measurements_file=args.output_measurements,
        )
        if att_errors or not att_record:
            return None, _emit_failure(att_errors, "Release blocked: failed to generate measurement attestation.")
        return measurement_record, 0

    def _run_sign(measurements_path: Path, attestation_path: Path, signing_key: str) -> int:
        record, errors = sign_measurements(ROOT, measurements_path, attestation_path, signing_key)
        if errors or not record:
            return _emit_failure(errors, "Release blocked: signing failed validation.")
        report = {
            "attestation_digest": record["attestation"]["digest"],
            "commit_sha": record["commit_sha"],
            "manifest_errors": [],
            "measurement_pipeline": "verified",
            "provenance_verified": True,
            "release_ready": True,
            "schema": "verifyci.release_preflight/v1",
            "shadow_checks": shadow,
            "validation_evidence": "evidence/release/release_validation.json",
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0

    if args.measure_only:
        measurement_record, status = _run_measure()
        if status != 0 or not measurement_record:
            return status
        report = {
            "commit_sha": measurement_record["commit_sha"],
            "manifest_errors": [],
            "measurement_pipeline": "verified",
            "measurements_file": str(args.output_measurements.as_posix()),
            "attestation_file": str(args.output_attestation.as_posix()),
            "release_ready": True,
            "schema": "verifyci.release_preflight/v1",
            "shadow_checks": shadow,
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0

    signing_key = os.environ.get("VERIFYCI_RELEASE_SIGNING_KEY")
    if not signing_key:
        return _emit_failure(
            ["VERIFYCI_RELEASE_SIGNING_KEY environment variable is missing"],
            "Release blocked: signing authority key is missing.",
        )

    if args.sign_only:
        return _run_sign(args.input_measurements, args.input_attestation, signing_key)

    _, status = _run_measure()
    if status != 0:
        return status
    return _run_sign(args.output_measurements, args.output_attestation, signing_key)


if __name__ == "__main__":
    raise SystemExit(main())
