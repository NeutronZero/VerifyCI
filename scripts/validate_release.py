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
    required_defects = {
        "SEC-SECRET",
        "SEC-SECRET-TO-SINK",
        "SEC-TAINT-TO-SINK",
        "SEC-DANGEROUS-CALL",
    }
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

    defects = [
        "SEC-SECRET",
        "SEC-SECRET-TO-SINK",
        "SEC-DANGEROUS-CALL",
        "SEC-TAINT-TO-SINK",
    ]
    confusion = {d: {"TP": 0, "FP": 0, "FN": 0, "TN": 0} for d in defects}
    outcome_matches = 0
    coverage_matches = 0
    reason_matches = 0
    findings_matches = 0
    zero_false_blocking = True
    strict_redaction = True

    for case in cases:
        cid = case["case_id"]
        exp = case["expected"]
        try:
            res = _execute_case(case, tmp_dir)
        except Exception as exc:
            errors.append(f"{cid}: execution failed with exception: {exc}")
            continue

        if res.outcome.value == exp["outcome"]:
            outcome_matches += 1
        else:
            errors.append(f"{cid}: outcome {res.outcome.value} != {exp['outcome']}")

        if res.coverage.value == exp["coverage"]:
            coverage_matches += 1
        else:
            errors.append(f"{cid}: coverage {res.coverage.value} != {exp['coverage']}")

        got_rc = sorted(res.reason_codes)
        exp_rc = sorted(exp.get("reason_codes", []))
        if got_rc == exp_rc:
            reason_matches += 1
        else:
            errors.append(f"{cid}: reason codes {got_rc} != {exp_rc}")

        got_findings = sorted(f.defect_id for f in res.findings)
        exp_findings = sorted(f["defect_id"] for f in exp.get("findings", []))
        if got_findings == exp_findings:
            findings_matches += 1
        else:
            errors.append(f"{cid}: findings {got_findings} != {exp_findings}")

        # Check for false blocking on clean control cases
        if exp["outcome"] != "FAIL" and res.outcome.value == "FAIL":
            zero_false_blocking = False
            errors.append(f"{cid}: unexpected blocking failure on non-defective control case")

        got_def_set = set(got_findings)
        exp_def_set = set(exp_findings)
        for did in defects:
            in_got = did in got_def_set
            in_exp = did in exp_def_set
            if in_got and in_exp:
                confusion[did]["TP"] += 1
            elif in_got and not in_exp:
                confusion[did]["FP"] += 1
            elif not in_got and in_exp:
                confusion[did]["FN"] += 1
            else:
                confusion[did]["TN"] += 1

        # Redaction verification on real engine findings
        for finding in res.findings:
            if finding.defect_id in ("SEC-SECRET", "SEC-SECRET-TO-SINK"):
                payload = finding.evidence.payload
                redacted = (
                    payload.get("redacted")
                    or payload.get("source", {}).get("redacted", "")
                )
                if "…" not in redacted and "***" not in redacted:
                    strict_redaction = False
                    errors.append(f"{cid}: missing redacted token representation in evidence payload")
                for secret_sample in [
                    "AKIA1234567890ABCDEF",
                    "ghp_123456789012345678901234",
                    "xoxb-1234567890-1234567890123",
                ]:
                    if secret_sample in finding.message or secret_sample in json.dumps(payload):
                        strict_redaction = False
                        errors.append(f"{cid}: unredacted secret leaked in finding output")

    defect_metrics: dict[str, Any] = {}
    for did in defects:
        c = confusion[did]
        tp, fp, fn = c["TP"], c["FP"], c["FN"]
        prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        defect_metrics[did] = {
            "precision": prec,
            "recall": rec,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": c["TN"],
        }
        if prec < 1.0:
            errors.append(f"defect {did} precision {prec:.2f} < 1.0")
        if rec < 0.90:
            errors.append(f"defect {did} recall {rec:.2f} < 0.90")

    if not zero_false_blocking:
        errors.append("benchmark violated zero_false_blocking requirement")
    if not strict_redaction:
        errors.append("benchmark violated strict_redaction requirement")

    benchmark_data = {
        "cases_evaluated": len(cases),
        "outcome_matches": outcome_matches,
        "coverage_matches": coverage_matches,
        "reason_code_matches": reason_matches,
        "findings_matches": findings_matches,
        "defects": defect_metrics,
        "zero_false_blocking": zero_false_blocking,
        "strict_redaction": strict_redaction,
    }
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


def sign_measurements(
    root: Path,
    measurement_record: dict[str, Any],
    signing_key: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Sign verified measurements with Ed25519 authority in protected environment.

    Security Boundary:
    This function consumes only a verified measurement dictionary. It DOES NOT execute
    repository tests or benchmark code while holding the signing key.
    """
    from verifyci.contracts.manifest import (
        CHECK_ORDER,
        CHECK_SPECS,
        manifest_hash,
        validate_manifest,
    )
    from verifyci.contracts.promotion import validate_promotion_chain
    from verifyci.contracts.release_validation import (
        compute_implementation_fingerprint,
        generate_release_validation_record,
        get_commit_sha,
    )

    errors = []

    # 1. Structural and manifest validation
    errors.extend(validate_manifest())
    for check_id in CHECK_ORDER:
        spec = CHECK_SPECS[check_id]
        chain_errors = validate_promotion_chain(spec)
        for err in chain_errors:
            if err not in errors:
                errors.append(err)

    # 2. Check commitment and fingerprint consistency
    current_commit = get_commit_sha(root)
    record_commit = measurement_record.get("commit_sha")
    if not current_commit or current_commit.lower() != str(record_commit).lower():
        errors.append(f"commit SHA mismatch between measurements ({record_commit}) and HEAD ({current_commit})")

    current_manifest_hash = manifest_hash()
    if measurement_record.get("manifest_hash") != current_manifest_hash:
        errors.append("manifest hash mismatch between measurements and current repository")

    current_impl_fingerprint = compute_implementation_fingerprint(root)
    if measurement_record.get("implementation_fingerprint") != current_impl_fingerprint:
        errors.append("implementation fingerprint mismatch between measurements and current repository")

    # 3. Validate measurement quality gates
    measurements = measurement_record.get("measurements", {})
    bench_data = measurements.get("benchmark", {})
    test_data = measurements.get("test_suite", {})

    if bench_data.get("cases_evaluated", 0) < 22:
        errors.append(f"benchmark cases evaluated insufficient: {bench_data.get('cases_evaluated')} < 22")
    if not bench_data.get("zero_false_blocking"):
        errors.append("benchmark violated zero_false_blocking")
    if not bench_data.get("strict_redaction"):
        errors.append("benchmark violated strict_redaction")

    if test_data.get("total_passed", 0) < 200:
        errors.append(f"test suite total_passed insufficient: {test_data.get('total_passed')} < 200")
    if test_data.get("total_failed", 1) != 0 or test_data.get("total_errors", 1) != 0:
        errors.append("test suite contains failing or errored tests")

    if errors or not record_commit:
        return None, errors

    # Atomically write signed release validation record
    record = generate_release_validation_record(
        root,
        record_commit,
        measurements,
        signing_key_hex=signing_key,
    )
    return record, []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authoritative release-validation pipeline for VerifyCI v3 (§15.10)")
    parser.add_argument("--benchmark-worker", action="store_true", help="Internal benchmark worker entrypoint")
    parser.add_argument("--measure-only", action="store_true", help="Execute preflight, benchmark, and test suites unprivileged")
    parser.add_argument("--output-measurements", type=Path, default=ROOT / "evidence" / "release" / "measurements.json", help="Path to write measurements artifact")
    parser.add_argument("--sign-only", action="store_true", help="Consume verified measurements and apply Ed25519 signature in protected release environment")
    parser.add_argument("--input-measurements", type=Path, default=ROOT / "evidence" / "release" / "measurements.json", help="Path to read verified measurements artifact")
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

    # --- Mode 1: Measure Only ---
    if args.measure_only:
        measurement_record, errors = collect_measurements(ROOT)
        if errors or not measurement_record:
            report = {
                "manifest_errors": errors,
                "measurement_pipeline": "failed",
                "release_ready": False,
                "schema": "verifyci.release_preflight/v1",
                "shadow_checks": shadow,
            }
            print(json.dumps(report, sort_keys=True, separators=(",", ":")))
            print("Release blocked: measurement pipeline failed.", file=sys.stderr)
            return 1

        args.output_measurements.parent.mkdir(parents=True, exist_ok=True)
        temp_file = args.output_measurements.with_name(f"{args.output_measurements.name}.tmp.{os.getpid()}")
        try:
            temp_file.write_text(json.dumps(measurement_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            os.replace(temp_file, args.output_measurements)
        except Exception:
            if temp_file.is_file():
                temp_file.unlink(missing_ok=True)
            raise

        report = {
            "commit_sha": measurement_record["commit_sha"],
            "manifest_errors": [],
            "measurement_pipeline": "verified",
            "measurements_file": str(args.output_measurements.as_posix()),
            "release_ready": True,
            "schema": "verifyci.release_preflight/v1",
            "shadow_checks": shadow,
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0

    # --- Mode 2: Sign Only ---
    if args.sign_only:
        signing_key = os.environ.get("VERIFYCI_RELEASE_SIGNING_KEY")
        if not signing_key:
            report = {
                "manifest_errors": ["VERIFYCI_RELEASE_SIGNING_KEY environment variable is missing"],
                "measurement_pipeline": "failed",
                "release_ready": False,
                "schema": "verifyci.release_preflight/v1",
                "shadow_checks": shadow,
            }
            print(json.dumps(report, sort_keys=True, separators=(",", ":")))
            print("Release blocked: signing authority key is missing.", file=sys.stderr)
            return 1

        if not args.input_measurements.is_file():
            report = {
                "manifest_errors": [f"measurements file not found: {args.input_measurements}"],
                "measurement_pipeline": "failed",
                "release_ready": False,
                "schema": "verifyci.release_preflight/v1",
                "shadow_checks": shadow,
            }
            print(json.dumps(report, sort_keys=True, separators=(",", ":")))
            print(f"Release blocked: measurements file missing: {args.input_measurements}", file=sys.stderr)
            return 1

        try:
            measurement_record = json.loads(args.input_measurements.read_text(encoding="utf-8"))
        except Exception as exc:
            report = {
                "manifest_errors": [f"failed to parse measurements file: {exc}"],
                "measurement_pipeline": "failed",
                "release_ready": False,
                "schema": "verifyci.release_preflight/v1",
                "shadow_checks": shadow,
            }
            print(json.dumps(report, sort_keys=True, separators=(",", ":")))
            return 1

        record, errors = sign_measurements(ROOT, measurement_record, signing_key)
        if errors or not record:
            report = {
                "manifest_errors": errors,
                "measurement_pipeline": "failed",
                "release_ready": False,
                "schema": "verifyci.release_preflight/v1",
                "shadow_checks": shadow,
            }
            print(json.dumps(report, sort_keys=True, separators=(",", ":")))
            print("Release blocked: signing failed validation.", file=sys.stderr)
            return 1

        report = {
            "attestation_digest": record["attestation"]["digest"],
            "commit_sha": record["commit_sha"],
            "manifest_errors": [],
            "measurement_pipeline": "verified",
            "release_ready": True,
            "schema": "verifyci.release_preflight/v1",
            "shadow_checks": shadow,
            "validation_evidence": "evidence/release/release_validation.json",
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0

    # --- Mode 3: Combined (Measure then Sign) ---
    signing_key = os.environ.get("VERIFYCI_RELEASE_SIGNING_KEY")
    if not signing_key:
        report = {
            "manifest_errors": ["VERIFYCI_RELEASE_SIGNING_KEY environment variable is missing; release attestation cannot be signed"],
            "measurement_pipeline": "failed",
            "release_ready": False,
            "schema": "verifyci.release_preflight/v1",
            "shadow_checks": shadow,
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        print("Release blocked: signing authority key is missing.", file=sys.stderr)
        return 1

    measurement_record, errors = collect_measurements(ROOT)
    if errors or not measurement_record:
        report = {
            "manifest_errors": errors,
            "measurement_pipeline": "failed",
            "release_ready": False,
            "schema": "verifyci.release_preflight/v1",
            "shadow_checks": shadow,
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        print("Release blocked: independent test or benchmark measurements failed.", file=sys.stderr)
        return 1

    record, errors = sign_measurements(ROOT, measurement_record, signing_key)
    if errors or not record:
        report = {
            "manifest_errors": errors,
            "measurement_pipeline": "failed",
            "release_ready": False,
            "schema": "verifyci.release_preflight/v1",
            "shadow_checks": shadow,
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        print("Release blocked: signing failed validation.", file=sys.stderr)
        return 1

    report = {
        "attestation_digest": record["attestation"]["digest"],
        "commit_sha": record["commit_sha"],
        "manifest_errors": [],
        "measurement_pipeline": "verified",
        "release_ready": True,
        "schema": "verifyci.release_preflight/v1",
        "shadow_checks": shadow,
        "validation_evidence": "evidence/release/release_validation.json",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
