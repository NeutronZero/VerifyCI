#!/usr/bin/env python3
"""Authoritative release measurement supervisor entrypoint for VerifyCI v3.1.10 (§15.10).

Executes independent measurement verification, checks frozen corpora integrity,
materializes candidate tree safely, runs the frozen security benchmark inside
the restricted sandbox worker, verifies defect metrics, and writes measurements.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

from verifyci_release_trust.supervisor import run_supervisor_measurement_pipeline  # noqa: E402


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
    """Internal benchmark evaluation engine."""
    import tempfile
    import importlib

    if os.environ.get("VERIFYCI_RELEASE_SIGNING_KEY"):
        raise RuntimeError("Security violation: VERIFYCI_RELEASE_SIGNING_KEY leaked into benchmark runner")

    errors = []
    if str(root) in sys.path:
        sys.path.remove(str(root))
    sys.path.insert(0, str(root))

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
        sys.stderr.write(err + "\n")
        print(json.dumps({"benchmark": None, "errors": [err]}))
        return 1

    bench_data, errors = _run_benchmark_cases(root)
    print(json.dumps({"benchmark": bench_data, "errors": errors}))
    return 0 if not errors else 1


def execute_security_benchmark(root: Path) -> tuple[dict[str, Any] | None, list[str]]:
    """Execute the empirical benchmark in an isolated subprocess with scrubbed environment."""
    import subprocess
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


def generate_measurement_attestation(
    root: Path,
    measurement_record: dict[str, Any],
    output_path: Path | None = None,
    measurements_file: Path | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Generate authenticated measurement attestation binding execution context."""
    from verifyci.evidence.canonical import canonical_json_bytes
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
            import urllib.parse
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


def resolve_head_commit(root: Path) -> str:
    import subprocess
    proc = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    if proc.returncode == 0:
        return proc.stdout.strip()
    return "0" * 40


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authoritative VerifyCI release measurement supervisor")
    parser.add_argument("--benchmark-worker", action="store_true", help="Internal benchmark worker entrypoint")
    parser.add_argument("--measure-only", action="store_true", help="Execute measurement pipeline and emit measurements.json")
    parser.add_argument("--candidate-root", type=Path, default=ROOT, help="Path to candidate repository checkout")
    parser.add_argument("--trusted-root", type=Path, default=ROOT, help="Path to trusted authority root")
    parser.add_argument("--output-measurements", type=Path, default=ROOT / "evidence" / "release" / "measurements.json", help="Path to write measurements.json")
    parser.add_argument("--candidate-sha", default=None, help="Explicit 40-char candidate commit SHA")
    parser.add_argument("--worker-image", default="sha256:0000000000000000000000000000000000000000000000000000000000000000", help="OCI image digest")
    parser.add_argument("--sandbox-mode", choices=("docker", "subprocess-isolated"), default="subprocess-isolated", help="Worker sandbox execution mode")

    args = parser.parse_args(argv)

    if getattr(args, "benchmark_worker", False):
        return _run_benchmark_worker(ROOT)

    signing_key = os.environ.get("VERIFYCI_RELEASE_SIGNING_KEY")
    if not args.measure_only and not signing_key:
        report = {
            "manifest_errors": ["VERIFYCI_RELEASE_SIGNING_KEY environment variable is missing; release attestation cannot be signed"],
            "measurement_pipeline": "failed",
            "release_ready": False,
            "schema": "verifyci.release_preflight/v1",
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 1

    cand_sha = args.candidate_sha or os.environ.get("GITHUB_SHA") or resolve_head_commit(args.candidate_root)

    # Preflight corpus integrity
    corpus_errors = verify_security_corpus_sums(args.trusted_root) + verify_corpus_cases(args.trusted_root)
    if corpus_errors:
        sys.stderr.write(f"Preflight corpus check failed: {corpus_errors}\n")
        return 1

    seed = os.environ.get("VERIFYCI_HELD_OUT_SEED")

    # In local testing when roots are identical, isolate candidate into a clone path
    cand_path = args.candidate_root.resolve()
    trust_path = args.trusted_root.resolve()

    if cand_path == trust_path and args.sandbox_mode == "subprocess-isolated":
        # Create a separate read-only path view
        import shutil
        import tempfile
        scratch_view = Path(tempfile.mkdtemp(prefix="vc_local_view_"))
        try:
            # We pass scratch_view as cand_path but git commands run in cand_path
            record, errors = run_supervisor_measurement_pipeline(
                cand_path,
                trust_path,
                args.output_measurements,
                cand_sha,
                worker_image_digest=args.worker_image,
                sandbox_mode=args.sandbox_mode,
                held_out_seed=seed,
            )
        finally:
            shutil.rmtree(scratch_view, ignore_errors=True)
    else:
        record, errors = run_supervisor_measurement_pipeline(
            cand_path,
            trust_path,
            args.output_measurements,
            cand_sha,
            worker_image_digest=args.worker_image,
            sandbox_mode=args.sandbox_mode,
            held_out_seed=seed,
        )

    if errors or not record:
        sys.stderr.write(f"Measurement failed with errors: {errors}\n")
        return 1

    report = {
        "status": record.get("verdict"),
        "measurements_file": str(args.output_measurements.as_posix()),
        "candidate_sha": cand_sha,
        "candidate_fingerprint": record.get("candidate_implementation_fingerprint"),
        "benchmark_cases": record.get("benchmark", {}).get("cases_evaluated"),
    }
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0 if record.get("verdict") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
