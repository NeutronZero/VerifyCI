"""Trusted Supervisor and Measurement Pipeline Orchestrator (§15.10 Component D).

Coordinates safe tree staging, benchmark case preparation, sandboxed container invocation,
independent grading, held-out evaluation, and post-execution fingerprint verification.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

from verifyci import __version__ as TOOL_VERSION
from verifyci_release_trust.evaluator import (
    aggregate_benchmark_metrics,
    generate_held_out_scenarios,
    grade_case_result,
    load_authoritative_public_cases,
)
from verifyci_release_trust.sandbox import run_candidate_in_docker
from verifyci_release_trust.tree_materializer import (
    compute_staging_fingerprint,
    materialize_tree_to_staging,
)


def _build_case_git_repo(case: dict[str, Any], target_dir: Path) -> tuple[str, str, str]:
    """Create synthetic git repo for benchmark case. Returns (repo_dir, base_sha, head_sha)."""
    repo_dir = target_dir / case["case_id"]
    if repo_dir.exists():
        shutil.rmtree(repo_dir)
    repo_dir.mkdir(parents=True)

    subprocess.run(["git", "init", "-q", "-b", "main", str(repo_dir)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "VerifyCITest"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "test@verifyci.dev"], check=True, capture_output=True)

    for rel_path, content in case.get("base_files", {}).items():
        f = repo_dir / rel_path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")

    subprocess.run(["git", "-C", str(repo_dir), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-q", "-m", "base", "--allow-empty"], check=True, capture_output=True)
    base_sha = subprocess.check_output(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True).strip()

    # Apply head files
    for item in repo_dir.iterdir():
        if item.name != ".git":
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

    for rel_path, content in case.get("head_files", {}).items():
        f = repo_dir / rel_path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")

    subprocess.run(["git", "-C", str(repo_dir), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-q", "-m", "head", "--allow-empty"], check=True, capture_output=True)
    head_sha = subprocess.check_output(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True).strip()

    return str(repo_dir), base_sha, head_sha


def _serialize_policy_toml(case: dict[str, Any]) -> str:
    pol = case.get("policy", {})
    lines: list[str] = []
    allow = pol.get("secret_allowlist_paths", [])
    places = pol.get("secret_placeholders", [])
    if allow or places:
        lines.append("[secrets]")
        if allow:
            lines.append(f"allowlist_paths = {json.dumps(allow)}")
        if places:
            lines.append(f"placeholder_patterns = {json.dumps(places)}")
    for rule_id, rule in pol.get("forbidden_calls", {}).items():
        lines.append(f"[forbidden_calls.{rule_id}]")
        lines.append(f"symbols = {json.dumps(rule.get('symbols', []))}")
        lines.append(f"reason = {json.dumps(rule.get('reason', 'forbidden'))}")
    sources = pol.get("taint_sources", [])
    sinks = pol.get("taint_sinks", {})
    if sources or sinks:
        lines.append("[taint]")
        if sources:
            lines.append(f"sources = {json.dumps(sources)}")
        for sink_id, sink in sinks.items():
            lines.append(f"[taint.sinks.{sink_id}]")
            lines.append(f"symbols = {json.dumps(sink.get('symbols', []))}")
            lines.append(f"kind = {json.dumps(sink.get('kind', 'generic'))}")
    return "\n".join(lines)


def run_supervisor_measurement_pipeline(
    candidate_root: Path,
    trusted_root: Path,
    output_measurements: Path,
    candidate_sha: str,
    *,
    worker_image_digest: str = "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    sandbox_mode: str = "docker",
    held_out_seed: str | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Execute authoritative supervisor pipeline."""
    errors: list[str] = []
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    cand_res = candidate_root.resolve()
    trust_res = trusted_root.resolve()
    if cand_res == trust_res:
        return None, ["candidate_root and trusted_root must be distinct directories"]
    if cand_res in trust_res.parents or trust_res in cand_res.parents:
        return None, ["candidate_root and trusted_root must not be nested"]

    # 1. Safe Git tree materialization into clean staging directory
    staging_temp = Path(tempfile.mkdtemp(prefix="vc_staging_"))
    try:
        manifest = materialize_tree_to_staging(cand_res, candidate_sha, staging_temp)
    except Exception as exc:
        return None, [f"failed to materialize candidate git tree: {exc}"]

    # 2. Load authoritative public benchmark cases
    try:
        public_cases = load_authoritative_public_cases(trust_res)
    except Exception as exc:
        return None, [f"failed to load public benchmark corpus: {exc}"]

    case_scratch = Path(tempfile.mkdtemp(prefix="vc_cases_"))
    case_results: list[dict[str, Any]] = []

    # 3. Execute public cases in worker sandbox
    for case in public_cases:
        cid = case["case_id"]
        repo_dir, base_sha, head_sha = _build_case_git_repo(case, case_scratch)
        pol_toml = _serialize_policy_toml(case)

        worker_args = [
            "check-case",
            "--candidate-root", "/candidate",
            "--repo-root", "/repo",
            "--base", base_sha,
            "--head", head_sha,
            "--policy-toml", pol_toml,
        ]

        if sandbox_mode == "docker":
            res = run_candidate_in_docker(
                staging_temp,
                Path(repo_dir),
                worker_image_digest,
                worker_args,
            )
            if res.error or not res.data:
                errors.append(f"{cid}: worker execution failed ({res.verdict}): {res.error}")
                continue
            cand_resp = res.data
        elif sandbox_mode == "subprocess-isolated":
            # Local-dev fallback only: invoke worker launcher directly with isolated python
            launcher = trust_res / "docker" / "worker" / "launch_candidate.py"
            cmd = [
                sys.executable, "-I", str(launcher),
                "check-case",
                "--candidate-root", str(staging_temp),
                "--repo-root", str(repo_dir),
                "--base", base_sha,
                "--head", head_sha,
                "--policy-toml", pol_toml,
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode not in (0, 1):
                errors.append(f"{cid}: worker failed (exit {proc.returncode}): {proc.stderr}")
                continue
            try:
                cand_resp = json.loads(proc.stdout)
            except Exception as exc:
                errors.append(f"{cid}: malformed worker response: {exc}")
                continue
        else:
            return None, [f"unsupported sandbox mode: {sandbox_mode}"]

        matched, case_errs, metrics = grade_case_result(case, cand_resp)
        errors.extend(case_errs)
        case_results.append(metrics)

    public_benchmark = aggregate_benchmark_metrics(case_results)

    # 4. Private held-out evaluation (mandatory for authoritative PASS verdict)
    held_out_metrics: dict[str, Any] = {}
    if not held_out_seed:
        errors.append("held-out evaluation failed closed: missing mandatory VERIFYCI_HELD_OUT_SEED")
        held_out_metrics = {
            "status": "MISSING_SEED",
            "cases_evaluated": 0,
            "error": "mandatory held-out evaluation seed not provided",
        }
    else:
        held_out_cases, commitment, epoch = generate_held_out_scenarios(held_out_seed, public_cases, count=10)
        ho_results: list[dict[str, Any]] = []
        for case in held_out_cases:
            cid = case["case_id"]
            repo_dir, base_sha, head_sha = _build_case_git_repo(case, case_scratch)
            pol_toml = _serialize_policy_toml(case)
            worker_args = [
                "check-case",
                "--candidate-root", "/candidate",
                "--repo-root", "/repo",
                "--base", base_sha,
                "--head", head_sha,
                "--policy-toml", pol_toml,
            ]
            if sandbox_mode == "docker":
                res = run_candidate_in_docker(
                    staging_temp, Path(repo_dir), worker_image_digest, worker_args
                )
                if res.data:
                    ok_case, case_errs, m = grade_case_result(case, res.data)
                    ho_results.append(m)
                    if not ok_case:
                        errors.extend(case_errs)
            elif sandbox_mode == "subprocess-isolated":
                launcher = trust_res / "docker" / "worker" / "launch_candidate.py"
                cmd = [
                    sys.executable, "-I", str(launcher),
                    "check-case",
                    "--candidate-root", str(staging_temp),
                    "--repo-root", str(repo_dir),
                    "--base", base_sha,
                    "--head", head_sha,
                    "--policy-toml", pol_toml,
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if proc.returncode in (0, 1):
                    try:
                        ho_resp = json.loads(proc.stdout)
                        ok_case, case_errs, m = grade_case_result(case, ho_resp)
                        ho_results.append(m)
                        if not ok_case:
                            errors.extend(case_errs)
                    except Exception as exc:
                        errors.append(f"{cid}: failed to parse held-out worker response: {exc}")
                else:
                    errors.append(f"{cid}: held-out worker subprocess failed with return code {proc.returncode}")

        ho_agg = aggregate_benchmark_metrics(ho_results)
        if len(ho_results) != len(held_out_cases):
            errors.append(f"held-out evaluation incomplete: {len(ho_results)}/{len(held_out_cases)} cases completed")
        if not ho_agg.get("zero_false_blocking"):
            errors.append("held-out evaluation violated zero_false_blocking invariant")
        if not ho_agg.get("strict_redaction"):
            errors.append("held-out evaluation violated strict_redaction invariant")

        held_out_metrics = {
            "epoch": epoch,
            "commitment": commitment,
            "cases_evaluated": ho_agg.get("cases_evaluated", 0),
            "coverage_matches": ho_agg.get("coverage_matches", 0),
            "zero_false_blocking": ho_agg.get("zero_false_blocking", True),
            "strict_redaction": ho_agg.get("strict_redaction", True),
        }

    # 5. Recompute post-execution staging fingerprint to assert immutability
    post_fp = compute_staging_fingerprint(staging_temp, manifest.commit_sha, manifest.tree_sha)
    if post_fp != manifest.fingerprint:
        errors.append("candidate source mutation detected: post-execution fingerprint mismatch")

    completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    has_errors = bool(errors)
    execution_verified = (
        not has_errors
        and bool(held_out_seed)
        and held_out_metrics.get("cases_evaluated", 0) == len(held_out_cases)
    )
    if execution_verified:
        overall_verdict = "PASS"
    elif has_errors:
        overall_verdict = "FAIL"
    else:
        overall_verdict = "INCONCLUSIVE"

    measurements_record = {
        "schema": "verifyci.measurements/v3",
        "tool_version": TOOL_VERSION,
        "verdict": overall_verdict,
        "candidate_sha": manifest.commit_sha,
        "candidate_tree_sha": manifest.tree_sha,
        "candidate_implementation_fingerprint": manifest.fingerprint,
        "started_at": started_at,
        "completed_at": completed_at,
        "sandbox_mode": sandbox_mode,
        "benchmark": public_benchmark,
        "held_out_evaluation": held_out_metrics,
        "errors": errors,
    }

    # Write measurements atomically
    output_measurements.parent.mkdir(parents=True, exist_ok=True)
    tmp_out = output_measurements.with_name(f"{output_measurements.name}.tmp.{os.getpid()}")
    tmp_out.write_text(json.dumps(measurements_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp_out, output_measurements)

    # Cleanup staging temp
    try:
        shutil.rmtree(staging_temp, ignore_errors=True)
        shutil.rmtree(case_scratch, ignore_errors=True)
    except Exception:
        pass

    return measurements_record, errors


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Authoritative VerifyCI release measurement supervisor")
    parser.add_argument("--measure-only", action="store_true", help="Execute measurement pipeline and emit measurements.json")
    parser.add_argument("--candidate-root", type=Path, default=Path.cwd(), help="Path to candidate repository checkout")
    parser.add_argument("--trusted-root", type=Path, default=Path.cwd(), help="Path to trusted authority root")
    parser.add_argument("--output-measurements", type=Path, default=Path("evidence/release/measurements.json"), help="Path to write measurements.json")
    parser.add_argument("--candidate-sha", default=None, help="Explicit 40-char candidate commit SHA")
    parser.add_argument("--worker-image", default="sha256:0000000000000000000000000000000000000000000000000000000000000000", help="OCI image digest")
    parser.add_argument("--sandbox-mode", choices=("docker", "subprocess-isolated"), default="docker", help="Worker sandbox execution mode")

    args = parser.parse_args(argv)

    cand_sha = args.candidate_sha or os.environ.get("GITHUB_SHA")
    if not cand_sha:
        proc = subprocess.run(["git", "-C", str(args.candidate_root), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
        cand_sha = proc.stdout.strip() if proc.returncode == 0 else "0" * 40

    seed = os.environ.get("VERIFYCI_HELD_OUT_SEED")

    record, errors = run_supervisor_measurement_pipeline(
        args.candidate_root.resolve(),
        args.trusted_root.resolve(),
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
