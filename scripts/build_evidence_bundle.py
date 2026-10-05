#!/usr/bin/env python3
"""Generates structured evidence bundle and computes claim establishment status."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def get_environment_metadata() -> dict:
    """Capture forensic execution environment metadata."""
    try:
        git_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        git_sha = "unknown"

    branch = os.environ.get("GITHUB_REF_NAME", "local")
    pyproject_bytes = (ROOT / "pyproject.toml").read_bytes() if (ROOT / "pyproject.toml").exists() else b""

    return {
        "commit": git_sha,
        "branch": branch,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pyproject_sha256": hashlib.sha256(pyproject_bytes).hexdigest(),
    }


def evaluate_claims() -> dict:
    """Evaluate empirical claims against frozen benchmark results."""
    claims = {}
    missing_benchmarks = []

    # 1. BEIR Retrieval Gate (H1)
    beir_res = ROOT / "benchmarks" / "beir" / "results.json"
    if beir_res.exists():
        data = json.loads(beir_res.read_text(encoding="utf-8"))
        metrics = data.get("metrics", {})
        gate = data.get("gate", {})
        delta_ndcg = metrics.get("delta_ndcg", 0.0)
        is_established = gate.get("established", False)
        claims["H1_retrieval_fusion"] = {
            "status": "ESTABLISHED" if is_established else "MEASURED",
            "metric": "nDCG@10 delta",
            "delta_ndcg": delta_ndcg,
            "dense_ndcg": metrics.get("dense", {}).get("ndcg"),
            "hybrid_ndcg": metrics.get("hybrid", {}).get("ndcg"),
            "queries": data.get("run", {}).get("queries"),
        }
    else:
        missing_benchmarks.append("H1_retrieval_fusion")
        claims["H1_retrieval_fusion"] = {
            "status": "MISSING",
            "error": "benchmarks/beir/results.json not found",
        }

    # 2. Patch Corpus Verifier Gate
    patch_res = ROOT / "benchmarks" / "patch_corpus" / "results.json"
    if patch_res.exists():
        data = json.loads(patch_res.read_text(encoding="utf-8"))
        metrics = data.get("metrics", {})
        agreement = metrics.get("overall_agreement", 0.0)
        catch_rate = metrics.get("deterministic_catch_rate", 0.0)
        false_accept_rate = metrics.get("semantic_false_accept_rate", 0.0)
        is_established = (agreement >= 0.90 and catch_rate >= 0.95 and false_accept_rate == 0.0)
        claims["patch_corpus_verifier"] = {
            "status": "ESTABLISHED" if is_established else "MEASURED",
            "overall_agreement": agreement,
            "deterministic_catch_rate": catch_rate,
            "semantic_false_accept_rate": false_accept_rate,
            "n_correct": metrics.get("n_correct"),
            "n_wrong": metrics.get("n_wrong"),
        }
    else:
        missing_benchmarks.append("patch_corpus_verifier")
        claims["patch_corpus_verifier"] = {
            "status": "MISSING",
            "error": "benchmarks/patch_corpus/results.json not found",
        }

    # 3. Blast Radius Gate
    blast_res = ROOT / "benchmarks" / "blast_corpus" / "results.json"
    if blast_res.exists():
        data = json.loads(blast_res.read_text(encoding="utf-8"))
        metrics = data.get("metrics", {})
        cov_seeded = metrics.get("coverage_seeded_only", 0.0)
        cov_all = metrics.get("coverage_all", 0.0)
        is_established = (cov_seeded >= 0.95 and cov_all >= 0.90)
        claims["blast_radius_bounds"] = {
            "status": "ESTABLISHED" if is_established else "MEASURED",
            "coverage_seeded_only": cov_seeded,
            "coverage_all": cov_all,
        }
    else:
        missing_benchmarks.append("blast_radius_bounds")
        claims["blast_radius_bounds"] = {
            "status": "MISSING",
            "error": "benchmarks/blast_corpus/results.json not found",
        }

    # Determine overall claim status across all evaluated claims
    all_statuses = [c["status"] for c in claims.values()]
    if missing_benchmarks:
        overall = "UNESTABLISHED"
    elif not all_statuses:
        overall = "INCONCLUSIVE"
    elif all(s == "ESTABLISHED" for s in all_statuses):
        overall = "ESTABLISHED"
    else:
        overall = "UNESTABLISHED"

    return {"overall_status": overall, "claims": claims, "missing_benchmarks": missing_benchmarks}


def main():
    env = get_environment_metadata()
    evaluation = evaluate_claims()

    bundle = {
        "schema_version": "1.0",
        "timestamp": env["timestamp_utc"],
        "overall_status": evaluation["overall_status"],
        "environment": env,
        "claims": evaluation["claims"],
    }

    out_dir = ROOT / "evidence"
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / "evidence-bundle.json"
    out_file.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"Evidence bundle written to {out_file}")

    # Generate GitHub Step Summary if running in CI
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(f"## VerifyCI Evidence Report: {bundle['overall_status']}\n\n")
            f.write(f"- **Commit**: `{env['commit'][:8]}`\n")
            f.write(f"- **Python**: `{env['python_version']}` ({env['platform']})\n")
            f.write(f"- **Timestamp**: `{env['timestamp_utc']}`\n\n")
            f.write("| Claim | Status | Summary |\n")
            f.write("| :--- | :---: | :--- |\n")
            for name, details in evaluation["claims"].items():
                status_icon = "ESTABLISHED" if details["status"] == "ESTABLISHED" else "MEASURED"
                summary_text = ", ".join(f"{k}: {v}" for k, v in details.items() if k != "status")
                f.write(f"| **{name}** | `{status_icon}` | {summary_text} |\n")


if __name__ == "__main__":
    main()
