#!/usr/bin/env python3
"""Generates structured evidence bundle using canonical claim predicates."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import time
from pathlib import Path

from verifyci.evidence.claims import evaluate_claims as _evaluate_claims

ROOT = Path(__file__).resolve().parent.parent


def get_environment_metadata() -> dict:
    """Capture forensic execution environment metadata."""
    try:
        git_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        git_sha = "unknown"

    branch = os.environ.get("GITHUB_REF_NAME", "local")
    pyproject_bytes = (ROOT / "pyproject.toml").read_bytes() if (ROOT / "pyproject.toml").exists() else b""
    lock_path = ROOT / "uv.lock"
    lock_bytes = lock_path.read_bytes() if lock_path.exists() else b""

    return {
        "commit": git_sha,
        "branch": branch,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pyproject_sha256": hashlib.sha256(pyproject_bytes).hexdigest(),
        "uv_lock_sha256": hashlib.sha256(lock_bytes).hexdigest() if lock_bytes else None,
        "resolved_versions": {
            dist.metadata["Name"]: dist.version
            for dist in sorted(importlib.metadata.distributions(), key=lambda d: (d.metadata["Name"] or "").lower())
        },
    }


def evaluate_claims(root: Path | None = None) -> dict:
    """Evaluate claims using the canonical evidence predicates."""
    return _evaluate_claims(ROOT if root is None else root)


def main():
    env = get_environment_metadata()
    evaluation = evaluate_claims()

    bundle = {
        "schema_version": "1.0",
        "timestamp": env["timestamp_utc"],
        "overall_status": evaluation["overall_status"],
        "environment": env,
        "claims": evaluation["claims"],
        "missing_benchmarks": evaluation["missing_benchmarks"],
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
                status_icon = details["status"]
                summary_text = ", ".join(f"{k}: {v}" for k, v in details.items() if k != "status")
                f.write(f"| **{name}** | `{status_icon}` | {summary_text} |\n")


if __name__ == "__main__":
    main()
