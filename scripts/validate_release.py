#!/usr/bin/env python3
"""Release validation suite for VerifyCI v2.0."""
from __future__ import annotations

import subprocess
import sys


def run_step(cmd: list[str], desc: str) -> None:
    print(f"=== {desc} ===")
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print(f"FAILED: {desc} (exit code {res.returncode})", file=sys.stderr)
        sys.exit(res.returncode)


def main() -> None:
    run_step([sys.executable, "-m", "ruff", "check", "verifyci_v2", "benchmarks/common", "tests/v2", "scripts"], "Ruff Linting")
    run_step([sys.executable, "-m", "pytest", "tests/v2", "-q"], "Pytest V2 Suite")
    run_step([sys.executable, "scripts/build_evidence_bundle.py"], "Evidence Bundle Generation")
    print("\nAll release validation gates passed successfully.")


if __name__ == "__main__":
    main()
