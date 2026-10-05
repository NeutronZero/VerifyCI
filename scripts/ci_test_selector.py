#!/usr/bin/env python3
"""Change-aware test selector with invariant fail-closed guarantee."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Permanent Core Invariant Set: ALWAYS executed on every run regardless of diff
CORE_INVARIANTS = [
    "tests/contracts/",
    "tests/verification/test_removal.py",
    "tests/verification/test_ungrounded_policy.py",
    "tests/interface/test_probe_infra_errors.py",
    "tests/storage/test_probe_a6_temporal_integrity.py",
    "tests/performance/test_performance_benchmarks.py",
]

# Source path to test directory mapping
PATH_MAPPING = {
    "verifyci/contracts/": ["tests/contracts/"],
    "verifyci/graph/": ["tests/graph/"],
    "verifyci/ingestion/": ["tests/ingestion/"],
    "verifyci/interface/": ["tests/interface/"],
    "verifyci/memory/": ["tests/memory/"],
    "verifyci/observability/": ["tests/observability/"],
    "verifyci/orchestration/": ["tests/orchestration/"],
    "verifyci/retrieval/": ["tests/retrieval/"],
    "verifyci/storage/": ["tests/storage/"],
    "verifyci/verification/": ["tests/verification/"],
    "benchmarks/": ["tests/evaluation/"],
}

# Changes that trigger the FULL test suite
FULL_RUN_TRIGGERS = [
    "pyproject.toml",
    ".github/",
    ".gitattributes",
    "tests/conftest.py",
    "scripts/",
]


def get_changed_files(base_ref: str = "origin/main") -> list[str]:
    """Retrieve list of files changed against base reference using git."""
    # Attempt 1: git diff against base_ref...HEAD (e.g. in PR context)
    for cmd in (
        ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
        ["git", "diff", "--name-only", f"{base_ref}"],
        ["git", "diff", "--name-only", "HEAD~1"],
        ["git", "status", "--porcelain"],
    ):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lines = [line.strip().split()[-1].replace("\\", "/")
                     for line in res.stdout.splitlines() if line.strip()]
            if lines:
                return lines
        except Exception:
            continue
    return []


def select_tests(changed_files: list[str]) -> list[str]:
    """Determine test paths to execute based on changed files."""
    # Empty or unable to determine diff -> run all tests safely
    if not changed_files:
        return ["tests/"]

    # Check for root/config triggers that require full test run
    for trigger in FULL_RUN_TRIGGERS:
        if any(f.startswith(trigger) for f in changed_files):
            return ["tests/"]

    selected = set(CORE_INVARIANTS)

    for f in changed_files:
        norm_f = f.replace("\\", "/")
        # If a test file itself changed, include it
        if norm_f.startswith("tests/") and norm_f.endswith(".py"):
            # Check if file exists on disk (was not deleted)
            if Path(norm_f).is_file():
                selected.add(norm_f)
            continue

        # Match source paths
        for src_prefix, test_targets in PATH_MAPPING.items():
            if norm_f.startswith(src_prefix):
                selected.update(test_targets)

    return sorted(selected)


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/main"
    files = get_changed_files(base)
    targets = select_tests(files)
    print(" ".join(targets))


if __name__ == "__main__":
    main()
