#!/usr/bin/env python3
"""Change-aware test selector with invariant fail-closed guarantee."""
from __future__ import annotations

import re
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
]

SAFE_TEST_TARGET_RE = re.compile(r"[A-Za-z0-9_./-]+\.py")
SAFE_TEST_DIR_RE = re.compile(r"tests/(?:[A-Za-z0-9_.-]+/)*")

# Source path to test directory mapping
PATH_MAPPING = {
    "verifyci/contracts/": ["tests/contracts/"],
    "verifyci/export/": ["tests/export/"],
    "verifyci/graph/": ["tests/graph/"],
    "verifyci/ingestion/": ["tests/ingestion/"],
    "verifyci/interface/": ["tests/interface/", "tests/integration/"],
    "verifyci/memory/": ["tests/memory/"],
    "verifyci/observability/": ["tests/observability/"],
    "verifyci/orchestration/": ["tests/orchestration/"],
    "verifyci/retrieval/": ["tests/retrieval/"],
    "verifyci/storage/": ["tests/storage/"],
    "verifyci/verification/": ["tests/verification/"],
    "benchmarks/": ["tests/evaluation/"],
    "benchmarks/latency/": ["tests/performance/"],
}

# Changes that trigger the FULL test suite
FULL_RUN_TRIGGERS = [
    "pyproject.toml",
    ".github/",
    ".gitattributes",
    "scripts/",
]


def get_changed_files(base_ref: str = "origin/main") -> list[str]:
    """Retrieve list of files changed against base reference using git."""
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
    if not changed_files:
        return ["tests/"]

    for trigger in FULL_RUN_TRIGGERS:
        if any(f.startswith(trigger) for f in changed_files):
            return ["tests/"]

    selected = set(CORE_INVARIANTS)

    for f in changed_files:
        norm_f = f.replace("\\", "/")
        if norm_f.startswith("tests/") and norm_f.endswith(".py"):
            if Path(norm_f).is_file():
                selected.add(norm_f)
            continue

        for src_prefix, test_targets in PATH_MAPPING.items():
            if norm_f.startswith(src_prefix):
                selected.update(test_targets)

    return sorted(selected)


def validate_test_targets(targets: list[str]) -> list[str]:
    """Allow only repository-relative test paths with safe characters.

    Accepts directory targets (e.g. tests/, tests/interface/) and .py files.
    """
    for target in targets:
        path = Path(target)
        if any(part == ".." for part in path.parts):
            raise ValueError(f"unsafe pytest target: {target!r}")
        if target.endswith("/"):
            if not SAFE_TEST_DIR_RE.fullmatch(target):
                raise ValueError(f"unsafe pytest target: {target!r}")
            continue
        if not SAFE_TEST_TARGET_RE.fullmatch(target):
            raise ValueError(f"unsafe pytest target: {target!r}")
        if not target.startswith("tests/"):
            raise ValueError(f"unsafe pytest target: {target!r}")
    return targets


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "origin/main"
    files = get_changed_files(base)
    targets = select_tests(files)
    validate_test_targets(targets)
    # One target per line is deliberate: the CI caller transports these through
    # a file and passes them to pytest as an argument array, never GITHUB_OUTPUT.
    print("\n".join(targets))


if __name__ == "__main__":
    main()
