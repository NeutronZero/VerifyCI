#!/usr/bin/env python3
"""Change-aware test selector with invariant fail-closed guarantee."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Permanent Core Invariant Set: ALWAYS executed on every run regardless of diff
CORE_INVARIANTS = [
    "tests/v3/test_gate_v3.py",
]

SAFE_TEST_TARGET_RE = re.compile(r"[A-Za-z0-9_./-]+\.py")
SAFE_TEST_DIR_RE = re.compile(r"tests/(?:[A-Za-z0-9_.-]+/)*")
SAFE_BASE_REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def validate_base_ref(base_ref: str) -> str:
    """Reject base refs that could inject git options or shell metacharacters.

    Applied before `git diff`: a leading dash enables option injection
    (e.g. --upload-pack=...), and whitespace/metacharacters would smuggle
    shell syntax into any caller that interpolates the ref.
    """
    if not base_ref:
        raise ValueError("unsafe git base ref: must be non-empty")
    if len(base_ref) > 256:
        raise ValueError(f"unsafe git base ref: too long ({len(base_ref)} chars)")
    if base_ref.startswith("-"):
        raise ValueError(f"unsafe git base ref: leading dash not allowed: {base_ref[:80]!r}")
    if not SAFE_BASE_REF_RE.fullmatch(base_ref):
        raise ValueError(f"unsafe git base ref: {base_ref[:80]!r}")
    return base_ref

# Source path to test directory mapping
PATH_MAPPING = {
    "verifyci/": [
        "tests/v3/",
    ],
}

# Changes that trigger the FULL test suite
FULL_RUN_TRIGGERS = [
    "pyproject.toml",
    ".github/",
    ".gitattributes",
    "scripts/",
    "uv.lock",
    "corpora/",
    "verifyci_release_trust/",
]


def get_changed_files(base_ref: str = "origin/main") -> list[str]:
    """Retrieve list of files changed against base reference using git."""
    if base_ref:
        validate_base_ref(base_ref)
        for cmd in (
            ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
            ["git", "diff", "--name-only", f"{base_ref}"],
        ):
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, check=True)
                lines = [
                    line.strip().replace("\\", "/")
                    for line in res.stdout.splitlines()
                    if line.strip()
                ]
                return lines
            except Exception:
                continue
        return []

    # If no base_ref is specified, check uncommitted working tree changes
    try:
        res = subprocess.run(
            ["git", "status", "--porcelain"], capture_output=True, text=True, check=True
        )
        lines = []
        for line in res.stdout.splitlines():
            if not line.strip() or len(line) < 3:
                continue
            entry = line[3:].strip().replace("\\", "/")
            if " -> " in entry:
                entry = entry.split(" -> ")[-1].strip()
            if entry:
                lines.append(entry)
        return lines
    except Exception:
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
    try:
        files = get_changed_files(base)
        targets = select_tests(files)
        validate_test_targets(targets)
    except ValueError as exc:
        # Fail closed and quietly: hostile input must not reach git/pytest.
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
    # One target per line is deliberate: the CI caller transports these through
    # a file and passes them to pytest as an argument array, never GITHUB_OUTPUT.
    print("\n".join(targets))


if __name__ == "__main__":
    main()
