"""Common git provenance extraction and dirty-tree validation across CAP harnesses."""

from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

# Canonical allowlist of files permitted to change during benchmark runs
ALLOWED_EXACT_RESULTS = {
    "benchmarks/secret_corpus/cap002b/results.json",
    "benchmarks/secret_corpus/cap002b/RESULTS.md",
    "benchmarks/removal_corpus/cap003a/results.json",
    "benchmarks/removal_corpus/cap003a/RESULTS.md",
    "benchmarks/call_semantics_corpus/cap004/results.json",
    "benchmarks/call_semantics_corpus/cap004/RESULTS.md",
    "benchmarks/patch_real/cap005/results.json",
    "benchmarks/patch_real/cap005/RESULTS.md",
    "benchmarks/temporal_corpus/cap006/results.json",
    "benchmarks/temporal_corpus/cap006/RESULTS.md",
    "benchmarks/retrieval_corpus/cap007/results.json",
    "benchmarks/retrieval_corpus/cap007/RESULTS.md",
    "benchmarks/concurrency_corpus/cap008/results.json",
    "benchmarks/concurrency_corpus/cap008/RESULTS.md",
    "benchmarks/diff_impact_corpus/cap009/results.json",
    "benchmarks/diff_impact_corpus/cap009/RESULTS.md",
    "benchmarks/retrieval_generalization/cap010/results.json",
    "benchmarks/retrieval_generalization/cap010/RESULTS.md",
    "benchmarks/secret_heldout/cap011/results.json",
    "benchmarks/secret_heldout/cap011/RESULTS.md",
    "benchmarks/repo_perf/cap012/results.json",
    "benchmarks/repo_perf/cap012/RESULTS.md",
    "benchmarks/robustness/cap013/results.json",
    "benchmarks/robustness/cap013/RESULTS.md",
    "evidence/cap-adjudication-bundle.json",
}


def is_path_exempt(path_str: str, allowed_exact: set[str] | None = None) -> bool:
    allowed = allowed_exact if allowed_exact is not None else ALLOWED_EXACT_RESULTS
    norm = path_str.strip().replace("\\", "/")
    return norm in allowed or fnmatch.fnmatchcase(norm, "benchmark-results-*.json")


def get_git_provenance(
    repo_root: Path | None = None, allowed_exact: set[str] | None = None
) -> tuple[str, bool]:
    root = repo_root or Path(__file__).resolve().parent.parent.parent

    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip()
    except Exception as exc:
        raise RuntimeError(f"Failed to obtain git commit provenance: {exc}") from exc

    if not commit or commit == "unknown":
        raise RuntimeError("Git commit provenance is invalid or unknown")

    try:
        raw_z = subprocess.check_output(
            ["git", "status", "--porcelain", "-z"], cwd=root
        )
    except Exception as exc:
        raise RuntimeError(
            f"Failed to obtain git status for provenance: {exc}"
        ) from exc

    dirty = False
    tokens = raw_z.split(b"\0")
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if not t:
            i += 1
            continue
        if len(t) < 3:
            dirty = True
            break
        status = t[:2].decode("utf-8", errors="replace")
        p1 = t[3:].decode("utf-8", errors="replace")
        if "R" in status or "C" in status:
            if i + 1 < len(tokens):
                i += 1
                p2 = tokens[i].decode("utf-8", errors="replace")
                if not (
                    is_path_exempt(p1, allowed_exact)
                    and is_path_exempt(p2, allowed_exact)
                ):
                    dirty = True
                    break
            else:
                dirty = True
                break
        else:
            if not is_path_exempt(p1, allowed_exact):
                dirty = True
                break
        i += 1

    return commit, dirty
