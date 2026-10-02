"""Single source of truth for which paths ingestion skips.

Every discovery path (source collection, manifest collection, `aci deps`)
must agree: a path classified as skipped must not become an indexed
entity or dependency merely because it is discovered through a different
code path. The old split had `deps` matching absolute path parts while
ingest matched repo-relative parts, so `node_modules/`, `.venv/`,
`build/` manifests leaked into `aci deps` output.

Defaults cover only unambiguous markers (VCS metadata, tool caches,
installed dependencies, venvs). Ambiguous names that are legitimate
package names in some repos (`build`, `dist`, `target`, `env`) are NOT
skipped by default; projects re-skip them via a `.verifyciignore` file
(gitignore-style) at the repo root.
"""
import fnmatch
import os
from pathlib import Path
from typing import Iterator

#: Directory names never walked, whatever the repo (unambiguous markers).
DEFAULT_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", ".nox", ".eggs",
    "node_modules",
    ".verifyci",
    ".idea", ".vscode",
})

IGNORE_FILE = ".verifyciignore"
_VENV_MARKER = "pyvenv.cfg"


def _load_patterns(repo: Path) -> list[str]:
    path = repo / IGNORE_FILE
    if not path.is_file():
        return []
    patterns = []
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    except OSError:
        return []
    return patterns


def _name_matches(name: str, patterns: list[str]) -> bool:
    """A bare pattern (no slash) matches by directory/file name anywhere."""
    for pat in patterns:
        p = pat.rstrip("/")
        if "/" in p:
            continue
        if fnmatch.fnmatchcase(name, p):
            return True
    return False


def _rel_matches(rel_posix: str, patterns: list[str]) -> bool:
    for pat in patterns:
        p = pat.rstrip("/")
        if "/" not in p and "*" not in p:
            continue
        if fnmatch.fnmatchcase(rel_posix, p):
            return True
        # `docs/` also prunes everything beneath docs.
        if fnmatch.fnmatchcase(rel_posix, p + "/**"):
            return True
    return False


def iter_repo_files(repo: Path) -> Iterator[Path]:
    """Yield files under ``repo`` that ingestion should consider.

    Prunes skipped directories before descending (so a skipped tree is
    never walked), detects virtualenvs by ``pyvenv.cfg`` rather than by
    guessing a name, and applies ``.verifyciignore``.
    """
    repo = Path(repo)
    patterns = _load_patterns(repo)
    for root, dirs, files in os.walk(repo):
        root_path = Path(root)
        kept = []
        for d in sorted(dirs):
            if d in DEFAULT_SKIP_DIRS or _name_matches(d, patterns):
                continue
            child = root_path / d
            if (child / _VENV_MARKER).is_file():
                continue  # virtualenv: never ingest its site-packages
            rel = child.relative_to(repo).as_posix()
            if _rel_matches(rel, patterns):
                continue
            kept.append(d)
        dirs[:] = kept
        for name in sorted(files):
            fpath = root_path / name
            rel = fpath.relative_to(repo).as_posix()
            if _name_matches(name, patterns) or _rel_matches(rel, patterns):
                continue
            yield fpath


def skipped_dir_names(repo: Path) -> list[str]:
    """Names of directories pruned at the top level (for ingest reporting)."""
    repo = Path(repo)
    patterns = _load_patterns(repo)
    out = []
    try:
        for child in sorted(repo.iterdir()):
            if not child.is_dir():
                continue
            if (child.name in DEFAULT_SKIP_DIRS
                    or _name_matches(child.name, patterns)
                    or (child / _VENV_MARKER).is_file()
                    or _rel_matches(child.name, patterns)):
                out.append(child.name)
    except OSError:
        return []
    return out