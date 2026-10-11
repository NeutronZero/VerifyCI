"""Centralized ingress validation and resource boundary enforcement.

Guarantees identical fail-closed validation across CLI, MCP, FastMCP, and HTTP
interfaces. Prevents cap-bypasses or premature parsing of oversized/malformed inputs.
"""
from __future__ import annotations


import os
from pathlib import Path

from verifyci.interface.limits import (
    MAX_CHANGED_FILES,
    MAX_CHANGED_LINES,
    MAX_DIFF_CHARS,
    MAX_K,
    MAX_QUERY_CHARS,
    MAX_TASK_DIFF_CHARS,
)

__all__ = [
    "IngressValidationError",
    "validate_diff_complexity",
    "validate_diff_ingress",
    "validate_task_ingress",
    "validate_query_ingress",
    "validate_safe_path",
    "validate_safe_db_path",
]


class IngressValidationError(ValueError):
    """Raised when an ingress request violates schema, size, or safety bounds."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def validate_diff_complexity(
    diff: str,
    max_files: int = MAX_CHANGED_FILES,
    max_lines: int = MAX_CHANGED_LINES,
) -> None:
    """Stateful single-pass pre-scan enforcing file and changed line limits before AST parsing.

    Recognizes git and unified diff headers, /dev/null additions/deletions, renames,
    and hunk boundaries without full parsing.
    """
    if not diff:
        return

    in_hunk = False
    files_seen = 0
    changed_lines = 0
    in_git_file = False

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            in_hunk = False
            in_git_file = True
            files_seen += 1
            if files_seen > max_files:
                raise IngressValidationError(
                    "diff_too_many_files",
                    f"diff modifies {files_seen} files, exceeding limit of {max_files}",
                )
            continue

        if not in_git_file and line.startswith(("--- a/", "--- /dev/null")):
            in_hunk = False
            files_seen += 1
            if files_seen > max_files:
                raise IngressValidationError(
                    "diff_too_many_files",
                    f"diff modifies {files_seen} files, exceeding limit of {max_files}",
                )
            continue

        if line.startswith("+++ "):
            continue

        if line.startswith("@@ ") and " @@" in line[3:]:
            in_hunk = True
            in_git_file = False
            continue

        if in_hunk:
            if line.startswith("+") and not line.startswith("+++ "):
                changed_lines += 1
            elif line.startswith("-") and not line.startswith("--- "):
                changed_lines += 1

            if changed_lines > max_lines:
                raise IngressValidationError(
                    "diff_too_many_lines",
                    f"diff contains {changed_lines} changed lines, exceeding limit of {max_lines}",
                )


def validate_diff_ingress(diff: str, max_chars: int = MAX_DIFF_CHARS,
                          max_files: int = MAX_CHANGED_FILES,
                          max_lines: int = MAX_CHANGED_LINES) -> str:
    """Validate incoming unified diff text and complexity before any AST or diff parsing occurs."""
    if not isinstance(diff, str):
        raise IngressValidationError("invalid_type", "diff must be a string")
    if len(diff) > max_chars:
        raise IngressValidationError("diff_too_large", f"diff exceeds maximum size of {max_chars} characters")
    validate_diff_complexity(diff, max_files=max_files, max_lines=max_lines)
    return diff



def validate_task_ingress(task: str, diff: str = "") -> tuple[str, str]:
    """Validate task description and optional accompanying diff before orchestration."""
    if not isinstance(task, str):
        raise IngressValidationError("invalid_type", "task must be a string")
    if not isinstance(diff, str):
        raise IngressValidationError("invalid_type", "diff must be a string")
    if len(task) > MAX_TASK_DIFF_CHARS:
        raise IngressValidationError("task_too_large", f"task exceeds maximum size of {MAX_TASK_DIFF_CHARS} characters")
    if diff:
        validate_diff_ingress(diff, max_chars=MAX_TASK_DIFF_CHARS)
    return task, diff


def validate_query_ingress(query: str, k: int = 10) -> tuple[str, int]:
    """Validate search/retrieval query and k parameter."""
    if not isinstance(query, str):
        raise IngressValidationError("invalid_type", "query must be a string")
    if len(query) > MAX_QUERY_CHARS:
        raise IngressValidationError("query_too_large", f"query exceeds maximum size of {MAX_QUERY_CHARS} characters")
    if isinstance(k, bool) or not isinstance(k, int) or k < 1 or k > MAX_K:
        raise IngressValidationError("invalid_k", f"k must be an integer between 1 and {MAX_K}")
    return query, k



def validate_safe_path(
    path: str | Path,
    base_dir: str | Path | None = None,
    allowed_extensions: tuple[str, ...] | None = None,
) -> Path:
    """Validate that a filesystem path is safe against directory traversal and escapes."""
    if not isinstance(path, (str, Path)):
        raise IngressValidationError("invalid_type", "path must be a string or Path")
    p_str = str(path)
    if "\x00" in p_str:
        raise IngressValidationError("invalid_path", "path must not contain null bytes")
    p = Path(path)
    if ".." in p.parts:
        raise IngressValidationError("path_traversal", "path must not contain parent traversals ('..')")
    if allowed_extensions is not None:
        if p.suffix.lower() not in [ext.lower() for ext in allowed_extensions]:
            raise IngressValidationError(
                "invalid_extension",
                f"path extension '{p.suffix}' not in allowed extensions {allowed_extensions}",
            )
    if base_dir is not None:
        base = Path(base_dir).resolve()
        try:
            resolved = (base / p).resolve() if not p.is_absolute() else p.resolve()
            if not resolved.is_relative_to(base):
                raise IngressValidationError("path_escape", f"path escapes base directory '{base}'")
            return resolved
        except (ValueError, RuntimeError) as exc:
            raise IngressValidationError("path_escape", f"failed to resolve safe path: {exc}")
    return p.resolve()


def validate_safe_db_path(db: str | None, repo_root: Path | None = None) -> str | None:
    """Validate database path to prevent path traversal and arbitrary filesystem access.

    Raises IngressValidationError with code 'invalid_db_path' if the path is unsafe.
    Returns resolved absolute path as string, or None if db is empty.
    """
    if db is None or db == "":
        return None
    if not isinstance(db, str):
        raise IngressValidationError("invalid_db_path", "db path must be a string")
    if "\x00" in db:
        raise IngressValidationError("invalid_db_path", "db path contains null bytes")
    p = Path(db)
    if ".." in p.parts:
        raise IngressValidationError("invalid_db_path", "db path must not contain parent traversals")
    if p.suffix.lower() != ".db":
        raise IngressValidationError("invalid_db_path", "db path must have .db extension")

    root = (
        repo_root.resolve()
        if repo_root is not None
        else Path(os.environ.get("VERIFYCI_ROOT", os.getcwd())).resolve()
    )
    allowed_dir = (root / ".verifyci").resolve()
    try:
        resolved = (root / p).resolve() if not p.is_absolute() else p.resolve()
        if not resolved.is_relative_to(allowed_dir):
            raise IngressValidationError("invalid_db_path", "db path must reside within repo's .verifyci directory")
    except (ValueError, RuntimeError) as exc:
        raise IngressValidationError("invalid_db_path", f"invalid db path resolution: {exc}")
    return str(resolved)
