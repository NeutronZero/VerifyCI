"""Centralized ingress validation and resource boundary enforcement.

Guarantees identical fail-closed validation across CLI, MCP, FastMCP, and HTTP
interfaces. Prevents cap-bypasses or premature parsing of oversized/malformed inputs.
"""
from __future__ import annotations


from verifyci.interface.limits import (
    MAX_DIFF_CHARS,
    MAX_K,
    MAX_QUERY_CHARS,
    MAX_TASK_DIFF_CHARS,
)


class IngressValidationError(ValueError):
    """Raised when an ingress request violates schema, size, or safety bounds."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def validate_diff_ingress(diff: str, max_chars: int = MAX_DIFF_CHARS) -> str:
    """Validate incoming unified diff text before any AST or diff parsing occurs."""
    if not isinstance(diff, str):
        raise IngressValidationError("invalid_type", "diff must be a string")
    if len(diff) > max_chars:
        raise IngressValidationError("diff_too_large", f"diff exceeds maximum size of {max_chars} characters")
    return diff


def validate_task_ingress(task: str, diff: str = "") -> tuple[str, str]:
    """Validate task description and optional accompanying diff before orchestration."""
    if not isinstance(task, str):
        raise IngressValidationError("invalid_type", "task must be a string")
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
    if not isinstance(k, int) or k < 1 or k > MAX_K:
        raise IngressValidationError("invalid_k", f"k must be an integer between 1 and {MAX_K}")
    return query, k
