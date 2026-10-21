"""Diagnostic and structured event logging without wall-clock drift."""

from __future__ import annotations

from typing import Any


def format_diagnostic(code: str, detail: str, **kwargs: Any) -> dict[str, Any]:
    diag: dict[str, Any] = {"code": code, "detail": detail}
    if kwargs:
        diag["metadata"] = kwargs
    return diag
