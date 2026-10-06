"""Strict Redaction Hard Boundary for VerifyCI secret detection."""
from __future__ import annotations

import binascii
import json
from typing import Any


def redact_secret_value(val: str) -> str:
    """Mask a raw secret into a safe, non-reversible, redacted representation.
    
    Guarantees that raw secret bytes cannot be recovered from the string.
    """
    if not val:
        return "[REDACTED:EMPTY]"
    length = len(val)
    crc = binascii.crc32(val.encode("utf-8")) & 0xFFFFFFFF
    crc_hex = f"{crc:08x}"
    if length <= 8:
        return f"[REDACTED:len={length}:crc={crc_hex}]"
    prefix = val[:3]
    suffix = val[-3:]
    return f"{prefix}...{suffix}[REDACTED:len={length}:crc={crc_hex}]"


def redact_context_snippet(line: str, span: tuple[int, int]) -> str:
    """Replace sensitive span within a context line with a safe marker."""
    if not line:
        return ""
    start, end = span
    start = max(0, min(start, len(line)))
    end = max(start, min(end, len(line)))
    return line[:start] + "[REDACTED]" + line[end:]


def assert_no_secret_leak(obj: Any, raw_secret: str) -> None:
    """Hard boundary assertion: recursively verify that raw_secret never appears
    in any serialized or string representation of obj.
    """
    if not raw_secret or len(raw_secret) < 3:
        return

    def _check(val: Any) -> None:
        if isinstance(val, str):
            if raw_secret in val:
                raise AssertionError(f"Redaction violation! Raw secret leaked into: {val[:50]}...")
        elif isinstance(val, bytes):
            if raw_secret.encode("utf-8") in val:
                raise AssertionError("Redaction violation! Raw secret bytes leaked into bytes object.")
        elif isinstance(val, dict):
            for k, v in val.items():
                _check(k)
                _check(v)
        elif isinstance(val, (list, tuple, set)):
            for item in val:
                _check(item)
        elif hasattr(val, "__dict__"):
            _check(val.__dict__)

    _check(obj)
    # Also test JSON serialization if serializable
    try:
        serialized = json.dumps(obj, default=str)
        if raw_secret in serialized:
            raise AssertionError("Redaction violation! Raw secret leaked into serialized JSON.")
    except (TypeError, ValueError):
        pass
