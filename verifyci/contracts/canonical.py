"""Deterministic canonical JSON serialization adhering strictly to RFC 8785 (JCS) and SHA-256 helpers."""

from __future__ import annotations

import decimal
from hashlib import sha256
import json
import math
from typing import Any, Mapping


def _serialize_str(s: str) -> bytes:
    return json.dumps(s, ensure_ascii=False).encode("utf-8")


def _serialize_float(v: float) -> bytes:
    """Format IEEE 754 float conforming to ECMAScript 6 (RFC 8785 Section 3.2.2.3)."""
    if math.isnan(v) or math.isinf(v):
        raise ValueError("NaN and Infinity are not permitted in RFC 8785 JSON")
    if v == 0.0:
        return b"0"
    sign = b"-" if v < 0 else b""
    v = abs(v)
    r = repr(v)
    if "e" in r.lower():
        parts = r.lower().split("e")
        m_str = parts[0].replace(".", "")
        e_val = int(parts[1])
        n = e_val + 1
        k = len(m_str)
        if -6 < n <= 0:
            zeros = "0" * (-n)
            res = f"0.{zeros}{m_str}"
        elif 0 < n <= 21:
            if n >= k:
                zeros = "0" * (n - k)
                res = f"{m_str}{zeros}"
            else:
                res = f"{m_str[:n]}.{m_str[n:]}"
        else:
            exp_sign = "+" if n - 1 >= 0 else "-"
            exp_num = abs(n - 1)
            if k == 1:
                res = f"{m_str}e{exp_sign}{exp_num}"
            else:
                res = f"{m_str[0]}.{m_str[1:]}e{exp_sign}{exp_num}"
        return sign + res.encode("ascii")

    if r.endswith(".0"):
        int_val = int(v)
        s_int = str(int_val)
        if len(s_int) > 21:
            n = len(s_int)
            res = f"{s_int[0]}.{s_int[1:].rstrip('0')}e+{n - 1}"
            return sign + res.encode("ascii")
        return sign + s_int.encode("ascii")

    return sign + r.encode("ascii")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize value to canonical JSON UTF-8 bytes conforming to RFC 8785 (JCS)."""
    if value is None:
        return b"null"
    if isinstance(value, bool):
        return b"true" if value else b"false"
    if isinstance(value, int):
        if value < -9007199254740991 or value > 9007199254740991:
            raise ValueError(
                f"Integer {value} exceeds RFC 8785 safe integer limit [-(2^53 - 1), 2^53 - 1]; "
                "values requiring higher precision must be encoded as strings."
            )
        return str(value).encode("ascii")
    if isinstance(value, float):
        return _serialize_float(value)
    if isinstance(value, decimal.Decimal):
        if not value.is_finite():
            raise ValueError(f"non-finite Decimal: {value}")
        return _serialize_float(float(value))
    if isinstance(value, str):
        return _serialize_str(value)
    if isinstance(value, Mapping):
        # RFC 8785 Section 3.2.3: Sort keys by UTF-16 code units
        for k in value:
            if not isinstance(k, str):
                raise TypeError(f"RFC 8785 requires string dictionary keys, got {type(k).__name__}")
        sorted_keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        parts: list[bytes] = []
        for k in sorted_keys:
            parts.append(_serialize_str(k) + b":" + canonical_json_bytes(value[k]))
        return b"{" + b",".join(parts) + b"}"
    if isinstance(value, (list, tuple)):
        parts = [canonical_json_bytes(item) for item in value]
        return b"[" + b",".join(parts) + b"]"
    raise TypeError(f"Unsupported type for RFC 8785 canonical serialization: {type(value).__name__}")


def sha256_prefixed(data: bytes) -> str:
    """Return ``sha256:<hex>`` digest of raw bytes."""
    return "sha256:" + sha256(data).hexdigest()


def payload_hash(value: Any) -> str:
    """Compute sha256 of the RFC 8785 canonical JSON bytes of value."""
    return sha256_prefixed(canonical_json_bytes(value))


def is_valid_hex64(value: Any) -> bool:
    """Return True if value is a 64-character lowercase hexadecimal digest."""
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


def is_hex40(value: Any) -> bool:
    """Return True if value is a 40-character hexadecimal SHA-1 string."""
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(ch in "0123456789abcdefABCDEF" for ch in value)
    )


def is_valid_sha256(value: Any) -> bool:
    """Return True if value is a ``sha256:<64-hex>`` digest string."""
    return isinstance(value, str) and value.startswith("sha256:") and is_valid_hex64(value[7:])


__all__ = [
    "canonical_json_bytes",
    "is_hex40",
    "is_valid_hex64",
    "is_valid_sha256",
    "payload_hash",
    "sha256_prefixed",
]
