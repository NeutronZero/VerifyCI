"""Deterministic canonical JSON serialization adhering strictly to RFC 8785 (JCS)."""

from __future__ import annotations

from hashlib import sha256
import math
from typing import Any, Mapping


def _serialize_str(s: str) -> bytes:
    out = bytearray(b'"')
    for ch in s:
        cp = ord(ch)
        if cp == 0x22:  # quotation mark "
            out.extend(b'\\"')
        elif cp == 0x5C:  # reverse solidus \
            out.extend(b"\\\\")
        elif cp == 0x08:  # backspace \b
            out.extend(b"\\b")
        elif cp == 0x0C:  # form feed \f
            out.extend(b"\\f")
        elif cp == 0x0A:  # line feed \n
            out.extend(b"\\n")
        elif cp == 0x0D:  # carriage return \r
            out.extend(b"\\r")
        elif cp == 0x09:  # character tabulation \t
            out.extend(b"\\t")
        elif cp < 0x20:  # control characters U+0000..U+001F
            out.extend(f"\\u{cp:04x}".encode("ascii"))
        else:
            out.extend(ch.encode("utf-8"))
    out.append(0x22)
    return bytes(out)


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
        return str(value).encode("ascii")
    if isinstance(value, float):
        return _serialize_float(value)
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


def payload_hash(value: Any) -> str:
    """Compute sha256 of the RFC 8785 canonical JSON bytes of value."""
    return "sha256:" + sha256(canonical_json_bytes(value)).hexdigest()


__all__ = ["canonical_json_bytes", "payload_hash"]
