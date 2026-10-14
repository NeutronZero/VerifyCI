from __future__ import annotations

from dataclasses import asdict, is_dataclass
import hashlib
import math
import struct
from typing import Any

try:
    import blake3 as _blake3_mod  # type: ignore[import-untyped]
except ImportError:
    _blake3_mod = None

try:
    import xxhash as _xxhash_mod  # type: ignore[import-untyped]
except ImportError:
    _xxhash_mod = None


class CanonicalSerializationError(ValueError):
    """Raised when an object violates RFC 8785 (JCS) canonicalization rules."""


def _utf16_sort_key(key: str) -> bytes:
    """RFC 8785 Section 3.2.3 requires sorting object keys by UTF-16BE code units."""
    return key.encode("utf-16-be")


def _escape_jcs_string(value: str) -> str:
    """RFC 8785 Section 3.2.2 string escaping."""
    out: list[str] = ['"']
    for ch in value:
        code = ord(ch)
        if code == 0x08:
            out.append("\\b")
        elif code == 0x09:
            out.append("\\t")
        elif code == 0x0A:
            out.append("\\n")
        elif code == 0x0C:
            out.append("\\f")
        elif code == 0x0D:
            out.append("\\r")
        elif code == 0x22:
            out.append('\\"')
        elif code == 0x5C:
            out.append("\\\\")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _format_jcs_float(value: float) -> str:
    """RFC 8785 Section 3.2.2.3 IEEE 754 double-precision number serialization."""
    if math.isnan(value) or math.isinf(value):
        raise CanonicalSerializationError("RFC 8785 forbids NaN and Infinity in canonical JSON")
    if value == 0.0:
        return "0"
    abs_val = abs(value)
    if 1e-6 <= abs_val < 1e21:
        formatted = repr(value)
        if "e" not in formatted and "E" not in formatted:
            if formatted.endswith(".0"):
                return formatted[:-2]
            return formatted
    # Exponential notation normalized per ES6 / RFC 8785
    formatted = repr(value).lower()
    if "e" in formatted:
        mantissa, exp_str = formatted.split("e", 1)
        if mantissa.endswith(".0"):
            mantissa = mantissa[:-2]
        exp_val = int(exp_str)
        sign = "+" if exp_val >= 0 else "-"
        return f"{mantissa}e{sign}{abs(exp_val)}"
    return formatted


def _to_jcs_str(obj: Any) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        return _format_jcs_float(obj)
    if isinstance(obj, str):
        return _escape_jcs_string(obj)
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return _escape_jcs_string(bytes(obj).hex())
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_to_jcs_str(item) for item in obj) + "]"
    if isinstance(obj, dict):
        items: list[tuple[str, Any]] = []
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalSerializationError(
                    f"RFC 8785 requires string dictionary keys, got {type(k).__name__}"
                )
            items.append((k, v))
        items.sort(key=lambda kv: _utf16_sort_key(kv[0]))
        return (
            "{"
            + ",".join(f"{_escape_jcs_string(k)}:{_to_jcs_str(v)}" for k, v in items)
            + "}"
        )
    if is_dataclass(obj) and not isinstance(obj, type):
        return _to_jcs_str(asdict(obj))
    if hasattr(obj, "__struct_fields__"):
        struct_dict = {field: getattr(obj, field) for field in obj.__struct_fields__}
        return _to_jcs_str(struct_dict)
    raise CanonicalSerializationError(f"Unsupported type for RFC 8785 JCS: {type(obj).__name__}")


def canonical_jcs_str(obj: Any) -> str:
    """Serializes an arbitrary contract structure into an RFC 8785 canonical JSON string."""
    return _to_jcs_str(obj)


def canonical_jcs_bytes(obj: Any) -> bytes:
    """Serializes an arbitrary contract structure into UTF-8 RFC 8785 canonical JSON bytes."""
    return _to_jcs_str(obj).encode("utf-8")


def xxh3_64_hex(data: bytes | str) -> str:
    """Fast 64-bit non-cryptographic content fingerprint for file-change detection."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if _xxhash_mod is not None:
        return str(_xxhash_mod.xxh3_64_hexdigest(raw))
    return hashlib.blake2s(raw, digest_size=8, person=b"vc2_xxh3").hexdigest()


def blake3_bytes(data: bytes | str, *, domain: str = "verifyci.v2") -> bytes:
    """Domain-separated 256-bit cryptographic digest for Merkle and Salsa identities."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    domain_bytes = domain.encode("utf-8")
    framed = struct.pack(">I", len(domain_bytes)) + domain_bytes + raw
    if _blake3_mod is not None:
        return bytes(_blake3_mod.blake3(framed).digest())
    return hashlib.blake2b(framed, digest_size=32).digest()


def blake3_hex(data: bytes | str, *, domain: str = "verifyci.v2") -> str:
    """Hex-encoded 256-bit domain-separated cryptographic digest."""
    return blake3_bytes(data, domain=domain).hex()


def canonical_digest(obj: Any, *, domain: str = "verifyci.v2.contract") -> str:
    """Computes the domain-separated cryptographic digest of an RFC 8785 JCS payload."""
    return blake3_hex(canonical_jcs_bytes(obj), domain=domain)