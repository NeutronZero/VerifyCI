from __future__ import annotations

import json
import msgspec
from dataclasses import is_dataclass
import functools
import math
import re
import struct
from typing import Any

import blake3
import xxhash

# Digest algorithm identity.
#
# These digests are load-bearing: `node_uid`, `edge_uid`, `finding_id`, every
# Merkle root, and every gittuf RSL entry hash derive from them. Both
# implementations are therefore hard dependencies, imported unconditionally
# rather than selected by "is the optional package importable?". A silent
# fallback here would re-hash the entire corpus for anyone whose environment
# differed, invalidating stored `.vc2` files and previously emitted
# attestations with no error and no diagnostic.
#
# The algorithm identifiers are recorded in the attestation predicate so a
# verifier can tell from the evidence alone how those identifiers were
# computed.
CONTENT_DIGEST_ALGORITHM = "blake3-256"
FINGERPRINT_ALGORITHM = "xxh3-64"


class CanonicalSerializationError(ValueError):
    """Raised when an object violates RFC 8785 (JCS) canonicalization rules."""


@functools.lru_cache(maxsize=4096)
def _utf16_sort_key(key: str) -> bytes:
    """RFC 8785 Section 3.2.3 requires sorting object keys by UTF-16BE code units."""
    return key.encode("utf-16-be")


_NEED_ESCAPE_RE = re.compile(r'[\x00-\x1f\\"]')


def _escape_jcs_string(value: str) -> str:
    """RFC 8785 Section 3.2.2 string escaping."""
    if not _NEED_ESCAPE_RE.search(value):
        return f'"{value}"'
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
        raise CanonicalSerializationError(
            "RFC 8785 forbids NaN and Infinity in canonical JSON"
        )
    if value == 0.0:
        return "0"
    abs_v = abs(value)
    if abs_v < 1e21 and value.is_integer():
        return str(int(value))
    rep = repr(value)
    if "e" in rep or "E" in rep:
        parts = rep.lower().split("e")
        mantissa = parts[0]
        exp = int(parts[1])
        sign = "-" if value < 0 else ""
        mantissa = mantissa.lstrip("-")
        if -6 <= exp < 0:
            digits = mantissa.replace(".", "")
            zeros = "0" * (-exp - 1)
            return f"{sign}0.{zeros}{digits}"
        elif 0 <= exp < 21:
            digits = mantissa.replace(".", "")
            dot_idx = mantissa.find(".")
            if dot_idx == -1:
                dot_idx = len(mantissa)
            shift = dot_idx + exp
            if shift >= len(digits):
                return sign + digits + "0" * (shift - len(digits))
            else:
                return f"{sign}{digits[:shift]}.{digits[shift:]}"
        else:
            m = parts[0]
            if m.endswith(".0"):
                m = m[:-2]
            exp_sign = "+" if exp >= 0 else "-"
            return f"{m}e{exp_sign}{abs(exp)}"
    return rep


_FAST_JCS_TYPES = (str, int, bool, type(None), list, tuple, dict)


def _has_custom_jcs_types(obj: Any) -> bool:
    if obj is None or isinstance(obj, (int, bool)):
        return False
    if isinstance(obj, str):
        return any(ord(c) > 0xFFFF for c in obj)
    if isinstance(obj, float):
        return True
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return True
    if isinstance(obj, (list, tuple)):
        return any(_has_custom_jcs_types(item) for item in obj)
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str) or any(ord(c) > 0xFFFF for c in k) or _has_custom_jcs_types(v):
                return True
        return False
    return True


def _to_jcs_str(obj: Any) -> str:
    if not _has_custom_jcs_types(obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

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
        return _to_jcs_str(msgspec.to_builtins(obj))
    if hasattr(obj, "__struct_fields__"):
        struct_dict = {field: getattr(obj, field) for field in obj.__struct_fields__}
        return _to_jcs_str(struct_dict)
    raise CanonicalSerializationError(
        f"Unsupported type for RFC 8785 JCS: {type(obj).__name__}"
    )


def canonical_jcs_str(obj: Any) -> str:
    """Serializes an arbitrary contract structure into an RFC 8785 canonical JSON string."""
    return _to_jcs_str(obj)


def canonical_jcs_bytes(obj: Any) -> bytes:
    """Serializes an arbitrary contract structure into UTF-8 RFC 8785 canonical JSON bytes."""
    return _to_jcs_str(obj).encode("utf-8")


def fingerprint_hex(data: bytes | str) -> str:
    """Fast 64-bit non-cryptographic content fingerprint for file-change detection.

    XXH3-64: see `CONTENT_DIGEST_ALGORITHM` for why the algorithm must not
    depend on an optional package being importable.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return xxhash.xxh3_64_hexdigest(raw)


@functools.lru_cache(maxsize=128)
def _domain_header_bytes(domain: str) -> bytes:
    domain_bytes = domain.encode("utf-8")
    return struct.pack(">I", len(domain_bytes)) + domain_bytes


def content_digest_bytes(data: bytes | str, *, domain: str = "verifyci.v2") -> bytes:
    """Domain-separated 256-bit cryptographic digest for Merkle and Salsa identities.

    BLAKE3 over a length-prefixed domain header. The header framing, not BLAKE3
    keyed mode, provides domain separation: the framing keeps every domain in a
    distinct prefix, and the single-shot path avoids the extra hasher construction
    and key derivation that keyed mode costs on every call. That matters because
    the dominant inputs here are short identity strings (`finding_id`, `node_uid`,
    `edge_uid`), where keyed mode measured ~2.3x slower than the plain path.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return bytes(blake3.blake3(_domain_header_bytes(domain) + raw).digest(length=32))


def content_digest_hex(data: bytes | str, *, domain: str = "verifyci.v2") -> str:
    """Hex-encoded 256-bit domain-separated cryptographic digest."""
    return content_digest_bytes(data, domain=domain).hex()


def canonical_digest(obj: Any, *, domain: str = "verifyci.v2.contract") -> str:
    """Computes the domain-separated cryptographic digest of an RFC 8785 JCS payload."""
    return content_digest_hex(canonical_jcs_bytes(obj), domain=domain)
