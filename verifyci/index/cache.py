"""CAS storage, Tier 1/Tier 2 key schemas, and HMAC authentication per VerifyCI v3.1 §14."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from verifyci.evidence.canonical import canonical_json_bytes

CACHE_SCHEMA_VERSION = 1
VALID_CACHE_MODES = frozenset({"none", "local", "authenticated"})
CACHE_SAMPLE_VERSION = "verifyci-cache-sample-v1"
CACHE_SAMPLE_RATE_NUMERATOR = 5
CACHE_SAMPLE_RATE_DENOMINATOR = 100

_TIER1_KEYS = frozenset(
    {"csv", "tc", "blob_hash", "repo_relative_path", "language_id", "frontend_version", "pd_paths"}
)
_KEY_SCHEMAS = {
    "entity_spans": _TIER1_KEYS,
    "symbol_facts": _TIER1_KEYS,
    "vfir": _TIER1_KEYS | {"lowering_version"},
    "summary": frozenset(
        {"csv", "tc", "t1_file", "rev", "qname", "closure_digest", "pd_decor", "pd_calls", "pd_taint", "budget_digest"}
    ),
    "contract_binding": frozenset(
        {"csv", "tc", "t1_base", "t1_head", "qname_base", "qname_head", "closure_base", "closure_head", "pd_public", "pd_decor", "pd_calls", "budget_digest"}
    ),
}
_SEMANTIC_FORMULA_KEYS = frozenset(
    {"csv", "tc", "formula_kind", "t1_base", "t1_head", "entity_pair", "closure_base", "closure_head", "alignment_digest", "pd_decor", "pd_calls", "pd_guard", "budget_digest"}
)


def validate_key_schema(object_type: str, components: dict[str, Any]) -> None:
    """Reject unspecified objects and incomplete/overbroad key schemas."""
    expected = _KEY_SCHEMAS.get(object_type)
    if object_type == "semantic_formula":
        kind = components.get("formula_kind")
        if kind not in {"guard", "exception", "binding_swap"}:
            raise ValueError("semantic_formula requires a supported formula_kind")
        expected = _SEMANTIC_FORMULA_KEYS | ({"pd_public"} if kind == "binding_swap" else set())
    elif object_type == "solver_result":
        kind = components.get("formula_kind")
        if kind not in {"guard", "exception", "binding_swap"}:
            raise ValueError("solver_result requires a supported formula_kind")
        expected = _SEMANTIC_FORMULA_KEYS | {"solver_digest"}
        if kind == "binding_swap":
            expected |= {"pd_public"}
    if expected is None:
        raise ValueError(f"unsupported cache object type: {object_type}")
    if not isinstance(components, dict) or frozenset(components) != frozenset(expected):
        raise ValueError(f"invalid {object_type} cache key schema")
    if components.get("csv") != CACHE_SCHEMA_VERSION:
        raise ValueError("cache schema version mismatch")


def should_sample(key_hex: str) -> bool:
    """Apply the release-pinned, entry-key-based 5/100 sampler (§14.3)."""
    if len(key_hex) != 64 or any(ch not in "0123456789abcdef" for ch in key_hex):
        raise ValueError("cache entry key must be 64 lowercase hexadecimal characters")
    sample = hashlib.sha256(
        CACHE_SAMPLE_VERSION.encode("utf-8") + b"\x00" + key_hex.encode("ascii")
    ).digest()
    return int.from_bytes(sample, "big") < (CACHE_SAMPLE_RATE_NUMERATOR * (1 << 256)) // CACHE_SAMPLE_RATE_DENOMINATOR


def entry_digest(object_type: str, components: dict[str, Any]) -> str:
    payload = object_type.encode("utf-8") + b"\x00" + canonical_json_bytes(components)
    return hashlib.sha256(payload).hexdigest()


def compute_hmac(
    key: bytes,
    key_id: str,
    object_type: str,
    components: dict[str, Any],
    value_digest: str,
) -> str:
    message = (
        key_id.encode("utf-8")
        + b"\x00"
        + object_type.encode("utf-8")
        + b"\x00"
        + canonical_json_bytes(components)
        + b"\x00"
        + value_digest.encode("utf-8")
    )
    return hmac.new(key, message, hashlib.sha256).hexdigest()


class CacheStore:
    def __init__(
        self,
        cache_dir: str | Path,
        mode: str = "none",
        key: bytes | None = None,
        key_id: str = "k1",
        read_only: bool = False,
    ):
        if mode not in VALID_CACHE_MODES:
            raise ValueError(
                f"Invalid cache mode {mode!r}; expected one of {sorted(VALID_CACHE_MODES)}"
            )
        if mode == "authenticated" and not key:
            raise ValueError(
                "Cache mode 'authenticated' requires a non-empty cryptographic key"
            )

        self.cache_dir = Path(cache_dir)
        self.mode = mode
        self.key = key
        self.key_id = key_id
        self.read_only = read_only
        if self.mode != "none":
            if not self.read_only:
                self.cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path_for_key(self, key_hex: str) -> Path:
        shard = key_hex[:2]
        return self.cache_dir / shard / f"{key_hex}.json"

    @staticmethod
    def entry_key(object_type: str, components: dict[str, Any]) -> str:
        return entry_digest(object_type, components)

    @staticmethod
    def sample_selected(object_type: str, components: dict[str, Any]) -> bool:
        """Return whether this exact cache entry is selected for recomputation."""
        return should_sample(entry_digest(object_type, components))

    def get(
        self, object_type: str, components: dict[str, Any]
    ) -> tuple[Any | None, bool]:
        """Look up an entry. Returns (value, is_hit)."""
        if self.mode == "none":
            return None, False

        validate_key_schema(object_type, components)

        k_hex = entry_digest(object_type, components)
        path = self._path_for_key(k_hex)
        if not path.is_file():
            return None, False

        try:
            with open(path, "r", encoding="utf-8") as f:
                record = json.load(f)
        except Exception:
            return None, False
        if not isinstance(record, dict):
            return None, False

        # Explicitly verify envelope metadata against expected values
        if record.get("object_type") != object_type:
            return None, False
        if record.get("components") != components:
            return None, False

        val = record.get("value")
        val_bytes = canonical_json_bytes(val)
        val_digest = hashlib.sha256(val_bytes).hexdigest()

        if record.get("value_digest") != val_digest:
            return None, False

        if self.mode == "authenticated":
            if not self.key:
                return None, False
            if record.get("key_id") != self.key_id:
                return None, False
            expected_hmac = compute_hmac(
                self.key, self.key_id, object_type, components, val_digest
            )
            supplied_hmac = record.get("hmac")
            if not isinstance(supplied_hmac, str) or not hmac.compare_digest(supplied_hmac, expected_hmac):
                return None, False
        elif self.mode == "local":
            # Negative-capable entries must never be returned in local mode
            if record.get("is_negative", False):
                return None, False

        return val, True

    def put(
        self,
        object_type: str,
        components: dict[str, Any],
        value: Any,
        *,
        is_negative: bool = False,
    ) -> bool:
        """Store an entry. In local mode, negative results are never stored."""
        if self.mode == "none" or self.read_only:
            return False
        validate_key_schema(object_type, components)
        if self.mode == "local" and is_negative:
            return False
        if self.mode == "authenticated" and not self.key:
            return False

        k_hex = entry_digest(object_type, components)
        path = self._path_for_key(k_hex)
        path.parent.mkdir(parents=True, exist_ok=True)

        val_bytes = canonical_json_bytes(value)
        val_digest = hashlib.sha256(val_bytes).hexdigest()

        record: dict[str, Any] = {
            "object_type": object_type,
            "components": components,
            "value": value,
            "value_digest": val_digest,
            "is_negative": is_negative,
        }

        if self.mode == "authenticated" and self.key:
            record["hmac"] = compute_hmac(
                self.key, self.key_id, object_type, components, val_digest
            )
            record["key_id"] = self.key_id

        temp_path = path.with_suffix(".tmp")
        try:
            descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as f:
                json.dump(record, f, sort_keys=True, separators=(",", ":"))
            os.replace(temp_path, path)
            return True
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            return False


__all__ = [
    "CACHE_SAMPLE_RATE_DENOMINATOR",
    "CACHE_SAMPLE_RATE_NUMERATOR",
    "CACHE_SAMPLE_VERSION",
    "CACHE_SCHEMA_VERSION",
    "CacheStore",
    "VALID_CACHE_MODES",
    "compute_hmac",
    "entry_digest",
    "should_sample",
    "validate_key_schema",
]
