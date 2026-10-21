"""CAS storage, Tier 1/Tier 2 key schemas, and HMAC authentication per VerifyCI v3.1 §14."""

from __future__ import annotations

import hmac
import hashlib
import json
import os
from pathlib import Path
from typing import Any

CACHE_SCHEMA_VERSION = 1


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def entry_digest(object_type: str, components: dict[str, Any]) -> str:
    payload = object_type.encode("utf-8") + b"\x00" + canonical_json_bytes(components)
    return hashlib.sha256(payload).hexdigest()


def compute_hmac(key: bytes, key_id: str, object_type: str, components: dict[str, Any], value_digest: str) -> str:
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
    ):
        self.cache_dir = Path(cache_dir)
        self.mode = mode
        self.key = key
        self.key_id = key_id
        if self.mode != "none":
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _path_for_key(self, key_hex: str) -> Path:
        shard = key_hex[:2]
        return self.cache_dir / shard / f"{key_hex}.json"

    def get(self, object_type: str, components: dict[str, Any]) -> tuple[Any | None, bool]:
        """Look up an entry. Returns (value, is_hit)."""
        if self.mode == "none":
            return None, False

        k_hex = entry_digest(object_type, components)
        path = self._path_for_key(k_hex)
        if not path.is_file():
            return None, False

        try:
            with open(path, "r", encoding="utf-8") as f:
                record = json.load(f)
        except Exception:
            return None, False

        val = record.get("value")
        val_bytes = canonical_json_bytes(val)
        val_digest = hashlib.sha256(val_bytes).hexdigest()

        if record.get("value_digest") != val_digest:
            return None, False

        if self.mode == "authenticated":
            if not self.key:
                return None, False
            expected_hmac = compute_hmac(self.key, self.key_id, object_type, components, val_digest)
            if not hmac.compare_digest(record.get("hmac", ""), expected_hmac):
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
        if self.mode == "none":
            return False
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
            record["hmac"] = compute_hmac(self.key, self.key_id, object_type, components, val_digest)
            record["key_id"] = self.key_id

        temp_path = path.with_suffix(".tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(record, f, sort_keys=True, separators=(",", ":"))
            os.replace(temp_path, path)
            return True
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            return False
