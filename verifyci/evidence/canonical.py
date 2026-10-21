"""Deterministic canonical JSON and payload hashing."""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def payload_hash(value: Any) -> str:
    return "sha256:" + sha256(canonical_json_bytes(value)).hexdigest()


__all__ = ["canonical_json_bytes", "payload_hash"]
