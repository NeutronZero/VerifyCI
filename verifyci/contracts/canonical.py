import hashlib
import json
from dataclasses import asdict
from typing import Any

CANONICAL_EXCLUDED_FIELDS = {"attestation"}


def canonical_event_bytes(event: Any) -> bytes:
    d = asdict(event)
    for field_name in CANONICAL_EXCLUDED_FIELDS:
        d.pop(field_name, None)
    return json.dumps(
        d,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def event_hash(event: Any) -> str:
    return hashlib.sha256(canonical_event_bytes(event)).hexdigest()
