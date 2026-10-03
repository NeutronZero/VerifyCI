import hashlib
import json
from typing import Any

CANONICAL_EXCLUDED_FIELDS = {"attestation"}


def canonical_event_bytes(event: Any) -> bytes:
    from verifyci.contracts.jsonio import to_json_dict
    d = to_json_dict(event) if not isinstance(event, dict) else dict(event)
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
