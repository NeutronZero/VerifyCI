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


CERTIFICATE_EXCLUDED_FIELDS = {"signature"}


def canonical_certificate_bytes(cert: Any) -> bytes:
    """Produce deterministic UTF-8 byte representation of a Certificate for hashing and signing."""
    from verifyci.contracts.jsonio import to_json_dict
    d = to_json_dict(cert) if not isinstance(cert, dict) else dict(cert)
    for field_name in CERTIFICATE_EXCLUDED_FIELDS:
        d.pop(field_name, None)
    return json.dumps(
        d,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def certificate_hash(cert: Any) -> str:
    """Compute SHA-256 content hash of canonical certificate representation."""
    return hashlib.sha256(canonical_certificate_bytes(cert)).hexdigest()
