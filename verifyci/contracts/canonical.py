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


ENVELOPE_EXCLUDED_FIELDS = {"signature"}


def canonical_envelope_bytes(envelope: Any) -> bytes:
    """Produce deterministic UTF-8 byte representation of a VerificationEnvelope for hashing and signing."""
    from verifyci.contracts.jsonio import to_json_dict
    d = to_json_dict(envelope) if not isinstance(envelope, dict) else dict(envelope)
    for field_name in ENVELOPE_EXCLUDED_FIELDS:
        d.pop(field_name, None)
    return json.dumps(
        d,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def envelope_hash(envelope: Any) -> str:
    """Compute SHA-256 content hash of canonical VerificationEnvelope representation."""
    return hashlib.sha256(canonical_envelope_bytes(envelope)).hexdigest()


def canonical_report_bytes(report: Any) -> bytes:
    """Produce deterministic UTF-8 byte representation of a VerificationReport."""
    from verifyci.contracts.jsonio import to_json_dict
    d = to_json_dict(report) if not isinstance(report, dict) else dict(report)
    return json.dumps(
        d,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def report_hash(report: Any) -> str:
    """Compute SHA-256 content hash of canonical VerificationReport representation."""
    return hashlib.sha256(canonical_report_bytes(report)).hexdigest()


def canonical_effective_policy_bundle_bytes(
    policy: Any,
    invariants: list[Any] | None = None,
    waivers: list[Any] | None = None,
    checker_configs: dict[str, Any] | None = None,
    policy_version: str = "1.0",
) -> bytes:
    """Produce deterministic UTF-8 byte representation of the complete effective policy bundle."""
    from verifyci.contracts.jsonio import to_json_dict
    bundle = {
        "checker_configs": checker_configs or {},
        "invariants": [to_json_dict(i) for i in (invariants or [])],
        "policy": to_json_dict(policy),
        "policy_version": policy_version,
        "waivers": [to_json_dict(w) for w in (waivers or [])],
    }
    return json.dumps(
        bundle,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def effective_policy_bundle_hash(
    policy: Any,
    invariants: list[Any] | None = None,
    waivers: list[Any] | None = None,
    checker_configs: dict[str, Any] | None = None,
    policy_version: str = "1.0",
) -> str:
    """Compute SHA-256 content hash of the complete effective policy bundle."""
    return hashlib.sha256(
        canonical_effective_policy_bundle_bytes(
            policy, invariants, waivers, checker_configs, policy_version
        )
    ).hexdigest()

