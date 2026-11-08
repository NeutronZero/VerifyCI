"""Canonical evidence bundle construction."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import platform
from typing import Any, Mapping, Sequence

from verifyci.contracts.manifest import manifest_hash, manifest_payload
from verifyci.contracts.model import CheckResult, EvidenceBundle, VerdictResult
from verifyci.evidence.canonical import canonical_json_bytes, payload_hash


BUNDLE_SCHEMA = "verifyci.evidence/v3.1"
ENVELOPE_SCHEMA = "verifyci.envelope/v3.1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def toolchain_fingerprint(*, git_version: str = "", object_format: str = "") -> str:
    identity = {
        "tool": "verifyci",
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.system(),
        "machine": platform.machine(),
        "git": git_version,
        "object_format": object_format,
        "manifest": manifest_hash(),
    }
    return "sha256:" + sha256(canonical_json_bytes(identity)).hexdigest()


def build_payload(
    *,
    inputs: Mapping[str, Any],
    scope: Mapping[str, Any],
    check_results: Sequence[CheckResult],
    findings: Sequence[Mapping[str, Any]],
    waivers: Sequence[Mapping[str, Any]],
    accepted_gaps: Sequence[Mapping[str, Any]],
    diagnostics: Sequence[Mapping[str, Any]],
    assumptions: Sequence[Mapping[str, Any]],
    excluded_scope: Sequence[Mapping[str, Any]],
    verdict: VerdictResult,
    toolchain: str,
    policy: Mapping[str, Any],
    gate_integrity: Mapping[str, Any],
    manifest_extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = manifest_payload()
    manifest["hash"] = manifest_hash()
    if manifest_extra:
        manifest.update(dict(manifest_extra))
    return {
        "schema": BUNDLE_SCHEMA,
        "tool": {
            "name": "verifyci",
            "version": "3.1.10",
            "toolchain_fingerprint": toolchain,
        },
        "inputs": dict(inputs),
        "policy": dict(policy),
        "manifest": manifest,
        "scope": dict(scope),
        "gate_integrity": dict(gate_integrity),
        "check_results": [r.to_dict() for r in check_results],
        "findings": [dict(f) for f in findings],
        "waivers": [dict(w) for w in waivers],
        "accepted_gaps": [dict(g) for g in accepted_gaps],
        "diagnostics": [dict(d) for d in diagnostics],
        "assumptions": [dict(a) for a in assumptions],
        "excluded_scope": [dict(e) for e in excluded_scope],
        "verdict": verdict.to_dict(),
    }


def build_envelope(
    payload: Mapping[str, Any],
    *,
    generated_at: str | None = None,
    duration_ms: int = 0,
    cache: Mapping[str, Any] | None = None,
    environment: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": ENVELOPE_SCHEMA,
        "payload_hash": payload_hash(payload),
        "generated_at": generated_at or utc_now(),
        "duration_ms": max(int(duration_ms), 0),
        "environment": dict(environment or {}),
        "cache": dict(cache or {"mode": "none"}),
    }


def build_bundle(
    payload: Mapping[str, Any],
    *,
    generated_at: str | None = None,
    duration_ms: int = 0,
    cache: Mapping[str, Any] | None = None,
    environment: Mapping[str, Any] | None = None,
) -> EvidenceBundle:
    envelope = build_envelope(
        payload,
        generated_at=generated_at,
        duration_ms=duration_ms,
        cache=cache,
        environment=environment,
    )
    return EvidenceBundle(payload=payload, envelope=envelope)


__all__ = [
    "BUNDLE_SCHEMA",
    "ENVELOPE_SCHEMA",
    "build_bundle",
    "build_envelope",
    "build_payload",
    "toolchain_fingerprint",
    "utc_now",
]
