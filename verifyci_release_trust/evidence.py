"""RFC 8785 Canonical JCS Serialization, Digests, and Fingerprint Computation (§15.10 Component E).

Computes:
- 6 explicit artifact digests (3 for release-measurements, 3 for release-attestation)
- 3 distinct fingerprints (Candidate, Measurement Authority, Signing Authority)
- RFC 8785 canonical JSON bytes and envelope structures.
"""
from __future__ import annotations

import decimal
import hashlib
import json
from pathlib import Path
from typing import Any


from verifyci.evidence.canonical import _serialize_float


def canonical_jcs_bytes(obj: Any) -> bytes:
    """Serialize object to deterministic canonical JSON according to RFC 8785 (JCS)."""
    if isinstance(obj, bool) or obj is None:
        return json.dumps(obj, separators=(",", ":")).encode("utf-8")
    elif isinstance(obj, int):
        return str(obj).encode("ascii")
    elif isinstance(obj, float):
        return _serialize_float(obj)
    elif isinstance(obj, decimal.Decimal):
        if not obj.is_finite():
            raise ValueError(f"non-finite Decimal: {obj}")
        # Format decimal cleanly
        s = format(obj, "f") if "." in str(obj) else str(obj)
        return s.encode("utf-8")
    elif isinstance(obj, str):
        # Strict escape rules of JSON
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    elif isinstance(obj, dict):
        # Keys MUST be sorted lexicographically by UTF-16 code units (RFC 8785 Section 3.2.3)
        sorted_keys = sorted(obj.keys(), key=lambda k: k.encode("utf-16-be"))
        parts: list[bytes] = []
        for k in sorted_keys:
            key_bytes = json.dumps(k, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            val_bytes = canonical_jcs_bytes(obj[k])
            parts.append(key_bytes + b":" + val_bytes)
        return b"{" + b",".join(parts) + b"}"
    elif isinstance(obj, (list, tuple)):
        parts = [canonical_jcs_bytes(x) for x in obj]
        return b"[" + b",".join(parts) + b"]"
    else:
        raise TypeError(f"unsupported type for RFC 8785 serialization: {type(obj).__name__}")


def canonical_jcs_digest(obj: Any) -> str:
    """Compute sha256:... digest over RFC 8785 canonical bytes."""
    data = canonical_jcs_bytes(obj)
    return "sha256:" + hashlib.sha256(data).hexdigest()


def compute_file_sha256(path: Path) -> str:
    """Compute sha256:... digest over raw uncompressed file bytes."""
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def build_evidence_bundle(
    *,
    candidate_tree: dict[str, str],
    worker_image: dict[str, str],
    raw_measurements: bytes,
    raw_attestation: bytes,
    raw_validation: bytes,
    candidate_impl_fingerprint: str,
    trusted_harness_fingerprint: str,
    trusted_supervisor_fingerprint: str,
) -> dict[str, Any]:
    digests = {
        "candidate_tree_manifest_sha256": candidate_tree.get("candidate_tree_manifest_sha256", ""),
        "candidate_source_archive_sha256": candidate_tree.get("candidate_source_archive_sha256", ""),
        "worker_image_digest": worker_image.get("worker_image_digest", ""),
        "measurements_raw_sha256": "sha256:" + hashlib.sha256(raw_measurements).hexdigest(),
        "attestation_raw_sha256": "sha256:" + hashlib.sha256(raw_attestation).hexdigest(),
        "release_validation_raw_sha256": "sha256:" + hashlib.sha256(raw_validation).hexdigest(),
    }
    fingerprints = {
        "candidate_implementation_fingerprint": candidate_impl_fingerprint,
        "trusted_harness_fingerprint": trusted_harness_fingerprint,
        "trusted_supervisor_fingerprint": trusted_supervisor_fingerprint,
    }
    return {
        "digests": digests,
        "fingerprints": fingerprints,
    }


def create_signed_evidence_payload(
    *,
    commit_sha: str,
    manifest_hash: str,
    candidate_fp: str,
    harness_fp: str,
    supervisor_fp: str,
    measurements: dict[str, Any],
    provenance: dict[str, Any],
    oidc_jti: str,
    raw_oidc_jwt: str,
) -> dict[str, Any]:
    jwt_digest = "sha256:" + hashlib.sha256(raw_oidc_jwt.encode("utf-8")).hexdigest()
    return {
        "schema": "verifyci.release_validation/v3",
        "commit_sha": commit_sha,
        "manifest_hash": manifest_hash,
        "candidate_implementation_fingerprint": candidate_fp,
        "trusted_harness_fingerprint": harness_fp,
        "trusted_supervisor_fingerprint": supervisor_fp,
        "measurements": measurements,
        "provenance": provenance,
        "oidc_binding": {
            "jti": oidc_jti,
            "jwt_sha256": jwt_digest,
        },
    }
