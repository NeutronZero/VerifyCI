"""RFC 8785 Canonical JCS Serialization, Digests, and Fingerprint Computation (§15.10 Component E).

Computes:
- 6 explicit artifact digests (3 for release-measurements, 3 for release-attestation)
- 3 distinct fingerprints (Candidate, Measurement Authority, Signing Authority)
- RFC 8785 canonical JSON bytes and envelope structures.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from verifyci.contracts.canonical import (
    canonical_json_bytes as canonical_jcs_bytes,
    payload_hash as canonical_jcs_digest,
    sha256_prefixed,
)


def compute_file_sha256(path: Path) -> str:
    """Compute sha256:... digest over raw uncompressed file bytes."""
    return sha256_prefixed(path.read_bytes())


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
        "measurements_raw_sha256": sha256_prefixed(raw_measurements),
        "attestation_raw_sha256": sha256_prefixed(raw_attestation),
        "release_validation_raw_sha256": sha256_prefixed(raw_validation),
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
    jwt_digest = sha256_prefixed(raw_oidc_jwt.encode("utf-8"))
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


__all__ = [
    "build_evidence_bundle",
    "canonical_jcs_bytes",
    "canonical_jcs_digest",
    "compute_file_sha256",
    "create_signed_evidence_payload",
]
