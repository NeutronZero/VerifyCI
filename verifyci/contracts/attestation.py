"""Canonical deterministic attestation schema and digest computation."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Mapping, Sequence

from verifyci import __version__
from verifyci.contracts.verdict import VerificationFinding, VerificationVerdict

ATTESTATION_SCHEMA_VERSION = "1.0"
ATTESTATION_DIGEST_DOMAIN = "verifyci.attestation.v1:sha256"


def normalize_path(path: str) -> str:
    """Normalize file path to POSIX style with forward slashes and no leading ./."""
    p = path.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p


def canonical_json_bytes(data: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme (JCS).

    Deterministic serialization: sorted keys, no whitespace separators,
    UTF-8 encoding without BOM, IEEE 754 float representation.
    """
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class CanonicalAttestationPayload:
    """Deterministic attestation payload.

    Identical normalized verification inputs, policy, analyzer versions,
    and deterministic results produce identical canonical payloads and digests.
    """

    base_commit_sha: str
    head_commit_sha: str
    files: tuple[str, ...]
    policy_hash: str
    verdict: VerificationVerdict
    findings: tuple[VerificationFinding, ...]
    schema_version: str = ATTESTATION_SCHEMA_VERSION
    analyzer_version: str = f"verifyci-{__version__}"

    def to_normalized_dict(self) -> dict[str, Any]:
        """Produce a normalized dictionary guaranteed to be deterministic."""
        normalized_files = sorted({normalize_path(f) for f in self.files if f})
        
        # Findings sorted deterministically by (file_path, start_line, rule_id, finding_id)
        sorted_findings = sorted(
            [f.to_dict() for f in self.findings],
            key=lambda d: (
                normalize_path(d["file_path"]),
                d["start_line"],
                d["rule_id"],
                d["finding_id"],
            ),
        )

        return {
            "schema_version": self.schema_version,
            "analyzer_version": self.analyzer_version,
            "policy_hash": self.policy_hash,
            "input_manifest": {
                "base_commit_sha": self.base_commit_sha or "none",
                "head_commit_sha": self.head_commit_sha or "none",
                "files": normalized_files,
            },
            "deterministic_verdict": self.verdict.value,
            "findings": sorted_findings,
        }

    def canonical_bytes(self) -> bytes:
        """Serialize normalized payload to RFC 8785 canonical bytes."""
        return canonical_json_bytes(self.to_normalized_dict())

    def compute_digest(self) -> str:
        """Compute versioned domain-separated SHA-256 digest."""
        hasher = hashlib.sha256()
        domain_prefix = f"{ATTESTATION_DIGEST_DOMAIN}:".encode("utf-8")
        hasher.update(domain_prefix)
        hasher.update(self.canonical_bytes())
        return hasher.hexdigest()


@dataclass(frozen=True)
class VerificationCertificate:
    """Complete verification certificate including envelope metadata and digest."""

    digest: str
    digest_algorithm: str
    verdict: VerificationVerdict
    payload: CanonicalAttestationPayload
    rationale: str
    execution_metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Export certificate for external consumers."""
        return {
            "digest": self.digest,
            "digest_algorithm": self.digest_algorithm,
            "verdict": self.verdict.value,
            "rationale": self.rationale,
            "attestation": self.payload.to_normalized_dict(),
            "execution_metadata": dict(self.execution_metadata),
        }
