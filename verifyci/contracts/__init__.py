"""Core verification contracts, findings, verdicts, and attestation schemas."""

from __future__ import annotations

from verifyci.contracts.attestation import (
    ATTESTATION_DIGEST_DOMAIN,
    ATTESTATION_SCHEMA_VERSION,
    CanonicalAttestationPayload,
    VerificationCertificate,
    canonical_json_bytes,
    normalize_path,
)
from verifyci.contracts.capabilities import (
    Capability,
    CapabilityDeclaration,
    ExecutionStatus,
)
from verifyci.contracts.verdict import (
    FindingReason,
    Severity,
    VerificationFinding,
    VerificationVerdict,
    derive_verdict,
)

__all__ = [
    "ATTESTATION_DIGEST_DOMAIN",
    "ATTESTATION_SCHEMA_VERSION",
    "CanonicalAttestationPayload",
    "Capability",
    "CapabilityDeclaration",
    "ExecutionStatus",
    "FindingReason",
    "Severity",
    "VerificationCertificate",
    "VerificationFinding",
    "VerificationVerdict",
    "canonical_json_bytes",
    "derive_verdict",
    "normalize_path",
]
