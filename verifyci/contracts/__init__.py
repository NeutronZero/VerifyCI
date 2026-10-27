"""VerifyCI v3 data contracts, models, capabilities, and manifests."""

from __future__ import annotations

from verifyci.contracts.capabilities import (
    Capability,
    CapabilityDeclaration,
    ExecutionStatus,
    ProviderClass,
    provider_for_capability,
    validate_capabilities,
)
from verifyci.contracts.manifest import CheckSpec, CHECK_SPECS, CHECK_ORDER
from verifyci.contracts.model import (
    CheckResult,
    Coverage,
    CoverageGap,
    DiffEntry,
    EvidenceBundle,
    Finding,
    Maturity,
    Outcome,
    Tier,
    Verdict,
    VerdictResult,
)
from verifyci.contracts.reason_codes import DEFECT_REASON_CODES

__all__ = [
    "CHECK_ORDER",
    "CHECK_SPECS",
    "Capability",
    "CapabilityDeclaration",
    "CheckResult",
    "CheckSpec",
    "Coverage",
    "CoverageGap",
    "DEFECT_REASON_CODES",
    "DiffEntry",
    "EvidenceBundle",
    "ExecutionStatus",
    "Finding",
    "Maturity",
    "Outcome",
    "ProviderClass",
    "Tier",
    "Verdict",
    "VerdictResult",
    "provider_for_capability",
    "validate_capabilities",
]
