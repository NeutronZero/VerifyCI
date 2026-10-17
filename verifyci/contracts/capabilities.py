"""Capability model and execution status for VerifyCI extensions."""

from __future__ import annotations

from enum import Enum
from typing import Any, Sequence

from verifyci.contracts.verdict import (
    FindingReason,
    Severity,
    VerificationFinding,
    VerificationVerdict,
)


class Capability(str, Enum):
    """Core and extension capabilities."""

    PURE_AST = "pure_ast"
    REMOVAL_PROVENANCE = "removal_provenance"
    SECRET_SCANNING = "secret_scanning"
    DANGEROUS_CALLS = "dangerous_calls"
    SYMBOLIC_EQUIVALENCE = "symbolic_equivalence"
    EQUALITY_SATURATION = "equality_saturation"
    TEMPORAL_GRAPH = "temporal_graph"
    WASM_SANDBOX = "wasm_sandbox"
    CRYPTO_ATTESTATION = "crypto_attestation"


class ExecutionStatus(str, Enum):
    """Execution status for capability checks.

    An unexecuted, timed-out, or crashed required capability never yields PASS.
    """

    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    UNAVAILABLE = "unavailable"
    FAILED_CLOSED = "failed_closed"


class CapabilityDeclaration:
    """Declaration of a capability requirement and execution outcome (slotted model)."""

    __slots__ = ("capability", "detail", "required", "status")

    def __init__(
        self,
        capability: Capability,
        required: bool,
        status: ExecutionStatus,
        detail: str = "",
    ) -> None:
        object.__setattr__(self, "capability", capability)
        object.__setattr__(self, "required", required)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "detail", detail)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("CapabilityDeclaration is immutable")

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, CapabilityDeclaration):
            return False
        return (
            self.capability == other.capability
            and self.required == other.required
            and self.status == other.status
            and self.detail == other.detail
        )

    def evaluate_finding(self, rule_id_prefix: str = "VC-CAP") -> VerificationFinding | None:
        """Derive an inconclusive finding if a required capability did not complete."""
        if not self.required or self.status == ExecutionStatus.COMPLETED:
            return None

        reason = (
            FindingReason.SMT_TIMEOUT
            if self.status == ExecutionStatus.TIMED_OUT
            else FindingReason.CAPABILITY_UNAVAILABLE
        )
        return VerificationFinding(
            finding_id=f"{self.capability.value}:{self.status.value}",
            rule_id=f"{rule_id_prefix}-{self.capability.value.upper()}",
            severity=Severity.HIGH,
            verdict=VerificationVerdict.INCONCLUSIVE,
            reason=reason,
            message=(
                f"Required capability '{self.capability.value}' did not complete "
                f"(status={self.status.value}): {self.detail or 'Execution blocked; failing closed.'}"
            ),
            file_path="<global>",
        )
