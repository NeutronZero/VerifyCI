"""Canonical capability vocabulary and provider models per VerifyCI v3.1 §10.2."""

from __future__ import annotations

from enum import Enum
from typing import Any, Sequence


class Capability(str, Enum):
    """Canonical v3 capability vocabulary (§10.2)."""

    ENTITY_SPANS = "entity_spans"
    SIGNATURE = "signature"
    CFG = "cfg"
    SSA = "ssa"
    CALLS = "calls"
    EFFECTS = "effects"
    EXCEPTIONS = "exceptions"
    TYPES = "types"
    TAINT = "taint"
    SYMBOLS = "symbols"
    REFERENCES = "references"
    GUARDS = "guards"


class ProviderClass(str, Enum):
    """Normative capability provider classes (§10.2)."""

    FRONTEND = "frontend"
    INDEX = "index"


# Canonical provider mapping per §10.2:
# Frontend / VFIR lowering: entity_spans, signature, cfg, ssa, calls, effects, exceptions, types, taint, guards
# Symbol/reference index: symbols, references
FRONTEND_CAPABILITIES: frozenset[Capability] = frozenset(
    {
        Capability.ENTITY_SPANS,
        Capability.SIGNATURE,
        Capability.CFG,
        Capability.SSA,
        Capability.CALLS,
        Capability.EFFECTS,
        Capability.EXCEPTIONS,
        Capability.TYPES,
        Capability.TAINT,
        Capability.GUARDS,
    }
)

INDEX_CAPABILITIES: frozenset[Capability] = frozenset(
    {
        Capability.SYMBOLS,
        Capability.REFERENCES,
    }
)

CAPABILITY_PROVIDERS: dict[Capability, ProviderClass] = {
    cap: ProviderClass.FRONTEND for cap in FRONTEND_CAPABILITIES
}
CAPABILITY_PROVIDERS.update(
    {cap: ProviderClass.INDEX for cap in INDEX_CAPABILITIES}
)


def provider_for_capability(capability: Capability | str) -> ProviderClass:
    cap = Capability(capability)
    return CAPABILITY_PROVIDERS[cap]


def validate_capabilities(
    capabilities: Sequence[Capability | str],
    available_providers: Sequence[ProviderClass | str] = (
        ProviderClass.FRONTEND,
        ProviderClass.INDEX,
    ),
) -> list[str]:
    """Validate that capabilities are valid and supplied by declared providers."""
    errors: list[str] = []
    providers_set = {
        p.value if isinstance(p, ProviderClass) else p for p in available_providers
    }
    for c in capabilities:
        try:
            cap = Capability(c)
        except ValueError:
            errors.append(f"unknown capability: {c}")
            continue
        provider = CAPABILITY_PROVIDERS[cap]
        if provider.value not in providers_set:
            errors.append(
                f"capability {cap.value} requires provider {provider.value}, which is not available"
            )
    return errors


class ExecutionStatus(str, Enum):
    """Execution status for capability checks."""

    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    UNAVAILABLE = "unavailable"
    FAILED_CLOSED = "failed_closed"


class CapabilityDeclaration:
    """Declaration of a capability requirement and execution outcome."""

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability.value,
            "required": self.required,
            "status": self.status.value,
            "detail": self.detail,
        }


__all__ = [
    "CAPABILITY_PROVIDERS",
    "Capability",
    "CapabilityDeclaration",
    "ExecutionStatus",
    "FRONTEND_CAPABILITIES",
    "INDEX_CAPABILITIES",
    "ProviderClass",
    "provider_for_capability",
    "validate_capabilities",
]
