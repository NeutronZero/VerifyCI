# verifyci_v2/interface/cap_adjudicator.py (Temporary shim while migrating tests/v2)
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from benchmarks.common.cap_adjudicator import (
        CapAdjudicationReport,
        CapabilityScorecard,
        V2CapabilityAdjudicator,
    )


def __getattr__(name: str) -> Any:
    import benchmarks.common.cap_adjudicator as _mod

    if hasattr(_mod, name):
        return getattr(_mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "CapAdjudicationReport",
    "CapabilityScorecard",
    "V2CapabilityAdjudicator",
]
