"""Latency fixture intent align shim for v2."""
from __future__ import annotations

from typing import Any

from verifyci_v2.neural.spec_compiler import IntentToSMTCompiler  # noqa: F401


def evaluate_invariants(*args: Any, **kwargs: Any) -> list[Any]:
    return []


def score_labeled(*args: Any, **kwargs: Any) -> float:
    return 1.0


__all__ = ["evaluate_invariants", "score_labeled"]
