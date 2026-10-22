"""Deterministic task scheduler and worker pool management."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


def run_deterministic_batch(items: list[T], worker: Callable[[T], R]) -> list[R]:
    """Execute tasks with strictly deterministic sequential reduction order."""
    return [worker(item) for item in items]
