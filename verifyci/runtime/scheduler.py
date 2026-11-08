"""Deterministic task scheduler and worker pool management."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


def run_deterministic_batch(
    items: list[T], worker: Callable[[T], R], max_workers: int = 1
) -> list[R]:
    """Execute tasks with strictly deterministic sequential reduction order."""
    if max_workers <= 1 or len(items) <= 1:
        return [worker(item) for item in items]
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(worker, items))
