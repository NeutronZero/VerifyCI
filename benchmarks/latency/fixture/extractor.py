"""Latency fixture extractor shim for v2."""
from __future__ import annotations

from typing import Any

from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa


def extract_entities(path: str, source: str) -> list[Any]:
    return list(lower_file_to_ussa(path, source))


def extract_edges(*args: Any, **kwargs: Any) -> list[Any]:
    return []


__all__ = ["extract_edges", "extract_entities"]
