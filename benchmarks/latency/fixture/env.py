"""Latency fixture env shim for v2."""
from __future__ import annotations

from typing import Any


def env_name() -> str:
    return "v2-benchmark"


def get_env() -> dict[str, Any]:
    return {}


__all__ = ["env_name", "get_env"]
