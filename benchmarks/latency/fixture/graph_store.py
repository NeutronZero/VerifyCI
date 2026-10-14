"""Latency fixture graph store shim for v2."""
from __future__ import annotations

from typing import Any

from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore as GraphStore


def latest_revision_id(*args: Any, **kwargs: Any) -> str:
    return "v2-rev"


__all__ = ["GraphStore", "latest_revision_id"]
