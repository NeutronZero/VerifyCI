"""Graph storage backends satisfying GraphStoreProtocol."""

from __future__ import annotations

from verifyci.extensions.storage.duckdb_store import DuckDBGraphStore
from verifyci.extensions.storage.sqlite_store import SQLiteGraphStore

__all__ = ["DuckDBGraphStore", "SQLiteGraphStore"]
