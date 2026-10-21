"""FactProvider implementation driving demand-driven analysis and cache access."""

from __future__ import annotations

from typing import Any
from verifyci.index.cache import CacheStore


class FactProvider:
    def __init__(self, cache_store: CacheStore | None = None) -> None:
        self.cache_store = cache_store

    def get_entity_spans(self, path: str, blob_hash: str) -> list[dict[str, Any]] | None:
        if self.cache_store:
            val, hit = self.cache_store.get("entity_spans", {"path": path, "blob_hash": blob_hash})
            if hit:
                return val
        return None

    def put_entity_spans(self, path: str, blob_hash: str, spans: list[dict[str, Any]]) -> None:
        if self.cache_store:
            self.cache_store.put("entity_spans", {"path": path, "blob_hash": blob_hash}, spans)
