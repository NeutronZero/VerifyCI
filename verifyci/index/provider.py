"""FactProvider implementation driving demand-driven analysis and cache access."""

from __future__ import annotations

from hashlib import sha256
from typing import Any
from verifyci.index.cache import CacheStore
from verifyci.evidence.canonical import canonical_json_bytes


class CacheIntegrityMismatch(RuntimeError):
    def __init__(self, entry_key: str) -> None:
        super().__init__(entry_key)
        self.entry_key = entry_key


class FactProvider:
    def __init__(self, cache_store: CacheStore | None = None) -> None:
        self.cache_store = cache_store
        self.stats = {"hits": 0, "misses": 0, "writes": 0, "sampled_recomputations": 0}

    def get_or_compute(
        self,
        object_type: str,
        components: dict[str, Any],
        compute,
    ) -> Any:
        """Read an authenticated fact or compute it from pinned Git bytes.

        Sampled valid hits are recomputed deterministically before consumption. A
        disagreement is a fatal integrity error; the caller must disable the cache.
        """
        if self.cache_store is None or self.cache_store.mode == "none":
            self.stats["misses"] += 1
            return compute()

        value, hit = self.cache_store.get(object_type, components)
        if not hit:
            self.stats["misses"] += 1
            value = compute()
            if self.cache_store.put(object_type, components, value):
                self.stats["writes"] += 1
            return value

        self.stats["hits"] += 1
        if not self.cache_store.sample_selected(object_type, components):
            return value

        self.stats["sampled_recomputations"] += 1
        recomputed = compute()
        if canonical_json_bytes(value) != canonical_json_bytes(recomputed):
            key = self.cache_store.entry_key(object_type, components)
            raise CacheIntegrityMismatch(key)
        return recomputed

    @staticmethod
    def tier1_components(
        *,
        toolchain_fingerprint: str,
        blob_hash: str,
        path: str,
        language_id: str,
        frontend_version: str,
        source_roots: tuple[str, ...],
    ) -> dict[str, Any]:
        from verifyci.index.cache import CACHE_SCHEMA_VERSION

        policy_digest = "sha256:" + sha256(
            canonical_json_bytes({"source_roots": list(source_roots)})
        ).hexdigest()
        return {
            "csv": CACHE_SCHEMA_VERSION,
            "tc": toolchain_fingerprint,
            "blob_hash": blob_hash,
            "repo_relative_path": path.replace("\\", "/"),
            "language_id": language_id,
            "frontend_version": frontend_version,
            "pd_paths": policy_digest,
        }

    def cache_stats(self) -> dict[str, int]:
        return dict(self.stats)

    def cache_disabled(self) -> None:
        if self.cache_store is not None:
            self.cache_store.mode = "none"

    def get_entity_spans(self, path: str, blob_hash: str) -> list[dict[str, Any]] | None:
        if self.cache_store:
            components = self.tier1_components(
                toolchain_fingerprint="legacy-provider-api",
                blob_hash=blob_hash,
                path=path,
                language_id="unknown",
                frontend_version="legacy-provider-api",
                source_roots=(),
            )
            val, hit = self.cache_store.get("entity_spans", components)
            if hit:
                return val
        return None

    def put_entity_spans(self, path: str, blob_hash: str, spans: list[dict[str, Any]]) -> None:
        if self.cache_store:
            components = self.tier1_components(
                toolchain_fingerprint="legacy-provider-api",
                blob_hash=blob_hash,
                path=path,
                language_id="unknown",
                frontend_version="legacy-provider-api",
                source_roots=(),
            )
            self.cache_store.put("entity_spans", components, spans)


__all__ = ["CacheIntegrityMismatch", "FactProvider"]
