"""Latency fixture provider shim for v2."""
from __future__ import annotations

from verifyci_v2.store.rabitq_index import RaBitQHybridIndex  # noqa: F401


class EmbeddingProvider:
    pass


class HashEmbeddingProvider(EmbeddingProvider):
    pass


class SentenceTransformerProvider(EmbeddingProvider):
    pass


class OllamaEmbeddingProvider(EmbeddingProvider):
    pass


class CachedEmbeddingProvider(EmbeddingProvider):
    pass


def default_dense_provider() -> EmbeddingProvider:
    return HashEmbeddingProvider()


__all__ = [
    "EmbeddingProvider",
    "HashEmbeddingProvider",
    "SentenceTransformerProvider",
    "OllamaEmbeddingProvider",
    "CachedEmbeddingProvider",
    "default_dense_provider",
]
