"""Deprecated frozen copy. Thin re-export of the live module (v1 remediation)."""
from verifyci.retrieval.provider import (
    CachedEmbeddingProvider,
    EmbeddingProvider,
    HashEmbeddingProvider,
    OllamaEmbeddingProvider,
    SentenceTransformerProvider,
    default_dense_provider,
)

__all__ = [
    "EmbeddingProvider",
    "HashEmbeddingProvider",
    "SentenceTransformerProvider",
    "OllamaEmbeddingProvider",
    "CachedEmbeddingProvider",
    "default_dense_provider",
]
