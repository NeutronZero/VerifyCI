from abc import ABC, abstractmethod
import hashlib
import math
from functools import lru_cache


@lru_cache(maxsize=32768)
def _trigram_bucket(trigram: str, dimensions: int) -> int:
    # Trigram hashing dominates embedding cost and repeats heavily: the same
    # corpus is re-embedded per query, and natural text reuses trigrams.
    # Cache is keyed (trigram, dimensions); entries are small ints.
    digest = hashlib.sha256(trigram.encode("utf-8")).digest()
    return int.from_bytes(digest[:2], "little") % dimensions


class EmbeddingProvider(ABC):
    @abstractmethod
    async def embed(self, texts: list[str]) -> list[list[float]]: ...

    @abstractmethod
    def model_name(self) -> str: ...


class HashEmbeddingProvider(EmbeddingProvider):
    """Deterministic offline embeddings: hashed char-trigram bag, L2-normalized.

    No model, no network. Lexical similarity only — an honest dense baseline
    for environments without an embedding server, and the default used by
    `aci query` unless an Ollama provider is injected.
    """

    def __init__(self, dimensions: int = 256):
        self.dimensions = dimensions

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(t) for t in texts]

    def _embed_one(self, text: str) -> list[float]:
        vec = [0.0] * self.dimensions
        lowered = f" {text.lower()} "
        for i in range(len(lowered) - 2):
            vec[_trigram_bucket(lowered[i:i + 3], self.dimensions)] += 1.0
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0:
            vec = [v / norm for v in vec]
        return vec

    def model_name(self) -> str:
        return f"offline-hash-{self.dimensions}"


class SentenceTransformerProvider(EmbeddingProvider):
    """Local sentence-transformers embeddings. Loads from disk only
    (never downloads, never a daemon); import is lazy so outage-free
    environments without torch are unaffected until constructed."""

    def __init__(self, model: str = "sentence-transformers/all-MiniLM-L6-v2"):
        self.model = model
        self._embedder = None

    def _load(self):
        if self._embedder is None:
            from sentence_transformers import SentenceTransformer  # type: ignore
            self._embedder = SentenceTransformer(self.model)
        return self._embedder

    async def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = self._load().encode(texts, normalize_embeddings=True)
        return [list(map(float, v)) for v in vectors]

    def model_name(self) -> str:
        return self.model


class OllamaEmbeddingProvider(EmbeddingProvider):
    def __init__(self, model: str = "nomic-embed-text", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    async def embed(self, texts: list[str]) -> list[list[float]]:
        import aiohttp
        results = []
        async with aiohttp.ClientSession() as session:
            for text in texts:
                async with session.post(
                    f"{self.base_url}/api/embeddings",
                    json={"model": self.model, "prompt": text},
                ) as resp:
                    data = await resp.json()
                    results.append(data["embedding"])
        return results

    def model_name(self) -> str:
        return self.model
