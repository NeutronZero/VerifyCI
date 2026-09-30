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
    """Local Ollama embeddings via batched `/api/embed`.

    One round-trip per `batch_size` chunk — the old per-text POST loop
    turned every 500-doc query into 500 HTTP calls. No connection is
    made at construction, so selecting this provider stays offline-safe;
    failures surface at embed time and callers fall back honestly.
    """

    def __init__(self, model: str = "nomic-embed-text",
                 base_url: str = "http://localhost:11434",
                 batch_size: int = 64):
        self.model = model
        self.base_url = base_url
        self.batch_size = max(1, batch_size)

    async def embed(self, texts: list[str]) -> list[list[float]]:
        out: list[list[float]] = []
        for i in range(0, len(texts), self.batch_size):
            out.extend(await self._embed_batch(texts[i:i + self.batch_size]))
        return out

    async def _embed_batch(self, texts: list[str]) -> list[list[float]]:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/embed",
                json={"model": self.model, "input": texts},
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                return [list(map(float, v)) for v in data["embeddings"]]

    def model_name(self) -> str:
        return self.model


def _cache_key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CachedEmbeddingProvider(EmbeddingProvider):
    """Content-addressed cache over another provider.

    Keys are sha256 of the exact text: changed text simply misses, so
    there is no invalidation logic to get wrong. The file (JSON
    {sha: vector}) is rewritten whole under a tmp+rename on each
    miss batch — single-writer assumption (local CLI / one MCP
    process); concurrent writers may lose entries, never corrupt
    reads. A corrupt or missing file rebuilds silently. `cache_path`
    None means memory-only (still dedupes within the process).
    """

    def __init__(self, base: EmbeddingProvider, cache_path: str | None = None):
        self.base = base
        self.cache_path = cache_path
        self._mem: dict[str, list[float]] = {}
        if cache_path:
            self._mem = self._read_file(cache_path)

    @staticmethod
    def _read_file(path: str) -> dict[str, list[float]]:
        import json as _json
        try:
            with open(path, encoding="utf-8") as fh:
                data = _json.load(fh)
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {k: v for k, v in data.items()
                if isinstance(k, str) and isinstance(v, list)}

    def _save(self) -> None:
        if not self.cache_path:
            return
        import json as _json
        import os as _os
        tmp = self.cache_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            _json.dump(self._mem, fh)
        _os.replace(tmp, self.cache_path)

    async def embed(self, texts: list[str]) -> list[list[float]]:
        keys = [_cache_key(t) for t in texts]
        missing = sorted({t for t, k in zip(texts, keys) if k not in self._mem})
        if missing:
            vectors = await self.base.embed(missing)
            for text, vector in zip(missing, vectors):
                self._mem[_cache_key(text)] = [float(v) for v in vector]
            self._save()
        return [list(self._mem[k]) for k in keys]

    def model_name(self) -> str:
        return f"cached:{self.base.model_name()}"


def default_dense_provider(cache_dir: str | None = None) -> EmbeddingProvider:
    """Select the dense provider from the environment (single call site).

    `ACI_EMBEDDINGS` unset/`hash` → offline trigram hash (default:
    deterministic, no server). `ollama[:model]` → Ollama wrapped in a
    content-addressed cache (file under `cache_dir` when given, else
    memory-only). Unknown specs raise — a misconfigured operator
    finds out loudly, not via silently wrong results.
    `ACI_OLLAMA_URL` overrides the server address.
    """
    import os
    spec = os.environ.get("ACI_EMBEDDINGS", "hash").strip().lower()
    if spec in ("", "hash", "offline"):
        return HashEmbeddingProvider()
    if spec == "ollama" or spec.startswith("ollama:"):
        model = "nomic-embed-text"
        if ":" in spec:
            model = spec.split(":", 1)[1] or model
        base_url = os.environ.get("ACI_OLLAMA_URL", "http://localhost:11434")
        base: EmbeddingProvider = OllamaEmbeddingProvider(
            model=model, base_url=base_url)
        if cache_dir:
            safe = "".join(c if c.isalnum() else "_" for c in model)
            return CachedEmbeddingProvider(
                base, os.path.join(cache_dir, f"embedding_cache_{safe}.json"))
        return CachedEmbeddingProvider(base)
    raise ValueError(f"unknown ACI_EMBEDDINGS={spec!r} (want hash|ollama[:model])")
