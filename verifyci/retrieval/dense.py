from dataclasses import dataclass

from verifyci.retrieval.provider import EmbeddingProvider


@dataclass
class SearchResult:
    id: str
    score: float
    metadata: dict


class DenseRetriever:
    def __init__(self, provider: EmbeddingProvider):
        self.provider = provider
        self._index = {}

    def add(self, id: str, text: str, metadata: dict, embedding: list[float] | None = None):
        self._index[id] = {"text": text, "metadata": metadata, "embedding": embedding}

    async def build_index(self) -> None:
        """Batch-precompute embeddings for any items missing vectors."""
        missing = [i for i, item in self._index.items() if item.get("embedding") is None]
        if missing:
            texts = [self._index[i]["text"] for i in missing]
            vectors = await self.provider.embed(texts)
            for i, vec in zip(missing, vectors):
                self._index[i]["embedding"] = vec
        for item in self._index.values():
            if item.get("norm_embedding") is None and item.get("embedding") is not None:
                vec = item["embedding"]
                norm = sum(x * x for x in vec) ** 0.5
                norm_vec = [x / norm for x in vec] if norm > 0 else vec
                item["norm_embedding"] = norm_vec

    async def search(self, query: str, k: int = 10) -> list[SearchResult]:
        if not self._index:
            return []
        await self.build_index()
        query_embedding = (await self.provider.embed([query]))[0]
        q_norm = sum(x * x for x in query_embedding) ** 0.5
        query_norm = [x / q_norm for x in query_embedding] if q_norm > 0 else query_embedding
        results = []
        for id, item in self._index.items():
            norm_emb = item.get("norm_embedding")
            if not query_norm or not norm_emb or len(query_norm) != len(norm_emb) or q_norm == 0:
                score = 0.0
            else:
                score = sum(x * y for x, y in zip(query_norm, norm_emb))
            results.append(SearchResult(id=id, score=score, metadata=item["metadata"]))
        results.sort(key=lambda r: (-r.score, r.id))
        return results[:k]


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)
