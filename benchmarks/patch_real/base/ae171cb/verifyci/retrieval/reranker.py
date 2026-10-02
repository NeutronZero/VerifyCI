"""Rerank stage: Dense + BM25 + Graph -> RRF -> rerank.

``OfflineReranker`` is a deterministic lexical-overlap scorer for offline
use. ``CrossEncoderReranker`` is the pipeline provider: it loads a local
cross-encoder model when one is configured *and* available in the local
environment (never downloads); otherwise it delegates to
``OfflineReranker`` and reports ``backend == "offline"``.
"""
from abc import ABC, abstractmethod

from verifyci.retrieval.dense import SearchResult
from verifyci.retrieval.textnorm import tokenize


class Reranker(ABC):
    backend: str = "unknown"

    @abstractmethod
    def score(self, query: str, text: str) -> float: ...

    @abstractmethod
    def rerank(self, query: str, results: list[SearchResult], k: int = 10) -> list[SearchResult]: ...


class OfflineReranker(Reranker):
    """Deterministic token-overlap scorer. No model, no network."""

    backend = "offline"

    def __init__(self, model: str = "offline-overlap") -> None:
        self.model = model

    def score(self, query: str, text: str) -> float:
        q = set(tokenize(query))
        t = set(tokenize(text))
        if not q or not t:
            return 0.0
        return len(q & t) / len(q | t)

    def rerank(self, query: str, results: list[SearchResult], k: int = 10) -> list[SearchResult]:
        # Scores are attached, not passed through: callers must see the
        # reranker's own verdict per item (previously input scores leaked).
        scored = [
            SearchResult(id=r.id, score=self.score(
                query, f"{r.id} {' '.join(str(v) for v in r.metadata.values())}"),
                metadata=r.metadata)
            for r in results
        ]
        scored.sort(key=lambda r: r.score, reverse=True)
        return scored[:k]


class CrossEncoderReranker(Reranker):
    """Pipeline reranker: real local cross-encoder when available, else offline.

    A real model is used only when ``model`` names a loadable local
    sentence-transformers CrossEncoder and ``local_files_only`` resolution
    succeeds. Nothing is ever downloaded.
    """

    def __init__(self, model: str | None = None, local_files_only: bool = True) -> None:
        self.model = model or "offline-overlap"
        self._delegate: Reranker = OfflineReranker(self.model)
        self.backend = "offline"
        if model:
            self._try_load(model, local_files_only)

    def _try_load(self, model: str, local_files_only: bool) -> None:
        try:
            from sentence_transformers import CrossEncoder  # type: ignore
            self._cross_encoder = CrossEncoder(model, local_files_only=local_files_only)
            self.backend = "cross_encoder"
        except Exception:  # noqa: BLE001, S110
            pass

    def score(self, query: str, text: str) -> float:
        if self.backend == "cross_encoder":
            try:
                return float(self._cross_encoder.predict([(query, text)])[0])
            except Exception:  # noqa: BLE001
                pass
        return self._delegate.score(query, text)

    def rerank(self, query: str, results: list[SearchResult], k: int = 10) -> list[SearchResult]:
        if self.backend == "cross_encoder":
            scored = [
                SearchResult(id=r.id, score=self.score(
                    query, f"{r.id} {' '.join(str(v) for v in r.metadata.values())}"),
                    metadata=r.metadata)
                for r in results
            ]
            scored.sort(key=lambda r: r.score, reverse=True)
            return scored[:k]
        return self._delegate.rerank(query, results, k=k)
