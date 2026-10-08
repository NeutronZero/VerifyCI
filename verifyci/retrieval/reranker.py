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
    """Deterministic token-overlap scorer. No model, no network.

    Context-free graph-aware bonuses (roadmap item 9 subset): exact
    symbol match and qualified-path tail match. Both read only the
    query and each result's own id/metadata — no corpus statistics —
    so deliberate omissions are the ambiguity penalty and
    caller/callee proximity, which need index-wide counts the
    rerank() signature cannot see. Bonuses are fixed constants, and
    the lexical base still decides among non-matching results.
    """

    backend = "offline"

    EXACT_SYMBOL_BONUS = 0.5
    QUALIFIED_PATH_BONUS = 0.3

    def __init__(self, model: str = "offline-overlap",
                 exact_bonus: float | None = None,
                 qualified_bonus: float | None = None) -> None:
        self.model = model
        # Override hooks exist for ablation (baseline / exact-only /
        # qualified-only / both); production always uses the class
        # constants. None means "constant", so 0.0 disables explicitly.
        self.exact_bonus = self.EXACT_SYMBOL_BONUS \
            if exact_bonus is None else exact_bonus
        self.qualified_bonus = self.QUALIFIED_PATH_BONUS \
            if qualified_bonus is None else qualified_bonus

    def score(self, query: str, text: str) -> float:
        q = set(tokenize(query))
        t = set(tokenize(text))
        if not q or not t:
            return 0.0
        return len(q & t) / len(q | t)

    def _symbol_bonuses(self, query: str, result_id: str) -> float:
        """Exact symbol + qualified-path bonuses for one result id.

        A query token equal to the id is an exact symbol hit. A query
        token shaped as a path (`App.run`, `ns::helper`) whose tail is
        the id is a qualified hit. Both are substring-exact and case
        sensitive: symbol identity is case sensitive in every indexed
        language, and folding would invent matches.
        """
        bonus = 0.0
        tokens = query.split()
        if result_id and result_id in tokens:
            bonus += self.exact_bonus
        for token in tokens:
            tail = token.replace("::", ".").rsplit(".", 1)
            if len(tail) == 2 and tail[1] == result_id and tail[0]:
                bonus += self.qualified_bonus
                break
        return bonus

    def rerank(self, query: str, results: list[SearchResult], k: int = 10) -> list[SearchResult]:
        # Scores are attached, not passed through: callers must see the
        # reranker's own verdict per item (previously input scores leaked).
        scored = [
            SearchResult(id=r.id, score=self.score(
                query, f"{r.id} {' '.join(str(v) for v in r.metadata.values())}")
                + self._symbol_bonuses(query, r.id),
                metadata=r.metadata)
            for r in results
        ]
        scored.sort(key=lambda r: (-r.score, r.id))
        return scored[:k]


class CrossEncoderReranker(Reranker):
    """Pipeline reranker: real local cross-encoder when available, else offline.

    A real model is used only when ``model`` names a loadable local
    sentence-transformers CrossEncoder and ``local_files_only`` resolution
    succeeds. Nothing is ever downloaded.

    Deliberate divergence, recorded here so it stays deliberate: the
    cross-encoder path ranks by pure model scores, WITHOUT the
    OfflineReranker exact/qualified symbol bonuses. Neural and lexical
    orderings therefore differ by design; unifying them would need a
    measured relevance study, not a drive-by constant change.
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
            scored.sort(key=lambda r: (-r.score, r.id))
            return scored[:k]
        return self._delegate.rerank(query, results, k=k)
