from src.retrieval.dense import SearchResult
from src.retrieval.provider import SentenceTransformerProvider
from src.retrieval.reranker import CrossEncoderReranker, OfflineReranker, Reranker


def test_offline_reranker_is_explicit_backend():
    assert OfflineReranker.backend == "offline"
    assert isinstance(OfflineReranker(), Reranker)


def test_default_provider_is_offline_without_downloads():
    reranker = CrossEncoderReranker()
    assert reranker.backend == "offline"
    assert isinstance(reranker, Reranker)


def test_reranker_prefers_token_overlap():
    reranker = CrossEncoderReranker()
    results = [
        SearchResult(id="a", score=0.9, metadata={"text": "unrelated database sql"}),
        SearchResult(id="b", score=0.1, metadata={"text": "authentication login flow"}),
    ]
    ranked = reranker.rerank("authentication login", results)
    assert ranked[0].id == "b"


def test_reranker_respects_k():
    reranker = CrossEncoderReranker()
    results = [SearchResult(id=str(i), score=float(i), metadata={"text": "x"}) for i in range(5)]
    assert len(reranker.rerank("x", results, k=2)) == 2


def test_rerank_attaches_own_scores_in_order():
    # Regression: rerank sorted but returned untouched inputs, so every
    # printed score was the input score (0.0 in the query path).
    reranker = OfflineReranker()
    results = [
        SearchResult(id="a", score=0.9, metadata={"text": "unrelated database sql"}),
        SearchResult(id="b", score=0.1, metadata={"text": "authentication login flow"}),
    ]
    ranked = reranker.rerank("authentication login", results)
    scores = [r.score for r in ranked]
    assert scores == sorted(scores, reverse=True)
    assert ranked[0].score > 0.0
    assert ranked[0].score == reranker.score("authentication login", "b authentication login flow")


def test_rerank_never_invents_results():
    reranker = OfflineReranker()
    results = [SearchResult(id=str(i), score=0.0, metadata={"text": f"doc {i}"}) for i in range(4)]
    ranked = reranker.rerank("doc", results, k=10)
    assert {r.id for r in ranked} <= {r.id for r in results}


def test_st_provider_is_lazy_and_named():
    # Hermetic: constructing must not import torch or touch disk/network.
    provider = SentenceTransformerProvider()
    assert provider.model_name() == "sentence-transformers/all-MiniLM-L6-v2"
    assert provider._embedder is None
