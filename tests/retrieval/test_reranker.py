from src.retrieval.dense import SearchResult
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
