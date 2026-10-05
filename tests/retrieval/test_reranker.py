from verifyci.retrieval.dense import SearchResult
from verifyci.retrieval.provider import SentenceTransformerProvider
from verifyci.retrieval.reranker import CrossEncoderReranker, OfflineReranker, Reranker


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


def test_exact_symbol_match_outranks_lexical_overlap():
    reranker = OfflineReranker()
    results = [
        SearchResult(id="parse", score=0.9, metadata={"text": "unrelated"}),
        SearchResult(id="other", score=0.1,
                     metadata={"text": "parse parse parse parse"}),
    ]
    ranked = reranker.rerank("where is parse defined", results)
    assert ranked[0].id == "parse"


def test_qualified_path_tail_matches_symbol():
    reranker = OfflineReranker()
    results = [
        SearchResult(id="run", score=0.0, metadata={"text": "App run method"}),
        SearchResult(id="walk", score=0.0, metadata={"text": "App run method"}),
    ]
    ranked = reranker.rerank("App.run", results)
    assert ranked[0].id == "run"
    ranked_ns = reranker.rerank("ns::helper", [
        SearchResult(id="helper", score=0.0, metadata={"text": "x"}),
        SearchResult(id="other", score=0.0, metadata={"text": "x"}),
    ])
    assert ranked_ns[0].id == "helper"


def test_symbol_bonuses_are_case_sensitive_and_deterministic():
    reranker = OfflineReranker()
    results = [
        SearchResult(id="Parse", score=0.0, metadata={"text": "parse"}),
        SearchResult(id="parse", score=0.0, metadata={"text": "parse"}),
    ]
    ranked = reranker.rerank("parse", results)
    assert ranked[0].id == "parse"
    again = reranker.rerank("parse", results)
    assert [r.id for r in again] == [r.id for r in ranked]
    assert reranker.EXACT_SYMBOL_BONUS > reranker.QUALIFIED_PATH_BONUS > 0


def test_zeroed_bonuses_equal_pure_lexical_scores():
    # Ablation baseline: with both bonuses at 0.0 the attached score
    # is exactly score(query, text), so feature effects isolate cleanly.
    reranker = OfflineReranker(exact_bonus=0.0, qualified_bonus=0.0)
    results = [
        SearchResult(id="parse", score=0.0, metadata={"text": "parse things"}),
        SearchResult(id="other", score=0.0, metadata={"text": "unrelated"}),
    ]
    ranked = reranker.rerank("where is parse", results)
    for r in ranked:
        assert r.score == reranker.score(
            "where is parse", f"{r.id} {r.metadata['text']}")


def test_st_provider_is_lazy_and_named():
    # Hermetic: constructing must not import torch or touch disk/network.
    provider = SentenceTransformerProvider()
    assert provider.model_name() == "sentence-transformers/all-MiniLM-L6-v2"
    assert provider._embedder is None
