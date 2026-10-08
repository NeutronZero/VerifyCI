"""PHASE 4: retrieval hardening — unicode, weights, cache integrity, bounds."""
import math


def test_tokenize_unicode_identifiers():
    from verifyci.retrieval.textnorm import tokenize
    # Accented and CJK identifiers tokenize instead of vanishing.
    assert "café" in tokenize("café")
    assert tokenize("café") == tokenize("cafe\u0301")
    cjk = tokenize("数据库连接")
    assert cjk and all(t for t in cjk)


def test_tokenize_ascii_unchanged():
    from verifyci.retrieval.textnorm import tokenize
    assert tokenize("beam_search_paths") == ["beam", "search", "paths"]
    assert tokenize("beamSearch") == ["beam", "search"]
    assert tokenize("HTTPResponse") == ["http", "response"]
    assert tokenize("") == []


def test_rrf_weights_default_equal_and_override():
    from verifyci.retrieval.dense import SearchResult
    from verifyci.retrieval.fusion import rrf_fusion, rrf_fusion_with_scores

    def _res(i):
        return SearchResult(id=i, score=0.0, metadata={})

    dense = [_res("a"), _res("b")]
    sparse = [_res("b"), _res("c")]
    assert rrf_fusion(dense, sparse, []) == [
        d for d, _ in rrf_fusion_with_scores(dense, sparse, [])]
    boosted = rrf_fusion(dense, sparse, [], weights=(1.0, 100.0, 1.0))
    assert boosted[0] == "b"


def test_graph_retriever_cache_invalidates_on_relabel():
    from verifyci.retrieval.graph_retriever import GraphRetriever
    from verifyci.contracts.edge import EdgeType
    from types import SimpleNamespace

    def payload(t):
        return SimpleNamespace(type=t)

    index = {0: (0, 1, payload(EdgeType.CALLS))}
    graph = SimpleNamespace(edge_index_map=lambda: index)
    r = GraphRetriever(graph, {"a": 0, "b": 1})
    first = r.retrieve(["a"])
    assert [x.id for x in first] == ["b"]
    # Same edge count, different label: stale adjacency must not be reused.
    index[0] = (0, 1, payload(EdgeType.DOCUMENTS))
    assert r.retrieve(["a"]) == []
    # Restore traversable label under a new edge: adjacency refreshes.
    index[1] = (1, 0, payload(EdgeType.CALLS))
    third = r.retrieve(["a"])
    assert {x.id for x in third} >= {"b"}


def test_cached_provider_drops_corrupt_vectors(tmp_path):
    import json
    from verifyci.retrieval.provider import CachedEmbeddingProvider
    cache = tmp_path / "c.json"
    cache.write_text(json.dumps({
        "good": [0.1, 0.2],
        "nan": [float("nan"), 0.1],
        "inf": [float("inf"), 0.1],
        "strs": ["a", "b"],
        "empty": [],
        5: [0.1],
    }), encoding="utf-8")
    mem = CachedEmbeddingProvider._read_file(str(cache))
    # Note: JSON object keys are always strings, so integer key 5 arrives
    # as "5" with a valid vector and is legitimately kept.
    assert set(mem) == {"good", "5"}
    assert all(math.isfinite(x) for v in mem.values() for x in v)


def test_ollama_provider_has_bounded_timeout():
    from verifyci.retrieval.provider import OllamaEmbeddingProvider
    p = OllamaEmbeddingProvider()
    assert p.timeout_s == 30.0
