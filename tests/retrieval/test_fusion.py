"""RRF fusion over dense/sparse/graph result lists."""
from verifyci.retrieval.dense import SearchResult
from verifyci.retrieval.fusion import rrf_fusion, rrf_fusion_with_scores


def _res(rid, score=1.0):
    return SearchResult(id=rid, score=score, metadata={})


def test_rrf_prefers_top_ranks_across_lists():
    dense = [_res("a"), _res("b")]
    sparse = [_res("b"), _res("c")]
    ranked = rrf_fusion_with_scores(dense, sparse, [])
    assert ranked[0][0] == "b"  # top-2 in two lists beats top-1 in one
    assert rrf_fusion(dense, sparse, [])[0] == "b"


def test_rrf_empty_inputs_yield_empty():
    assert rrf_fusion_with_scores([], [], []) == []
    assert rrf_fusion([], [], []) == []


def test_rrf_dedupes_ids():
    ranked = rrf_fusion_with_scores([_res("a")], [_res("a")], [_res("a")])
    assert [doc for doc, _ in ranked] == ["a"]
