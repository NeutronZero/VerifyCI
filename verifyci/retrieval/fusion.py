from verifyci.retrieval.dense import SearchResult


def rrf_fusion_with_scores(
    dense_results: list[SearchResult],
    sparse_results: list[SearchResult],
    graph_results: list[SearchResult],
    k: int = 60,
    weights: tuple[float, float, float] = (1.0, 1.0, 1.0),
) -> list[tuple[str, float]]:
    """Reciprocal-rank fusion with per-channel weights.

    Default weights are equal (historical behavior, unchanged). Weighted
    variants (e.g. sparse-boosted ablations) pass explicit weights instead
    of forking a second implementation.
    """
    if k <= 0:
        k = 60
    w_dense, w_sparse, w_graph = weights
    scores = {}
    for rank, result in enumerate(dense_results):
        scores[result.id] = scores.get(result.id, 0) + w_dense / (k + rank + 1)
    for rank, result in enumerate(sparse_results):
        scores[result.id] = scores.get(result.id, 0) + w_sparse / (k + rank + 1)
    for rank, result in enumerate(graph_results):
        scores[result.id] = scores.get(result.id, 0) + w_graph / (k + rank + 1)
    return sorted(scores.items(), key=lambda t: (-t[1], t[0]))


def rrf_fusion(
    dense_results: list[SearchResult],
    sparse_results: list[SearchResult],
    graph_results: list[SearchResult],
    k: int = 60,
    weights: tuple[float, float, float] = (1.0, 1.0, 1.0),
) -> list[str]:
    return [doc_id for doc_id, _ in rrf_fusion_with_scores(
        dense_results, sparse_results, graph_results, k, weights)]
