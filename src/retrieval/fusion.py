from src.retrieval.dense import SearchResult


def rrf_fusion(
    dense_results: list[SearchResult],
    sparse_results: list[SearchResult],
    graph_results: list[SearchResult],
    k: int = 60,
) -> list[str]:
    scores = {}
    for rank, result in enumerate(dense_results):
        scores[result.id] = scores.get(result.id, 0) + 1.0 / (k + rank + 1)
    for rank, result in enumerate(sparse_results):
        scores[result.id] = scores.get(result.id, 0) + 1.0 / (k + rank + 1)
    for rank, result in enumerate(graph_results):
        scores[result.id] = scores.get(result.id, 0) + 1.0 / (k + rank + 1)
    return sorted(scores, key=scores.get, reverse=True)
