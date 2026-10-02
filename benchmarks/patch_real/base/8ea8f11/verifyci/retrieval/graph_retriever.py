from verifyci.retrieval.dense import SearchResult


class GraphRetriever:
    def __init__(self, graph, node_map: dict = None):
        self.graph = graph
        self.node_map = node_map or {}

    def retrieve(self, seed_entity_ids: list[str], max_hops: int = 2) -> list[SearchResult]:
        if self.graph is None:
            return []

        seed_indices = []
        for eid in seed_entity_ids:
            idx = self.node_map.get(eid)
            if idx is not None:
                seed_indices.append(idx)

        if not seed_indices:
            return []

        visited = set()
        current_level = set(seed_indices)

        for _ in range(max_hops):
            next_level = set()
            for node_idx in current_level:
                if hasattr(self.graph, 'predecessors'):
                    next_level.update(_as_index(n, self.node_map) for n in self.graph.predecessors(node_idx))
                if hasattr(self.graph, 'successors'):
                    next_level.update(_as_index(n, self.node_map) for n in self.graph.successors(node_idx))
            next_level.discard(None)
            next_level -= visited
            visited.update(current_level)
            current_level = next_level

        visited.update(current_level)
        visited -= set(seed_indices)

        reverse_map = {v: k for k, v in self.node_map.items()}
        return [SearchResult(id=reverse_map.get(idx, str(idx)), score=1.0 / (max_hops + 1), metadata={}) for idx in visited]


def _as_index(neighbor, node_map: dict):
    if isinstance(neighbor, int):
        return neighbor
    eid = getattr(neighbor, "revision_entity_id", None)
    if eid is not None:
        return node_map.get(eid)
    return None
