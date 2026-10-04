from verifyci.contracts.edge import EdgeType
from verifyci.retrieval.dense import SearchResult

#: Relationship edges that mean "related code" for retrieval expansion.
#: Structural edges (CONTAINS file<->symbol, DOCUMENTS, DEFINES) and
#: SBOM DEPENDS_ON are excluded: a two-hop expansion that traversed
#: CONTAINS pulled in an entire module for every seed, drowning the
#: graph channel's signal in file rows.
TRAVERSABLE_EDGE_TYPES = frozenset({
    EdgeType.CALLS, EdgeType.CALLS_UNRESOLVED,
    EdgeType.IMPORTS, EdgeType.INHERITS, EdgeType.INHERITS_UNRESOLVED,
    EdgeType.IMPLEMENTS, EdgeType.REFERENCES, EdgeType.USES,
    EdgeType.RETURNS, EdgeType.DECORATES,
})

_TRAVERSABLE_VALUES = frozenset(t.value for t in TRAVERSABLE_EDGE_TYPES)


def _traversable(payload) -> bool:
    etype = getattr(payload, "type", None)
    if etype is None:
        return False
    if isinstance(etype, EdgeType):
        return etype in TRAVERSABLE_EDGE_TYPES
    return etype in _TRAVERSABLE_VALUES


class GraphRetriever:
    """Expand a seed set along *semantic* edges, scored by hop distance.

    Primary path: when the graph exposes `edge_index_map()` (rustworkx
    PyDiGraph and the test doubles), adjacency is built from edge
    payloads filtered to TRAVERSABLE_EDGE_TYPES, so containment/document
    edges never carry a seed into its whole module. Fallback: graphs that
    only expose successor/predecessor neighbors are expanded through
    those callables, unfiltered (still distance-scored, still
    deterministic) so retrieval never breaks on an unfamiliar adapter.
    Results are ordered by (-score, id): closer hops beat farther ones,
    ties break on id.
    """

    def __init__(self, graph, node_map: dict = None):
        self.graph = graph
        self.node_map = node_map or {}

    def retrieve(self, seed_entity_ids: list[str], max_hops: int = 2) -> list[SearchResult]:
        if self.graph is None or max_hops <= 0 or not seed_entity_ids:
            return []

        from verifyci.graph.traverse import as_index, edge_allowed
        edge_adj = self._adjacency_from_edges()
        if edge_adj is not None:
            seeds = [self.node_map[eid] for eid in seed_entity_ids
                      if eid in self.node_map]
            reverse = {v: k for k, v in self.node_map.items()}
            adj, neighbors = edge_adj, None
            to_id = lambda node: reverse.get(node, str(node))  # noqa: E731
        else:
            successors = getattr(self.graph, "successors", None)
            predecessors = getattr(self.graph, "predecessors", None)
            if not (callable(successors) or callable(predecessors)):
                return []
            # Hybrid seeds: mapped ids expand by index (rustworkx
            # successors take indices and yield PAYLOADS, normalized
            # via as_index exactly like traverse); unmapped ids pass
            # through verbatim so old id-based adapters keep working.
            seeds = ([self.node_map[eid] for eid in seed_entity_ids
                      if eid in self.node_map]
                     + [eid for eid in seed_entity_ids
                        if eid not in self.node_map])
            adj, neighbors = None, (successors, predecessors)
            reverse = {v: k for k, v in self.node_map.items()}
            to_id = lambda node: reverse.get(node, str(node))  # noqa: E731
        if not seeds:
            return []

        seed_set = set(seeds)
        distances = {}
        frontier = seed_set
        for hop in range(1, max_hops + 1):
            nxt = set()
            for node in frontier:
                for raw in self._expand(adj, neighbors, node):
                    neighbor = raw
                    if adj is None:
                        # Fallback yields PAYLOADS (rustworkx included),
                        # not indices: normalize exactly like
                        # traverse.as_index. Raw string ids from
                        # old id-based adapters pass through verbatim.
                        neighbor = as_index(raw, self.node_map)
                        if neighbor is None and isinstance(raw, str):
                            neighbor = raw
                    if neighbor is None or neighbor in seed_set or neighbor in distances:
                        continue
                    if adj is None and isinstance(node, int) and isinstance(neighbor, int):
                        # Fallback relation filter (same rule as
                        # traverse.edge_allowed): semantic edges expand,
                        # containment/docs do not. Graphs without an
                        # edge API bypass unfiltered; unmapped string
                        # ids bypass below this check entirely.
                        try:
                            if not (edge_allowed(self.graph, node, neighbor,
                                                 _TRAVERSABLE_VALUES)
                                    or edge_allowed(self.graph, neighbor, node,
                                                    _TRAVERSABLE_VALUES)):
                                continue
                        except RuntimeError:
                            continue
                    distances[neighbor] = hop
                    nxt.add(neighbor)
            frontier = nxt
            if not frontier:
                break

        results = [SearchResult(id=to_id(node), score=1.0 / dist,
                                metadata={"hops": dist})
                   for node, dist in distances.items()]
        results.sort(key=lambda r: (-r.score, r.id))
        return results

    def _expand(self, adj, neighbors, node) -> list:
        if adj is not None:
            return adj.get(node, ())
        successors, predecessors = neighbors
        out = []
        for fn in (successors, predecessors):
            if callable(fn):
                try:
                    out.extend(fn(node))
                except Exception:  # noqa: BLE001 - adapter-specific shapes
                    continue
        return out

    def _adjacency_from_edges(self):
        """(src->dst, dst->src) from edge payloads, filtered to semantic
        edges. Returns None when the graph does not expose
        edge_index_map, so the caller falls back to neighbor expansion."""
        index = getattr(self.graph, "edge_index_map", None)
        if not callable(index):
            return None
        adj: dict = {}
        try:
            for _eidx, entry in index().items():
                src, dst, payload = entry[0], entry[1], entry[2]
                if not _traversable(payload):
                    continue
                adj.setdefault(src, set()).add(dst)
                adj.setdefault(dst, set()).add(src)
        except Exception:  # noqa: BLE001 - unfamiliar adapter shape
            return None
        return adj
