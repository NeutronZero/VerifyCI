from typing import Any

from verifyci.contracts.edge import EdgeType
from verifyci.retrieval.dense import SearchResult

#: Relationship edges that mean "related code" for retrieval expansion.
#: Structural edges (CONTAINS file<->symbol, DOCUMENTS, DEFINES) are excluded:
#: a two-hop expansion that traversed CONTAINS pulled in an entire module for every seed,
#: drowning the graph channel's signal in file rows.
TRAVERSABLE_EDGE_TYPES = frozenset({
    EdgeType.CALLS, EdgeType.CALLS_UNRESOLVED,
    EdgeType.IMPORTS, EdgeType.INHERITS, EdgeType.INHERITS_UNRESOLVED,
    EdgeType.DEPENDS_ON,
    EdgeType.IMPLEMENTS, EdgeType.REFERENCES, EdgeType.USES,
    EdgeType.RETURNS, EdgeType.DECORATES,
})

_TRAVERSABLE_VALUES = frozenset(
    t.value if hasattr(t, "value") else str(t) for t in TRAVERSABLE_EDGE_TYPES
)


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
    PyDiGraph and the test doubles), pre-indexed (outgoing, incoming)
    adjacency is built once from edge payloads filtered to TRAVERSABLE_EDGE_TYPES
    and cached for zero-overhead index reuse.
    
    Traversal follows canonical semantic influence:
    - Outgoing BFS from seeds reaches direct/transitive callees
    - Incoming BFS from seeds reaches direct/transitive callers
    Combining both directions at each node preserves directed influence
    without leaking into unrelated caller-of-callee clusters.
    
    Results are ordered by multi-attribute ranking: (-score, id),
    ensuring closer hops beat farther ones and equidistant ties break
    deterministically by entity ID.
    """

    def __init__(self, graph, node_map: dict = None):
        self.graph = graph
        self.node_map = node_map or {}
        self._cached_adj = None
        self._cached_adj_fp: str | None = None

    def invalidate(self) -> None:
        """Drop cached adjacency (call after mutating the graph in place)."""
        self._cached_adj = None
        self._cached_adj_fp = None

    def retrieve(self, seed_entity_ids: list[str], max_hops: int = 2) -> list[SearchResult]:
        if self.graph is None or max_hops <= 0 or not seed_entity_ids:
            return []

        from verifyci.graph.traverse import as_index, edge_allowed
        edge_adj = self._adjacency_from_edges()
        if edge_adj is not None:
            outgoing_adj, incoming_adj = edge_adj
            seeds = [self.node_map[eid] for eid in seed_entity_ids
                      if eid in self.node_map]
            if not seeds:
                return []
            reverse = {v: k for k, v in self.node_map.items()}
            to_id = lambda node: reverse.get(node, str(node))  # noqa: E731

            seed_set = set(seeds)

            def _bfs_dir(adj_map: dict[int, set[int]]) -> dict[int, int]:
                visited = set(seed_set)
                current = set(seed_set)
                hop_map: dict[int, int] = {}
                for h in range(1, max_hops + 1):
                    nxt = set()
                    for u in current:
                        for v in adj_map.get(u, ()):
                            if v not in visited:
                                visited.add(v)
                                hop_map[v] = h
                                nxt.add(v)
                    current = nxt
                    if not current:
                        break
                return hop_map

            callee_hops = _bfs_dir(outgoing_adj)
            caller_hops = _bfs_dir(incoming_adj)

            all_impacted = set(callee_hops.keys()) | set(caller_hops.keys())
            distances = {
                node: min(callee_hops.get(node, 999), caller_hops.get(node, 999))
                for node in all_impacted
            }
        else:
            successors = getattr(self.graph, "successors", None)
            predecessors = getattr(self.graph, "predecessors", None)
            if not (callable(successors) or callable(predecessors)):
                return []
            # Fail-closed fallback: without edge payloads the traversable
            # filter cannot be enforced for index-addressed graphs. Str-id
            # legacy graphs (old test fakes) traverse unfiltered by
            # explicit legacy contract below; int-index graphs without an
            # edge-data API return no unfiltered partials — they skip
            # per-edge (fail closed) instead of silently mixing CONTAINS
            # and DOCUMENTS neighbours into semantic results.
            has_edge_api = callable(getattr(self.graph, "get_all_edge_data", None))
            seeds = ([self.node_map[eid] for eid in seed_entity_ids
                      if eid in self.node_map]
                     + [eid for eid in seed_entity_ids
                        if eid not in self.node_map])
            if not seeds:
                return []
            reverse = {v: k for k, v in self.node_map.items()}
            to_id = lambda node: reverse.get(node, str(node))  # noqa: E731
            seed_set = set(seeds)

            def _bfs_fn(fn, is_incoming: bool) -> dict[Any, int]:
                if not callable(fn):
                    return {}
                visited = set(seed_set)
                current = set(seed_set)
                hop_map: dict[Any, int] = {}
                for h in range(1, max_hops + 1):
                    nxt = set()
                    for u in current:
                        try:
                            neighbors = fn(u)
                        except Exception:  # noqa: BLE001
                            continue
                        for raw in neighbors:
                            neighbor = as_index(raw, self.node_map)
                            if neighbor is None and isinstance(raw, str):
                                # Legacy str-id graphs only: no edge payloads
                                # exist to filter on, so traversal is
                                # explicitly unfiltered (old-shape contract,
                                # covered by test). Int-index graphs never
                                # take this path — see below.
                                neighbor = raw
                            if neighbor is None or neighbor in visited:
                                continue
                            if isinstance(u, int) and isinstance(neighbor, int):
                                if not has_edge_api and isinstance(raw, int):
                                    # Raw index-addressed graph without an
                                    # edge-data API: traversability
                                    # unverifiable — fail closed per-edge
                                    # (skip) instead of emitting a silent
                                    # unfiltered partial. Payload-resolved
                                    # neighbours (adapter yields payload
                                    # objects mapped via node_map) keep the
                                    # established no-API contract
                                    # (edge_allowed traverses unfiltered).
                                    continue
                                try:
                                    src, dst = (neighbor, u) if is_incoming else (u, neighbor)
                                    if not edge_allowed(self.graph, src, dst, _TRAVERSABLE_VALUES):
                                        continue
                                except RuntimeError:
                                    continue
                            visited.add(neighbor)
                            hop_map[neighbor] = h
                            nxt.add(neighbor)
                    current = nxt
                    if not current:
                        break
                return hop_map

            callee_hops = _bfs_fn(successors, is_incoming=False)
            caller_hops = _bfs_fn(predecessors, is_incoming=True)

            all_impacted = set(callee_hops.keys()) | set(caller_hops.keys())
            distances = {
                node: min(callee_hops.get(node, 999), caller_hops.get(node, 999))
                for node in all_impacted
            }

        results = [
            SearchResult(
                id=to_id(node),
                score=round(1.0 / dist, 6),
                metadata={"hops": dist},
            )
            for node, dist in distances.items()
        ]
        results.sort(key=lambda r: (-r.score, r.id))
        return results

    def _adjacency_from_edges(self):
        """(outgoing, incoming) adjacency indices built from traversable edge payloads.
        Cached on the graph instance for zero-overhead index reuse across queries.
        Cache key is a content fingerprint (edge count plus the sorted
        (src, dst, type) triples): a same-count edge replacement or relabel
        must not reuse a stale adjacency. A size-only key did exactly that.
        """
        import hashlib as _hashlib
        import json as _json

        def _type_name(payload) -> str:
            etype = getattr(payload, "type", None)
            return getattr(etype, "value", etype) if etype is not None else "?"

        index = getattr(self.graph, "edge_index_map", None)
        if not callable(index):
            return None
        try:
            raw_index = index()
            fingerprint = _hashlib.sha256(_json.dumps(sorted(
                (src, dst, str(_type_name(payload)))
                for _, (src, dst, payload) in raw_index.items()
            ), sort_keys=True).encode("utf-8")).hexdigest()
        except Exception:  # noqa: BLE001 - unfamiliar adapter shape
            return None
        cached = getattr(self.graph, "_verifyci_adj_cache", None)
        cached_fp = getattr(self.graph, "_verifyci_adj_cache_fp", None)
        if cached is not None and cached_fp == fingerprint:
            return cached
        if self._cached_adj is not None and getattr(
                self, "_cached_adj_fp", None) == fingerprint:
            return self._cached_adj

        outgoing: dict[int, set[int]] = {}
        incoming: dict[int, set[int]] = {}
        try:
            for _eidx, entry in raw_index.items():
                src, dst, payload = entry[0], entry[1], entry[2]
                if not _traversable(payload):
                    continue
                outgoing.setdefault(src, set()).add(dst)
                incoming.setdefault(dst, set()).add(src)
        except Exception:  # noqa: BLE001 - unfamiliar adapter shape
            return None
        result = (outgoing, incoming)
        self._cached_adj = result
        self._cached_adj_fp = fingerprint
        try:
            self.graph._verifyci_adj_cache = result
            self.graph._verifyci_adj_cache_fp = fingerprint
        except Exception:
            pass
        return result
