"""Cost-weighted, thread-safe, immutability-guaranteed graph snapshot cache.

Prevents repeated whole-graph construction ($O(V+E)$ work) across verifications
using an estimated cost ceiling eviction heuristic (nodes + 2 * edges),
preventing concurrent duplicate builds (single-flight), and guaranteeing that
cached snapshots cannot be mutated.
"""
from __future__ import annotations

from collections import OrderedDict
import threading
from types import MappingProxyType
from typing import Any, Callable

DEFAULT_MAX_CACHE_COST = 200_000
"""Estimated cost ceiling ($V + 2E$), serving as a heuristic eviction threshold
rather than a measured byte-level memory limit.
"""


def estimate_graph_cost(entities: list | tuple, edges: list | tuple) -> int:
    """Documented cost estimate accounting for entity nodes, edge adjacency, and metadata."""
    return len(entities) + len(edges) * 2


class ImmutableGraphView:
    """Read-only view over a code graph preventing mutating operations.

    Delegates all query/traversal methods to the underlying graph while raising
    TypeError on any attempt to call mutating methods (add_node, add_edge, etc.).
    """

    def __init__(self, graph: Any):
        self._graph = graph

    def __getattr__(self, name: str) -> Any:
        if name.startswith(("add_", "remove_", "clear", "extend_")) or name in (
            "insert_node", "insert_edge"
        ):
            raise TypeError(f"ImmutableGraphView cannot be modified: attempt to call '{name}'")
        return getattr(self._graph, name)

    def __len__(self) -> int:
        return len(self._graph)

    def __getitem__(self, idx: Any) -> Any:
        return self._graph[idx]

    def __iter__(self):
        return iter(self._graph)

    def nodes(self):
        return self._graph.nodes()

    def successors(self, idx):
        return self._graph.successors(idx)

    def predecessors(self, idx):
        return self._graph.predecessors(idx)

    def in_edges(self, idx):
        return self._graph.in_edges(idx)

    def out_edges(self, idx):
        return self._graph.out_edges(idx)

    def get_edge_data(self, u, v):
        return self._graph.get_edge_data(u, v)

    def get_all_edge_data(self, u, v):
        fn = getattr(self._graph, "get_all_edge_data", None)
        if callable(fn):
            return fn(u, v)
        raise AttributeError("Underlying graph does not implement get_all_edge_data")

    def edge_index_map(self):
        return self._graph.edge_index_map()


def _wrap_graph(graph: Any) -> Any:
    if graph is None or isinstance(graph, ImmutableGraphView):
        return graph
    return ImmutableGraphView(graph)


class GraphSnapshotCache:
    """Thread-safe LRU cache storing built code graphs.

    Invariants:
    1. Single-flight loading: concurrent cache misses for the same key produce exactly one build.
    2. Estimated cost ceiling: snapshots exceeding max_cost are never cached.
    3. State cleanup: lock tracking is cleanly removed on both success and failure.
    4. Immutability: cached graph data structures are protected against caller mutation.
    """

    def __init__(self, max_cost: int = DEFAULT_MAX_CACHE_COST):
        self._max_cost = max_cost
        self._current_cost = 0
        self._lock = threading.Lock()
        self._key_locks: dict[tuple, tuple[threading.Lock, int]] = {}
        # key -> (graph, node_map_proxy, entities_tuple, cost)
        self._cache: OrderedDict[tuple, tuple[Any, MappingProxyType, tuple, int]] = OrderedDict()

    def get_or_load(
        self,
        key: tuple,
        loader_fn: Callable[[], tuple[Any, dict, list, list]],
    ) -> tuple[Any, dict, list]:
        """Retrieve from cache, or invoke loader_fn under a single-flight lock.

        loader_fn must return `(graph, node_map, entities, edges)`.
        Returns `(graph, node_map, entities)` where node_map and entities are safe copies
        and graph is protected against mutation.
        """
        # Fast path under global lock
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                graph, node_map, entities, _ = self._cache[key]
                return _wrap_graph(graph), dict(node_map), list(entities)

            # Register or acquire single-flight key lock
            if key in self._key_locks:
                key_lock, count = self._key_locks[key]
                self._key_locks[key] = (key_lock, count + 1)
            else:
                key_lock = threading.Lock()
                self._key_locks[key] = (key_lock, 1)

        try:
            with key_lock:
                # Re-check under key lock
                with self._lock:
                    if key in self._cache:
                        self._cache.move_to_end(key)
                        graph, node_map, entities, _ = self._cache[key]
                        return _wrap_graph(graph), dict(node_map), list(entities)

                # Execute load
                graph, node_map, entities, edges = loader_fn()
                cost = estimate_graph_cost(entities, edges)

                with self._lock:
                    # Only cache if snapshot fits within max_cost
                    if cost <= self._max_cost:
                        while (self._current_cost + cost > self._max_cost) and self._cache:
                            _, (_, _, _, old_cost) = self._cache.popitem(last=False)
                            self._current_cost -= old_cost

                        self._cache[key] = (
                            graph,
                            MappingProxyType(dict(node_map)),
                            tuple(entities),
                            cost,
                        )
                        self._current_cost += cost

                return _wrap_graph(graph), dict(node_map), list(entities)
        finally:
            with self._lock:
                if key in self._key_locks:
                    k_lock, count = self._key_locks[key]
                    if count <= 1:
                        del self._key_locks[key]
                    else:
                        self._key_locks[key] = (k_lock, count - 1)

    def clear(self) -> None:
        """Clear all cached snapshots and reset cost."""
        with self._lock:
            self._cache.clear()
            self._current_cost = 0

    @property
    def current_cost(self) -> int:
        with self._lock:
            return self._current_cost


GLOBAL_GRAPH_CACHE = GraphSnapshotCache()
