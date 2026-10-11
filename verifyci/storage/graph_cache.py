"""Cost-weighted, thread-safe, immutability-guaranteed graph snapshot cache.

Prevents repeated whole-graph construction ($O(V+E)$ work) across verifications
using an estimated cost ceiling eviction heuristic (nodes + 2 * edges),
preventing concurrent duplicate builds (single-flight), and guaranteeing that
cached snapshots cannot be mutated.
"""
from __future__ import annotations

from collections import OrderedDict
from collections.abc import Mapping
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

MUTATING_GRAPH_METHODS = frozenset({
    "add_child",
    "add_edge",
    "add_edges_from",
    "add_edges_from_no_data",
    "add_node",
    "add_nodes_from",
    "add_parent",
    "clear",
    "clear_edges",
    "compose",
    "contract_nodes",
    "extend_from_edge_list",
    "extend_from_weighted_edge_list",
    "insert_node_on_in_edges",
    "insert_node_on_in_edges_multiple",
    "insert_node_on_out_edges",
    "insert_node_on_out_edges_multiple",
    "make_symmetric",
    "merge_nodes",
    "remove_edge",
    "remove_edge_from_index",
    "remove_edges_from",
    "remove_node",
    "remove_node_retain_edges",
    "remove_node_retain_edges_by_id",
    "remove_node_retain_edges_by_key",
    "remove_nodes_from",
    "substitute_node_with_subgraph",
    "update_edge",
    "update_edge_by_index",
    "update_node",
})


def _freeze_payload(val: Any) -> Any:
    """Recursively freeze dictionaries, lists, and sets to prevent caller mutation of cached payloads."""
    if val is None or isinstance(val, (int, float, str, bool, bytes)):
        return val
    if isinstance(val, (Mapping, dict)):
        return MappingProxyType({k: _freeze_payload(v) for k, v in val.items()})
    if isinstance(val, (list, tuple)):
        return tuple(_freeze_payload(x) for x in val)
    if isinstance(val, set):
        return frozenset(_freeze_payload(x) for x in val)
    return val


class ImmutableGraphView:
    """Read-only view over a code graph preventing mutating operations.

    Delegates query/traversal methods to the underlying graph while raising
    TypeError on any attempt to call mutating methods or modify payloads.
    Direct access to private underlying graph attributes (_graph) is blocked.
    """

    def __init__(self, graph: Any):
        object.__setattr__(self, "_graph", graph)

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError(f"ImmutableGraphView cannot be modified: attribute assignment '{name}' is forbidden")

    def __delattr__(self, name: str) -> None:
        raise TypeError(f"ImmutableGraphView cannot be modified: attribute deletion '{name}' is forbidden")

    def __getattribute__(self, name: str) -> Any:
        if name == "_graph":
            raise AttributeError("Direct access to private _graph attribute is prohibited")
        return super().__getattribute__(name)

    def __getattr__(self, name: str) -> Any:
        if name == "_graph":
            raise AttributeError("Direct access to private _graph attribute is prohibited")
        graph = object.__getattribute__(self, "_graph")
        if name in MUTATING_GRAPH_METHODS or name.startswith(("add_", "remove_", "clear", "extend_", "insert_", "update_")):
            raise TypeError(f"ImmutableGraphView cannot be modified: attempt to call '{name}'")
        attr = getattr(graph, name)
        if callable(attr):
            return attr
        return _freeze_payload(attr)

    def _get_inner(self) -> Any:
        return object.__getattribute__(self, "_graph")

    def __len__(self) -> int:
        return len(self._get_inner())

    def __getitem__(self, idx: Any) -> Any:
        return _freeze_payload(self._get_inner()[idx])

    def __setitem__(self, idx: Any, value: Any) -> None:
        raise TypeError("ImmutableGraphView cannot be modified: item assignment is forbidden")

    def __delitem__(self, idx: Any) -> None:
        raise TypeError("ImmutableGraphView cannot be modified: item deletion is forbidden")

    def __iter__(self):
        return iter(self._get_inner())

    def nodes(self):
        return [_freeze_payload(n) for n in self._get_inner().nodes()]

    def node_indices(self):
        return self._get_inner().node_indices()

    def successors(self, idx):
        return [_freeze_payload(n) for n in self._get_inner().successors(idx)]

    def predecessors(self, idx):
        return [_freeze_payload(n) for n in self._get_inner().predecessors(idx)]

    def in_edges(self, idx):
        return [(src, dst, _freeze_payload(data)) for src, dst, data in self._get_inner().in_edges(idx)]

    def out_edges(self, idx):
        return [(src, dst, _freeze_payload(data)) for src, dst, data in self._get_inner().out_edges(idx)]

    def get_edge_data(self, u, v):
        return _freeze_payload(self._get_inner().get_edge_data(u, v))

    def get_all_edge_data(self, u, v):
        fn = getattr(self._get_inner(), "get_all_edge_data", None)
        if callable(fn):
            return [_freeze_payload(d) for d in fn(u, v)]
        raise AttributeError("Underlying graph does not implement get_all_edge_data")

    def edge_index_map(self):
        raw = self._get_inner().edge_index_map()
        return {k: (src, dst, _freeze_payload(payload)) for k, (src, dst, payload) in raw.items()}

    def num_nodes(self) -> int:
        return self._get_inner().num_nodes()

    def num_edges(self) -> int:
        return self._get_inner().num_edges()


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
