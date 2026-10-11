"""Cost-weighted, thread-safe, immutability-guaranteed graph snapshot cache.

Prevents repeated whole-graph construction ($O(V+E)$ work) across verifications
using an estimated cost ceiling eviction heuristic (nodes + 2 * edges),
preventing concurrent duplicate builds (single-flight), and guaranteeing that
cached snapshots cannot be mutated.
"""
from __future__ import annotations

import dataclasses
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
    """Recursively freeze dictionaries, lists, sets, and dataclasses to prevent caller mutation of cached payloads."""
    if val is None or isinstance(val, (int, float, str, bool, bytes)):
        return val
    if isinstance(val, (Mapping, dict)):
        return MappingProxyType({k: _freeze_payload(v) for k, v in val.items()})
    if isinstance(val, (list, tuple)):
        return tuple(_freeze_payload(x) for x in val)
    if isinstance(val, (set, frozenset)):
        return frozenset(_freeze_payload(x) for x in val)
    if dataclasses.is_dataclass(val) and not isinstance(val, type):
        updates = {}
        for f in dataclasses.fields(val):
            field_val = getattr(val, f.name)
            frozen_val = _freeze_payload(field_val)
            if frozen_val is not field_val:
                updates[f.name] = frozen_val
        if updates:
            return dataclasses.replace(val, **updates)
        return val
    return val


class ImmutableGraphView:
    """Read-only view over a code graph enforcing strict immutability.

    Restricts graph access exclusively to supported query and traversal methods.
    Blocks all mutating methods, prohibits direct access to private attributes
    (such as `_graph`), disallows arbitrary method forwarding, and deeply freezes
    returned payloads (including nested dataclass fields) so shared cache state
    cannot be corrupted.
    """

    def __init__(self, graph: Any):
        object.__setattr__(self, "_graph", graph)

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError(f"ImmutableGraphView cannot be modified: attribute assignment '{name}' is forbidden")

    def __delattr__(self, name: str) -> None:
        raise TypeError(f"ImmutableGraphView cannot be modified: attribute deletion '{name}' is forbidden")

    def __getattribute__(self, name: str) -> Any:
        if name.startswith("_") and not (name.startswith("__") and name.endswith("__")):
            raise AttributeError(f"Direct access to private or internal attribute '{name}' is prohibited")
        return super().__getattribute__(name)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") and not (name.startswith("__") and name.endswith("__")):
            raise AttributeError(f"Direct access to private or internal attribute '{name}' is prohibited")
        if name in MUTATING_GRAPH_METHODS or name.startswith(("add_", "remove_", "clear", "extend_", "insert_", "update_")):
            raise TypeError(f"ImmutableGraphView cannot be modified: attempt to call mutating method '{name}'")
        raise AttributeError(f"'ImmutableGraphView' object has no attribute '{name}'")

    def __len__(self) -> int:
        return len(object.__getattribute__(self, "_graph"))

    def __getitem__(self, idx: Any) -> Any:
        return _freeze_payload(object.__getattribute__(self, "_graph")[idx])

    def __setitem__(self, idx: Any, value: Any) -> None:
        raise TypeError("ImmutableGraphView cannot be modified: item assignment is forbidden")

    def __delitem__(self, idx: Any) -> None:
        raise TypeError("ImmutableGraphView cannot be modified: item deletion is forbidden")

    def __contains__(self, idx: Any) -> bool:
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "has_node", None)
        if callable(fn):
            return bool(fn(idx))
        fn_indices = getattr(graph, "node_indices", None)
        if callable(fn_indices):
            return idx in fn_indices()
        return False

    def has_node(self, idx: Any) -> bool:
        return idx in self

    def __iter__(self):
        return iter(self.nodes())

    def nodes(self):
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "nodes", None)
        if callable(fn):
            return [_freeze_payload(n) for n in fn()]
        if hasattr(graph, "__iter__"):
            return [_freeze_payload(n) for n in graph]
        return []

    def node_indices(self):
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "node_indices", None)
        if callable(fn):
            return list(fn())
        return list(range(len(graph)))

    def num_nodes(self) -> int:
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "num_nodes", None)
        if callable(fn):
            return int(fn())
        return len(graph)

    def num_edges(self) -> int:
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "num_edges", None)
        if callable(fn):
            return int(fn())
        fn_edges = getattr(graph, "edge_list", None)
        if callable(fn_edges):
            return len(fn_edges())
        return 0

    def successors(self, idx: Any):
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "successors", None)
        if callable(fn):
            return [_freeze_payload(n) for n in fn(idx)]
        return []

    def predecessors(self, idx: Any):
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "predecessors", None)
        if callable(fn):
            return [_freeze_payload(n) for n in fn(idx)]
        return []

    def neighbors(self, idx: Any):
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "neighbors", None)
        if callable(fn):
            return [_freeze_payload(n) for n in fn(idx)]
        raise AttributeError("Underlying graph does not implement neighbors")

    def in_edges(self, idx: Any):
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "in_edges", None)
        if callable(fn):
            return [(src, dst, _freeze_payload(data)) for src, dst, data in fn(idx)]
        return []

    def out_edges(self, idx: Any):
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "out_edges", None)
        if callable(fn):
            return [(src, dst, _freeze_payload(data)) for src, dst, data in fn(idx)]
        return []

    def get_edge_data(self, u: Any, v: Any):
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "get_edge_data", None)
        if callable(fn):
            return _freeze_payload(fn(u, v))
        return None

    def get_all_edge_data(self, u: Any, v: Any):
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "get_all_edge_data", None)
        if callable(fn):
            return [_freeze_payload(d) for d in fn(u, v)]
        raise AttributeError("Underlying graph does not implement get_all_edge_data")

    def has_edge(self, u: Any, v: Any) -> bool:
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "has_edge", None)
        if callable(fn):
            return bool(fn(u, v))
        raise AttributeError("Underlying graph does not implement has_edge")

    def edge_index_map(self):
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "edge_index_map", None)
        if callable(fn):
            raw = fn()
            return {k: (src, dst, _freeze_payload(payload)) for k, (src, dst, payload) in raw.items()}
        raise AttributeError("Underlying graph does not implement edge_index_map")

    def edge_indices(self):
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "edge_indices", None)
        if callable(fn):
            return list(fn())
        raise AttributeError("Underlying graph does not implement edge_indices")

    def edge_list(self):
        graph = object.__getattribute__(self, "_graph")
        fn = getattr(graph, "edge_list", None)
        if callable(fn):
            return [(src, dst) for src, dst in fn()]
        raise AttributeError("Underlying graph does not implement edge_list")


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
