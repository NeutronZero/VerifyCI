"""Shared graph-traversal helpers for rustworkx-backed graphs.

This rustworkx version yields node *payloads* (not indices) from
``successors()``/``predecessors()``; every helper here normalizes back to
indices via a node map. Edge-type filtering degrades gracefully: graphs
without an edge-data API (test fakes) are traversed unfiltered.
"""
from typing import Any

#: Edge types that carry call/dependency influence. CONTAINS/HAS_NAME are
#: structural and excluded so blast radius measures real dependents.
#: REFERENCES is excluded to eliminate non-causal identifier fanout.
CALL_FLOW_TYPES = frozenset({"CALLS", "IMPORTS", "INHERITS", "DEPENDS_ON"})


def payload_id(payload: Any) -> str | None:
    for attr in ("revision_entity_id", "logical_entity_id", "name"):
        value = getattr(payload, attr, None)
        if value:
            return str(value)
    if isinstance(payload, dict):
        for key in ("revision_entity_id", "logical_entity_id", "name"):
            if payload.get(key):
                return str(payload[key])
    return None


class NodeMapError(Exception):
    """The graph object is unreadable or internally inconsistent."""


def derive_node_map(graph: Any) -> dict[str, int]:
    node_map: dict[str, int] = {}
    if graph is None or not hasattr(graph, "node_indices"):
        return node_map
    try:
        indices = list(graph.node_indices())
        datas = list(graph.nodes()) if hasattr(graph, "nodes") else []
    except Exception as e:  # noqa: BLE001
        raise NodeMapError(f"graph nodes unreadable: {type(e).__name__}: {e}") from e
    if hasattr(graph, "nodes") and len(indices) != len(datas):
        # zip() would silently drop the tail and every later check would
        # pass on a partial map, forever, with no signal.
        raise NodeMapError(
            f"node_indices ({len(indices)}) and nodes ({len(datas)}) disagree")
    for idx, data in zip(indices, datas):
        eid = payload_id(data)
        if eid:
            node_map[eid] = idx
    return node_map


def as_index(neighbor: Any, node_map: dict) -> int | None:
    if isinstance(neighbor, int):
        return neighbor
    eid = payload_id(neighbor)
    return node_map.get(eid) if eid is not None else None


def _edge_payloads_between(graph: Any, src_idx: int, dst_idx: int) -> list[Any] | None:
    """Edge payloads from src to dst, or None when the graph has no edge API."""
    fn = getattr(graph, "get_all_edge_data", None)
    if not callable(fn):
        return None
    try:
        return list(fn(src_idx, dst_idx))
    except Exception:  # noqa: BLE001, S110
        return None


def _edge_type_name(edge: Any) -> str | None:
    etype = getattr(edge, "type", None)
    if etype is None and isinstance(edge, dict):
        etype = edge.get("type")
    if etype is None:
        return None
    return getattr(etype, "value", etype)


def edge_allowed(graph: Any, src_idx: int, dst_idx: int, allowed: set[str] | frozenset | None) -> bool:
    if not allowed:
        return True
    payloads = _edge_payloads_between(graph, src_idx, dst_idx)
    if payloads is None:
        return True  # no edge API (fake graphs): traverse unfiltered
    return any(_edge_type_name(e) in allowed for e in payloads)


def traverse(
    graph: Any,
    seed_idx: int,
    direction: str,
    max_hops: int,
    node_map: dict | None = None,
    allowed_types: set[str] | frozenset | None = None,
) -> set[int]:
    """BFS from seed following predecessors (incoming) or successors.

    Returns visited indices excluding the seed.
    """
    node_map = node_map or {}
    visited = {seed_idx}
    current_level = {seed_idx}
    for _ in range(max_hops):
        next_level = set()
        for idx in current_level:
            if direction == "incoming":
                neighbors = graph.predecessors(idx) if hasattr(graph, "predecessors") else []
                pairs = [("in", n) for n in neighbors]
            else:
                neighbors = graph.successors(idx) if hasattr(graph, "successors") else []
                pairs = [("out", n) for n in neighbors]
            for kind, neighbor in pairs:
                nidx = as_index(neighbor, node_map)
                if nidx is None or nidx in visited:
                    continue
                if kind == "in":
                    ok = edge_allowed(graph, nidx, idx, allowed_types)
                else:
                    ok = edge_allowed(graph, idx, nidx, allowed_types)
                if ok:
                    next_level.add(nidx)
        visited.update(next_level)
        current_level = next_level
        if not current_level:
            break
    visited.discard(seed_idx)
    return visited


def iter_edge_payloads(graph: Any) -> list[Any]:
    fn = getattr(graph, "edge_index_map", None)
    if not callable(fn):
        return []
    try:
        return [payload for _, (_, _, payload) in fn().items()]
    except Exception:  # noqa: BLE001, S110
        return []
