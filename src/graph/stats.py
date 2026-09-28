from typing import Any


def compute_stats(graph: Any, node_map: dict | None = None) -> dict[str, Any]:
    if graph is None:
        return {"nodes": 0, "edges": 0}
    nodes = graph.num_nodes() if hasattr(graph, "num_nodes") else 0
    edges = graph.num_edges() if hasattr(graph, "num_edges") else 0
    stats: dict[str, Any] = {"nodes": nodes, "edges": edges}
    if node_map is not None:
        stats["indexed"] = len(node_map)
    return stats
