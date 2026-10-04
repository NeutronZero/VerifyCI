"""Graph topology integrity and health diagnostics.

Analyzes collections of Entity and Edge records to detect dangling edges,
missing target entities, unauthorized self-loops, duplicate edges, and
unresolved call ratios with deterministic ordering.
"""
from __future__ import annotations

from dataclasses import dataclass

from verifyci.contracts.edge import CPGEdgeSubtype, Edge, EdgeType
from verifyci.contracts.entity import Entity


@dataclass(frozen=True)
class GraphDiagnosticsReport:
    total_entities: int
    total_edges: int
    dangling_edges: int
    missing_targets: list[str]
    self_loops: int
    duplicate_edges: int
    unresolved_calls: int
    cross_file_call_ratio: float


def compute_graph_diagnostics(
    entities: list[Entity],
    edges: list[Edge],
) -> GraphDiagnosticsReport:
    """Analyze entities and edges for structural anomalies."""
    entity_ids = {e.revision_entity_id for e in entities}
    entity_by_id = {e.revision_entity_id: e for e in entities}

    dangling_edges = 0
    missing_targets_set: set[str] = set()
    self_loops = 0
    unresolved_calls = 0
    resolved_calls = 0
    cross_file_calls = 0

    seen_edges: set[tuple[str, str, str, str | None]] = set()
    duplicate_edges = 0

    for edge in edges:
        # Check duplicate
        sub = edge.subtype.value if edge.subtype is not None else None
        key = (edge.src_entity_id, edge.dst_entity_id, edge.type.value, sub)
        if key in seen_edges:
            duplicate_edges += 1
        else:
            seen_edges.add(key)

        # Unresolved call count
        if edge.type == EdgeType.CALLS_UNRESOLVED:
            unresolved_calls += 1

        # Check self loops
        if edge.dst_entity_id and edge.src_entity_id == edge.dst_entity_id:
            if edge.subtype != CPGEdgeSubtype.CALLS_RECURSIVE:
                self_loops += 1

        # Check dangling edges
        src_exists = edge.src_entity_id in entity_ids
        if edge.dst_entity_id:
            dst_exists = edge.dst_entity_id in entity_ids
            if not dst_exists:
                missing_targets_set.add(edge.dst_entity_id)
            if not src_exists or not dst_exists:
                dangling_edges += 1
            else:
                # Both endpoints exist, check if cross-file call
                if edge.type == EdgeType.CALLS and edge.subtype in (
                    CPGEdgeSubtype.CALLS_DIRECT,
                    CPGEdgeSubtype.CALLS_RECURSIVE,
                ):
                    resolved_calls += 1
                    src_ent = entity_by_id.get(edge.src_entity_id)
                    dst_ent = entity_by_id.get(edge.dst_entity_id)
                    if src_ent and dst_ent and src_ent.file_path != dst_ent.file_path:
                        cross_file_calls += 1
        else:
            # Empty dst is expected for unresolved edges
            if not src_exists:
                dangling_edges += 1

    ratio = (cross_file_calls / resolved_calls) if resolved_calls > 0 else 0.0

    return GraphDiagnosticsReport(
        total_entities=len(entities),
        total_edges=len(edges),
        dangling_edges=dangling_edges,
        missing_targets=sorted(missing_targets_set),
        self_loops=self_loops,
        duplicate_edges=duplicate_edges,
        unresolved_calls=unresolved_calls,
        cross_file_call_ratio=round(ratio, 4),
    )
