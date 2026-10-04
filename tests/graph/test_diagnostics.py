import pytest

from verifyci.contracts.edge import CPGEdgeSubtype, Edge, EdgeType
from verifyci.contracts.entity import Entity, EntityType
from verifyci.graph.diagnostics import compute_graph_diagnostics


def _create_entity(eid: str, name: str, file_path: str = "src/a.py") -> Entity:
    return Entity(
        repository_id="repo",
        logical_entity_id=eid,
        revision_entity_id=eid,
        type=EntityType.FUNCTION,
        name=name,
        file_path=file_path,
        line_start=1,
        line_end=10,
        language="python",
        source_hash="h" * 64,
        revision_id="rev",
    )


def test_diagnostics_clean_graph():
    e1 = _create_entity("e1", "foo", "src/a.py")
    e2 = _create_entity("e2", "bar", "src/b.py")
    edge = Edge(
        id="edge1",
        revision_id="rev",
        src_entity_id="e1",
        dst_entity_id="e2",
        type=EdgeType.CALLS,
        subtype=CPGEdgeSubtype.CALLS_DIRECT,
        valid_from=1.0,
        observed_at=1.0,
        t_created=1.0,
    )
    report = compute_graph_diagnostics([e1, e2], [edge])
    assert report.total_entities == 2
    assert report.total_edges == 1
    assert report.dangling_edges == 0
    assert report.missing_targets == []
    assert report.self_loops == 0
    assert report.duplicate_edges == 0
    assert report.unresolved_calls == 0
    assert report.cross_file_call_ratio == 1.0  # src/a.py -> src/b.py


def test_diagnostics_anomalies_detected():
    e1 = _create_entity("e1", "foo", "src/a.py")
    # Dangling edge to missing target 'e99'
    dangling = Edge(
        id="dangling",
        revision_id="rev",
        src_entity_id="e1",
        dst_entity_id="e99",
        type=EdgeType.CALLS,
        subtype=CPGEdgeSubtype.CALLS_DIRECT,
        valid_from=1.0,
        observed_at=1.0,
        t_created=1.0,
    )
    # Self loop
    loop = Edge(
        id="loop",
        revision_id="rev",
        src_entity_id="e1",
        dst_entity_id="e1",
        type=EdgeType.CALLS,
        subtype=CPGEdgeSubtype.CALLS_DIRECT,
        valid_from=1.0,
        observed_at=1.0,
        t_created=1.0,
    )
    # Duplicate edge
    loop_dup = Edge(
        id="loop_dup",
        revision_id="rev",
        src_entity_id="e1",
        dst_entity_id="e1",
        type=EdgeType.CALLS,
        subtype=CPGEdgeSubtype.CALLS_DIRECT,
        valid_from=1.0,
        observed_at=1.0,
        t_created=1.0,
    )
    # Unresolved call
    unres = Edge(
        id="unres",
        revision_id="rev",
        src_entity_id="e1",
        dst_entity_id="",
        type=EdgeType.CALLS_UNRESOLVED,
        subtype=None,
        valid_from=1.0,
        observed_at=1.0,
        t_created=1.0,
    )

    report = compute_graph_diagnostics([e1], [dangling, loop, loop_dup, unres])
    assert report.total_entities == 1
    assert report.total_edges == 4
    assert report.dangling_edges == 1
    assert report.missing_targets == ["e99"]
    assert report.self_loops == 2
    assert report.duplicate_edges == 1
    assert report.unresolved_calls == 1
