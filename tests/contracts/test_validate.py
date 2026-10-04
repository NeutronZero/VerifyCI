import pytest

from verifyci.contracts.edge import CPGEdgeSubtype, Edge, EdgeType
from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.evidence import EvidencePack, SourceChunk
from verifyci.contracts.validate import (
    validate_edge,
    validate_entity,
    validate_evidence_pack,
    validate_graph_contracts,
)


def _make_valid_entity():
    return Entity(
        repository_id="repo",
        logical_entity_id="a" * 64,
        revision_entity_id="b" * 64,
        type=EntityType.FUNCTION,
        name="calc",
        file_path="src/calc.py",
        line_start=10,
        line_end=20,
        language="python",
        source_hash="c" * 64,
        revision_id="rev",
    )


def test_validate_entity_success():
    ent = _make_valid_entity()
    errors = validate_entity(ent)
    assert errors == []


def test_validate_entity_violations():
    # Inverted lines, bad hex, Windows path
    ent = Entity(
        repository_id="",
        logical_entity_id="short_hex",
        revision_entity_id="bad",
        type=EntityType.FUNCTION,
        name="",
        file_path="src\\calc.py",
        line_start=25,
        line_end=10,
        language="python",
        source_hash="c" * 64,
        revision_id="rev",
    )
    errors = validate_entity(ent)
    assert len(errors) >= 5
    assert any("repository_id" in e for e in errors)
    assert any("64-char lowercase hex" in e for e in errors)
    assert any("cannot be less than line_start" in e for e in errors)
    assert any("POSIX normalized" in e for e in errors)


def test_validate_edge_success():
    edge = Edge(
        id="edge_1",
        revision_id="rev",
        src_entity_id="a" * 64,
        dst_entity_id="b" * 64,
        type=EdgeType.CALLS,
        subtype=CPGEdgeSubtype.CALLS_DIRECT,
        valid_from=100.0,
        observed_at=100.0,
        t_created=100.0,
    )
    assert validate_edge(edge) == []


def test_validate_edge_illegal_self_loop():
    edge = Edge(
        id="edge_loop",
        revision_id="rev",
        src_entity_id="a" * 64,
        dst_entity_id="a" * 64,  # Self-loop!
        type=EdgeType.CALLS,
        subtype=CPGEdgeSubtype.CALLS_DIRECT,  # Not CALLS_RECURSIVE
        valid_from=100.0,
        observed_at=100.0,
        t_created=100.0,
    )
    errors = validate_edge(edge)
    assert len(errors) == 1
    assert "self-loop edge edge_loop forbidden" in errors[0]


def test_validate_graph_contracts():
    e1 = _make_valid_entity()
    ed1 = Edge(
        id="e1",
        revision_id="rev",
        src_entity_id="a" * 64,
        dst_entity_id="b" * 64,
        type=EdgeType.CALLS,
        subtype=CPGEdgeSubtype.CALLS_DIRECT,
        valid_from=1.0,
        observed_at=1.0,
        t_created=1.0,
    )
    ok, errs = validate_graph_contracts([e1], [ed1])
    assert ok is True
    assert errs == []
