import json

from verifyci.contracts.edge import Edge, EdgeType
from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.event import Event
from verifyci.contracts.jsonio import edge_from_json, entity_from_json, event_from_json, to_json
from verifyci.contracts.validate import validate


def _entity():
    return Entity(
        repository_id="r", logical_entity_id="l", revision_entity_id="rv",
        type=EntityType.FUNCTION, name="f", file_path="a.py",
        line_start=1, line_end=2, language="python", source_hash="h", revision_id="rev",
    )


def test_json_serializes_enums():
    s = to_json(_entity())
    assert json.loads(s)["type"] == "FUNCTION"


def test_entity_round_trip():
    assert entity_from_json(json.loads(to_json(_entity()))) == _entity()


def test_edge_round_trip():
    edge = Edge(id="e", revision_id="rev", src_entity_id="a", dst_entity_id="b",
                type=EdgeType.CALLS, observed_at=0.0)
    assert edge_from_json(json.loads(to_json(edge))) == edge


def test_event_round_trip():
    event = Event(id="e1", type="T", timestamp=1.0, payload={"k": "v"}, provenance={})
    assert event_from_json(json.loads(to_json(event))) == event


def test_pydantic_validation_passes():
    assert validate(_entity()) is True
    assert validate(Event(id="e1", type="T", timestamp=1.0)) is True
