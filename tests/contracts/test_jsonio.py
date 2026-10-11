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


def test_frozen_dataclass_with_mappingproxy_serializes():
    from types import MappingProxyType
    from verifyci.contracts.jsonio import to_json_dict

    # Construct entity with deeply nested MappingProxyType metadata
    nested_meta = MappingProxyType({
        "role": "auth",
        "limits": MappingProxyType({"rate": 100, "timeout": 30}),
        "tags": ("security", "audit"),
    })
    entity = _entity()
    frozen_entity = Entity(
        repository_id=entity.repository_id,
        logical_entity_id=entity.logical_entity_id,
        revision_entity_id=entity.revision_entity_id,
        type=entity.type,
        name=entity.name,
        file_path=entity.file_path,
        line_start=entity.line_start,
        line_end=entity.line_end,
        language=entity.language,
        source_hash=entity.source_hash,
        revision_id=entity.revision_id,
        metadata=nested_meta,
    )

    # to_json_dict should not raise TypeError: cannot pickle 'mappingproxy' object
    data = to_json_dict(frozen_entity)
    assert isinstance(data, dict)
    assert data["metadata"]["role"] == "auth"
    assert data["metadata"]["limits"]["rate"] == 100
    assert data["metadata"]["tags"] == ["security", "audit"]

    # to_json should succeed and produce valid parseable JSON
    json_str = to_json(frozen_entity)
    parsed = json.loads(json_str)
    assert parsed["metadata"]["role"] == "auth"
    assert parsed["metadata"]["limits"]["timeout"] == 30

