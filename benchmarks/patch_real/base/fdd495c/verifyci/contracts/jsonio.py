"""JSON serialization for frozen contracts.

``to_json_dict`` handles dataclasses + Enums (the stdlib ``asdict`` leaves
Enum members, which ``json.dumps`` rejects). ``entity_from_json`` and
friends round-trip the core code-intelligence types.
"""
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any


def to_json_dict(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj):
        return {k: to_json_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: to_json_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_json_dict(v) for v in obj]
    return obj


def to_json(obj: Any) -> str:
    return json.dumps(to_json_dict(obj), sort_keys=True, ensure_ascii=False, allow_nan=False)


def _enum(enum_cls, value):
    return enum_cls(value) if not isinstance(value, enum_cls) else value


def entity_from_json(data: dict) -> Any:
    from verifyci.contracts.entity import Entity, EntityType
    d = dict(data)
    d["type"] = _enum(EntityType, d["type"])
    return Entity(**{k: v for k, v in d.items() if k in Entity.__dataclass_fields__})


def edge_from_json(data: dict) -> Any:
    from verifyci.contracts.edge import Edge, EdgeType, CPGEdgeSubtype
    d = dict(data)
    d["type"] = _enum(EdgeType, d["type"])
    if d.get("subtype") is not None:
        d["subtype"] = _enum(CPGEdgeSubtype, d["subtype"])
    return Edge(**{k: v for k, v in d.items() if k in Edge.__dataclass_fields__})


def event_from_json(data: dict) -> Any:
    from verifyci.contracts.event import AttestationMetadata, Event
    d = dict(data)
    if d.get("attestation") is not None:
        d["attestation"] = AttestationMetadata(**d["attestation"])
    return Event(**{k: v for k, v in d.items() if k in Event.__dataclass_fields__})
