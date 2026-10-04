"""Contract schema validation utilities.

Combines Pydantic TypeAdapter boundary validation with deep contract invariant
checks for Entity, Edge, and EvidencePack instances.
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import TypeAdapter

from verifyci.contracts.edge import CPGEdgeSubtype, Edge, EdgeType
from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.event import Event
from verifyci.contracts.evidence import EvidencePack
from verifyci.contracts.jsonio import to_json_dict
from verifyci.contracts.revision import Revision
from verifyci.contracts.verification_ir import VerificationDecision, VerificationReport

_ADAPTERS = {
    Entity: TypeAdapter(Entity),
    Edge: TypeAdapter(Edge),
    Event: TypeAdapter(Event),
    Revision: TypeAdapter(Revision),
    VerificationReport: TypeAdapter(VerificationReport),
    VerificationDecision: TypeAdapter(VerificationDecision),
}


def validate(obj: Any) -> bool:
    """Validate a contract instance against its pydantic adapter."""
    adapter = _ADAPTERS.get(type(obj))
    if adapter is None:
        raise TypeError(f"no_validator:{type(obj).__name__}")
    adapter.validate_python(to_json_dict(obj))
    return True


_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_hex64(val: str) -> bool:
    return bool(val and len(val) == 64 and _HEX64_RE.match(val))


def validate_entity(entity: Entity) -> list[str]:
    """Validate an Entity instance, returning a list of contract violation messages."""
    errors: list[str] = []

    if not entity.repository_id:
        errors.append("entity.repository_id must be non-empty")

    if not _is_hex64(entity.logical_entity_id):
        errors.append(f"entity.logical_entity_id must be 64-char lowercase hex, got '{entity.logical_entity_id}'")

    if not _is_hex64(entity.revision_entity_id):
        errors.append(f"entity.revision_entity_id must be 64-char lowercase hex, got '{entity.revision_entity_id}'")

    if not isinstance(entity.type, EntityType):
        errors.append(f"entity.type must be an EntityType enum, got '{type(entity.type).__name__}'")

    if not entity.name:
        errors.append("entity.name must be non-empty")

    if "\\" in entity.file_path:
        errors.append(f"entity.file_path must be POSIX normalized (no backslashes), got '{entity.file_path}'")

    if entity.line_start is not None and entity.line_end is not None:
        if entity.line_start < 1:
            errors.append(f"entity.line_start must be >= 1, got {entity.line_start}")
        if entity.line_end < entity.line_start:
            errors.append(f"entity.line_end ({entity.line_end}) cannot be less than line_start ({entity.line_start})")

    if entity.valid_from is not None and entity.valid_until is not None:
        if entity.valid_until <= entity.valid_from:
            errors.append(f"entity.valid_until ({entity.valid_until}) must be > valid_from ({entity.valid_from})")

    return errors


def validate_edge(edge: Edge) -> list[str]:
    """Validate an Edge instance, returning a list of contract violation messages."""
    errors: list[str] = []

    if not edge.id:
        errors.append("edge.id must be non-empty")

    if not edge.src_entity_id:
        errors.append("edge.src_entity_id must be non-empty")

    if not isinstance(edge.type, EdgeType):
        errors.append(f"edge.type must be an EdgeType enum, got '{type(edge.type).__name__}'")

    if edge.subtype is not None and not isinstance(edge.subtype, CPGEdgeSubtype):
        errors.append(f"edge.subtype must be None or a CPGEdgeSubtype enum, got '{type(edge.subtype).__name__}'")

    # Unresolved edges have empty dst_entity_id by design
    is_unresolved = edge.type in (EdgeType.CALLS_UNRESOLVED, EdgeType.INHERITS_UNRESOLVED)
    if is_unresolved:
        if edge.dst_entity_id != "":
            errors.append(f"unresolved edge must have empty dst_entity_id, got '{edge.dst_entity_id}'")
    else:
        if not edge.dst_entity_id:
            errors.append("resolved edge.dst_entity_id must be non-empty")
        elif edge.src_entity_id == edge.dst_entity_id:
            if edge.subtype != CPGEdgeSubtype.CALLS_RECURSIVE:
                errors.append(f"self-loop edge {edge.id} forbidden unless subtype is CALLS_RECURSIVE")

    return errors


def validate_evidence_pack(pack: EvidencePack) -> list[str]:
    """Validate an EvidencePack instance."""
    errors: list[str] = []
    if not pack.query:
        errors.append("evidence_pack.query must be non-empty")
    for i, ent in enumerate(pack.entities):
        e_errs = validate_entity(ent)
        errors.extend(f"entities[{i}]: {err}" for err in e_errs)
    for i, chunk in enumerate(pack.source_chunks):
        if "\\" in chunk.file_path:
            errors.append(f"source_chunks[{i}].file_path must be POSIX normalized, got '{chunk.file_path}'")
        if chunk.line_start < 1 or chunk.line_end < chunk.line_start:
            errors.append(f"source_chunks[{i}] invalid span {chunk.line_start}..{chunk.line_end}")
    return errors


def validate_graph_contracts(entities: list[Entity], edges: list[Edge]) -> tuple[bool, list[str]]:
    """Validate a collection of entities and edges, returning (is_valid, errors)."""
    errors: list[str] = []
    for i, e in enumerate(entities):
        e_errs = validate_entity(e)
        errors.extend(f"entity[{i}:{e.name}]: {err}" for err in e_errs)
    for i, edge in enumerate(edges):
        ed_errs = validate_edge(edge)
        errors.extend(f"edge[{i}:{edge.id}]: {err}" for err in ed_errs)
    return len(errors) == 0, errors
