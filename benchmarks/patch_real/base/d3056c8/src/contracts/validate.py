"""Pydantic validation for frozen contracts.

Dataclasses are the source of truth; these validators assert that payloads
crossing process boundaries (DB rows, MCP I/O, HTTP) still satisfy the
contracts. Uses pydantic TypeAdapters over the frozen dataclasses so the
schemas cannot drift from the code.
"""
from pydantic import TypeAdapter

from src.contracts.edge import Edge
from src.contracts.entity import Entity
from src.contracts.event import Event
from src.contracts.jsonio import to_json_dict
from src.contracts.revision import Revision
from src.contracts.verification_ir import VerificationDecision, VerificationReport

_ADAPTERS = {
    Entity: TypeAdapter(Entity),
    Edge: TypeAdapter(Edge),
    Event: TypeAdapter(Event),
    Revision: TypeAdapter(Revision),
    VerificationReport: TypeAdapter(VerificationReport),
    VerificationDecision: TypeAdapter(VerificationDecision),
}


def validate(obj) -> bool:
    """Validate a contract instance against its pydantic adapter."""
    adapter = _ADAPTERS.get(type(obj))
    if adapter is None:
        raise TypeError(f"no_validator:{type(obj).__name__}")
    adapter.validate_python(to_json_dict(obj))
    return True
