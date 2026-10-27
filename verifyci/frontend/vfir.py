"""Verified Function Intermediate Representation (VFIR) models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class EntityStatus(str, Enum):
    LOWERED = "LOWERED"
    PARTIAL = "PARTIAL"
    OPAQUE = "OPAQUE"


class Capability(str, Enum):
    ENTITY_SPANS = "entity_spans"
    SIGNATURE = "signature"
    CFG = "cfg"
    SSA = "ssa"
    CALLS = "calls"
    EFFECTS = "effects"
    EXCEPTIONS = "exceptions"
    TYPES = "types"
    TAINT = "taint"
    SYMBOLS = "symbols"
    REFERENCES = "references"


@dataclass(frozen=True)
class BasicBlock:
    block_id: str
    instructions: tuple[dict[str, Any], ...]
    predecessors: tuple[str, ...]
    successors: tuple[str, ...]


@dataclass(frozen=True)
class FunctionVFIR:
    qualified_name: str
    status: EntityStatus
    parameters: tuple[str, ...]
    blocks: tuple[BasicBlock, ...]
    capabilities: tuple[Capability, ...]
    reason_codes: tuple[str, ...] = ()
