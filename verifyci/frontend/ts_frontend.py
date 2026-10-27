"""TypeScript frontend CST lowering to VFIR."""

from __future__ import annotations

from verifyci.contracts.model import Entity
from verifyci.frontend.vfir import Capability, EntityStatus, FunctionVFIR, BasicBlock
from verifyci.scope.entities import extract_entities


class TypeScriptFrontend:
    language_id = "typescript"
    version = "tree-sitter-0.23"

    def extract_entities(self, source: bytes, path: str) -> list[Entity]:
        return list(extract_entities(source, path))

    def lower(self, source: bytes, path: str, entity_name: str) -> FunctionVFIR:
        return FunctionVFIR(
            qualified_name=entity_name,
            status=EntityStatus.LOWERED,
            parameters=(),
            blocks=(BasicBlock(block_id="entry", instructions=(), predecessors=(), successors=()),),
            capabilities=(Capability.ENTITY_SPANS, Capability.SIGNATURE),
            reason_codes=(),
        )
