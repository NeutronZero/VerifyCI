"""Frontend protocols and interfaces for language lowering."""

from __future__ import annotations

from typing import Protocol
from verifyci.contracts.model import Entity
from verifyci.frontend.vfir import FunctionVFIR


class LanguageFrontendProtocol(Protocol):
    language_id: str
    version: str

    def extract_entities(self, source: bytes, path: str) -> list[Entity]: ...
    def lower(self, source: bytes, path: str, entity_name: str) -> FunctionVFIR: ...
