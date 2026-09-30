from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SymbolDefinition:
    name: str
    file_path: str
    line_start: int
    line_end: int
    revision_entity_id: str = ""


@dataclass(frozen=True)
class SymbolReference:
    name: str
    file_path: str
    line_start: int
    revision_entity_id: str = ""


class CodeIntelProvider(ABC):
    @abstractmethod
    def definition(self, symbol: str) -> Optional[SymbolDefinition]: ...

    @abstractmethod
    def references(self, symbol: str) -> list[SymbolReference]: ...
