from src.contracts.code_intel import CodeIntelProvider, SymbolDefinition, SymbolReference
from typing import Optional


class StoreCodeIntelProvider(CodeIntelProvider):
    def __init__(self, store) -> None:
        self._store = store

    def definition(self, symbol: str) -> Optional[SymbolDefinition]:
        entity = self._store.get_entity_by_logical(symbol)
        if entity is None and hasattr(self._store, "get_entity_by_name"):
            entity = self._store.get_entity_by_name(symbol)
        if entity is None:
            return None
        return SymbolDefinition(
            name=entity.name, file_path=entity.file_path,
            line_start=entity.line_start, line_end=entity.line_end,
            revision_entity_id=entity.revision_entity_id,
        )

    def references(self, symbol: str) -> list[SymbolReference]:
        return []
