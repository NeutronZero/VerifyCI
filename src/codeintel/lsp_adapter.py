from src.codeintel import StoreCodeIntelProvider

__all__ = ["LspAdapter"]


class LspAdapter(StoreCodeIntelProvider):
    """LSP backed provider. V1: delegates to the SQLite store."""
