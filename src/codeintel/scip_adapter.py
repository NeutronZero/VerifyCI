from src.codeintel import StoreCodeIntelProvider

__all__ = ["StoreCodeIntelProvider"]


class ScipAdapter(StoreCodeIntelProvider):
    """SCIP index backed provider. V1: delegates to the SQLite store."""
