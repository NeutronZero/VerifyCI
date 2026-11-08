"""Control-flow graph construction and dominance frontiers."""

from __future__ import annotations

from typing import Any


class CFG:
    def __init__(self, blocks: list[dict[str, Any]]) -> None:
        self.blocks = blocks
