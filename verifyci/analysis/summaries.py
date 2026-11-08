"""Function summary models for interprocedural contracts and taint."""

from __future__ import annotations


class FunctionSummary:
    def __init__(self, qualified_name: str) -> None:
        self.qualified_name = qualified_name
