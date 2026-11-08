"""Static Single Assignment (SSA) construction and def-use chains."""

from __future__ import annotations


class SSAForm:
    def __init__(self) -> None:
        self.variables: dict[str, list[str]] = {}
