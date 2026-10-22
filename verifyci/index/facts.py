"""Fact representations and symbol models for VerifyCI v3.1."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FileFacts:
    path: str
    definitions: tuple[dict[str, Any], ...]
    imports: tuple[dict[str, Any], ...]
    exports: tuple[str, ...]
    call_sites: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "definitions": list(self.definitions),
            "imports": list(self.imports),
            "exports": list(self.exports),
            "call_sites": list(self.call_sites),
        }
