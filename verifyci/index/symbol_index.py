"""Lightweight symbol index and reverse lookups over Git-derived facts."""

from __future__ import annotations

from typing import Any


class SymbolIndex:
    def __init__(self) -> None:
        self.definitions: dict[str, dict[str, Any]] = {}
        self.callers: dict[str, list[dict[str, Any]]] = {}
        self.imports: dict[str, list[str]] = {}

    def add_file_facts(self, facts: dict[str, Any]) -> None:
        path = facts.get("path", "")
        for defn in facts.get("definitions", []):
            qname = defn.get("qname", "")
            if qname:
                self.definitions[qname] = defn

        for call in facts.get("call_sites", []):
            callee = call.get("callee", "")
            if callee:
                self.callers.setdefault(callee, []).append({**call, "caller_file": path})

    def find_callers(self, target_symbol: str) -> list[dict[str, Any]]:
        return self.callers.get(target_symbol, [])
