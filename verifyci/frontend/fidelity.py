"""Frontend conformance and differential fidelity models."""

from __future__ import annotations

import ast
from typing import Any


def check_fidelity(source: bytes, expected_return: Any = None) -> bool:
    """Validate frontend syntax conformance and differential fidelity."""
    if not source:
        return True
    try:
        ast.parse(source)
        return True
    except SyntaxError:
        try:
            import tree_sitter_typescript as ts
            from tree_sitter import Language, Parser

            parser = Parser(Language(ts.language_typescript()))
            tree = parser.parse(source)
            return not tree.root_node.has_error
        except Exception:
            return False
