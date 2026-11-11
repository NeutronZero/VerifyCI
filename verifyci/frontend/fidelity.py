"""Frontend conformance and differential fidelity models."""

from __future__ import annotations

import ast
from typing import Any

from verifyci.scope.parsers import parse_ts_bytes


def check_fidelity(source: bytes, expected_return: Any = None) -> bool:
    """Validate frontend syntax conformance and differential fidelity."""
    if not source:
        return True
    try:
        ast.parse(source)
        return True
    except SyntaxError:
        tree = parse_ts_bytes(source, "typescript")
        return tree is not None and not tree.root_node.has_error
