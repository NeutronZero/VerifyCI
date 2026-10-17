"""Dependency and import resolution analysis."""

from __future__ import annotations

import ast
import sys
from typing import Sequence

from verifyci.contracts.verdict import (
    FindingReason,
    Severity,
    VerificationFinding,
    VerificationVerdict,
)
from verifyci.core.canonical import content_digest_hex


def find_unresolvable_imports(added_lines: Sequence[str]) -> list[str]:
    """Identify top-level imported packages that cannot be resolved in current environment."""
    modules: set[str] = set()

    for line in added_lines:
        text = line.strip()
        if not (text.startswith("import ") or text.startswith("from ")):
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue  # relative in-repo import
                if node.module:
                    modules.add(node.module.split(".")[0])

    import importlib.util

    unresolved: list[str] = []
    for mod in sorted(modules):
        if not mod or mod in sys.stdlib_module_names:
            continue
        try:
            found = importlib.util.find_spec(mod) is not None
        except (ImportError, ValueError):
            found = False

        if not found:
            unresolved.append(mod)

    return unresolved


def check_unresolved_imports(
    file_path: str,
    added_lines: Sequence[str],
    is_blocking: bool = False,
) -> list[VerificationFinding]:
    """Check for unresolvable external dependencies.

    Only produces INCONCLUSIVE when the unresolved import blocks a required
    semantic check.
    """
    if not is_blocking:
        return []

    findings: list[VerificationFinding] = []
    unresolved = find_unresolvable_imports(added_lines)

    for mod in unresolved:
        finding_id = content_digest_hex(f"unresolved_import:{file_path}:{mod}")[:16]
        findings.append(
            VerificationFinding(
                finding_id=finding_id,
                rule_id="VC-DEPENDENCY-UNRESOLVED-IMPORT",
                severity=Severity.MEDIUM,
                verdict=VerificationVerdict.INCONCLUSIVE,
                reason=FindingReason.UNRESOLVED_IMPORT,
                message=(
                    f"Patch adds an import of '{mod}', which is unresolvable in this environment "
                    "and blocks required semantic analysis; failing closed."
                ),
                file_path=file_path,
                details={"unresolved_module": mod},
            )
        )

    return findings
