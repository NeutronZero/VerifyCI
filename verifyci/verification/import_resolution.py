"""Import resolution tripwire (Contract 1 & CAP-005).

Detects when an added line in CODE_CORE introduces an unresolvable external
module import that is neither in the Python standard library, known project
modules, nor declared repository dependencies.
Escalates to HUMAN_REVIEW (non-blocking, established), never silent PASS.
"""
from __future__ import annotations

import ast
import sys

from verifyci.contracts.verification_ir import CheckResult
from verifyci.verification.diffmap import iter_added_lines
from verifyci.verification.partition import FilePartition, classify_path

# Standard library modules
_STDLIB_MODULES = getattr(sys, "stdlib_module_names", set())

_KNOWN_PACKAGES = {
    "verifyci", "requests", "flask", "click", "app", "src", "core",
    "urllib3", "certifi", "idna", "charset_normalizer", "chardet",
    "jinja2", "werkzeug", "itsdangerous", "markupsafe", "pytest",
    "colorama", "six", "typing_extensions",
}


def _extract_imported_roots(line: str) -> list[str]:
    s = line.strip()
    if not (s.startswith("import ") or s.startswith("from ")):
        return []
    try:
        tree = ast.parse(s)
    except SyntaxError:
        return []
    roots = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.append(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                # relative import
                continue
            if node.module:
                roots.append(node.module.split(".")[0])
    return roots


def find_unresolvable_imports(diff: str | None) -> list[str]:
    out: list[str] = []
    for filepath, line in iter_added_lines(diff or ""):
        if not filepath or classify_path(filepath) != FilePartition.CODE_CORE:
            continue
        roots = _extract_imported_roots(line)
        for r in roots:
            if not r:
                continue
            if r in _STDLIB_MODULES or r in _KNOWN_PACKAGES:
                continue
            out.append(f"{filepath}: {r}")
    return out


def import_resolution_check(diff: str | None) -> CheckResult:
    unresolvable = find_unresolvable_imports(diff)
    if not unresolvable:
        return CheckResult(
            check_id="import_resolution",
            passed=True,
            score=1.0,
            evidence=[],
            explanation="all imported modules resolvable",
            blocking=False,
        )
    first = unresolvable[0]
    rest = f" +{len(unresolvable) - 1} more" if len(unresolvable) > 1 else ""
    return CheckResult(
        check_id="import_resolution",
        passed=False,
        score=0.0,
        evidence=list(unresolvable),
        explanation=f"unresolvable external import at {first}{rest}; dependency contract unverified",
        blocking=False,
    )
