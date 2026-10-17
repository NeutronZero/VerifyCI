"""Dangerous dynamic call detection with import alias resolution."""

from __future__ import annotations

import ast
from typing import Mapping, Sequence

from verifyci.contracts.verdict import (
    FindingReason,
    Severity,
    VerificationFinding,
    VerificationVerdict,
)
from verifyci.core.canonical import content_digest_hex

_DANGEROUS_BUILTINS: dict[str, str] = {
    "eval": "executes arbitrary dynamic Python code",
    "exec": "executes arbitrary dynamic Python code",
    "compile": "compiles arbitrary code string at runtime",
    "__import__": "dynamic import bypasses static import policy",
}

_DANGEROUS_ATTRIBUTES: dict[str, tuple[str, str]] = {
    "system": ("os", "executes a shell command via os.system"),
    "popen": ("subprocess", "spawns a subprocess pipeline"),
    "spawn": ("subprocess", "spawns a new process"),
    "call": ("subprocess", "spawns a subprocess and waits"),
    "run": ("subprocess", "spawns a process and runs a command"),
    "check_output": ("subprocess", "spawns a process and captures output"),
    "check_call": ("subprocess", "spawns a process and checks exit code"),
    "loads": ("pickle", "deserializes untrusted object stream"),
    "load": ("pickle", "deserializes untrusted object stream"),
    "unsafe_load": ("yaml", "deserializes arbitrary Python objects from YAML"),
}


class DangerousCallVisitor(ast.NodeVisitor):
    """AST visitor that resolves import aliases and assigned aliases to detect dangerous calls."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.module_aliases: dict[str, str] = {}  # alias -> canonical module name
        self.symbol_aliases: dict[str, tuple[str, str]] = {}  # alias -> (module, canonical attr)
        self.builtin_aliases: dict[str, str] = {}  # alias -> canonical builtin name
        self.findings: list[VerificationFinding] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            base_mod = alias.name.split(".")[0]
            target_name = alias.asname or alias.name
            self.module_aliases[target_name] = base_mod
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        base_mod = module.split(".")[0]
        for alias in node.names:
            if alias.name == "*":
                # Handle star imports: from subprocess import * or from os import *
                for attr, (expected_mod, _) in _DANGEROUS_ATTRIBUTES.items():
                    if expected_mod == base_mod:
                        self.symbol_aliases[attr] = (base_mod, attr)
            else:
                target_name = alias.asname or alias.name
                self.symbol_aliases[target_name] = (base_mod, alias.name)
        self.generic_visit(node)

    def _track_alias_assignment(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Name):
            return
        target_id = target.id

        # 1. Alias assigned to another name (e.g. my_eval = eval or cmd = system)
        if isinstance(value, ast.Name):
            source_id = value.id
            if source_id in _DANGEROUS_BUILTINS:
                self.builtin_aliases[target_id] = source_id
            elif source_id in self.builtin_aliases:
                self.builtin_aliases[target_id] = self.builtin_aliases[source_id]
            elif source_id in self.symbol_aliases:
                self.symbol_aliases[target_id] = self.symbol_aliases[source_id]
            elif source_id in self.module_aliases:
                self.module_aliases[target_id] = self.module_aliases[source_id]

        # 2. Alias assigned to attribute (e.g. cmd = os.system or cmd = my_os.system)
        elif isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
            recv_name = value.value.id
            attr_name = value.attr
            canonical_mod = self.module_aliases.get(recv_name, recv_name)
            if attr_name in _DANGEROUS_ATTRIBUTES:
                expected_mod, _ = _DANGEROUS_ATTRIBUTES[attr_name]
                if canonical_mod == expected_mod:
                    self.symbol_aliases[target_id] = (canonical_mod, attr_name)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._track_alias_assignment(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._track_alias_assignment(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        lineno = getattr(node, "lineno", 1)

        # 1. Direct function call: e.g. eval(...) or my_eval(...) or imported symbol alias run(...)
        if isinstance(func, ast.Name):
            name = func.id
            if name in _DANGEROUS_BUILTINS:
                reason_desc = _DANGEROUS_BUILTINS[name]
                self._record_finding(name, lineno, reason_desc)
            elif name in self.builtin_aliases:
                orig_builtin = self.builtin_aliases[name]
                reason_desc = _DANGEROUS_BUILTINS[orig_builtin]
                self._record_finding(orig_builtin, lineno, reason_desc)
            elif name in self.symbol_aliases:
                mod, attr = self.symbol_aliases[name]
                if attr in _DANGEROUS_ATTRIBUTES and _DANGEROUS_ATTRIBUTES[attr][0] == mod:
                    reason_desc = _DANGEROUS_ATTRIBUTES[attr][1]
                    self._record_finding(f"{mod}.{attr}", lineno, reason_desc)

        # 2. Attribute call: e.g. os.system(...) or my_os.system(...)
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            recv_name = func.value.id
            attr_name = func.attr
            canonical_mod = self.module_aliases.get(recv_name, recv_name)

            if attr_name in _DANGEROUS_ATTRIBUTES:
                expected_mod, reason_desc = _DANGEROUS_ATTRIBUTES[attr_name]
                if canonical_mod == expected_mod:
                    self._record_finding(f"{canonical_mod}.{attr_name}", lineno, reason_desc)

        self.generic_visit(node)

    def _record_finding(self, symbol: str, lineno: int, description: str) -> None:
        finding_id = content_digest_hex(f"dangerous_call:{self.file_path}:{lineno}:{symbol}")[:16]
        self.findings.append(
            VerificationFinding(
                finding_id=finding_id,
                rule_id="VC-SECURITY-DANGEROUS-CALL",
                severity=Severity.HIGH,
                verdict=VerificationVerdict.FAIL,
                reason=FindingReason.DANGEROUS_CALL,
                message=f"Invocation of dangerous primitive '{symbol}' at line {lineno}: {description}",
                file_path=self.file_path,
                start_line=lineno,
                end_line=lineno,
                details={"symbol": symbol, "description": description},
            )
        )


def is_test_path(file_path: str) -> bool:
    """Determine whether file path represents a test or fixture."""
    norm = file_path.replace("\\", "/").lower()
    return (
        norm.startswith("tests/")
        or "/tests/" in norm
        or norm.startswith("test/")
        or "/test/" in norm
        or "/fixtures/" in norm
        or norm.endswith("_test.py")
        or norm.split("/")[-1].startswith("test_")
    )


def scan_dangerous_calls(
    file_path: str,
    source: str,
    exclude_tests: bool = True,
) -> list[VerificationFinding]:
    """Scan Python source for forbidden dangerous dynamic execution calls."""
    if exclude_tests and is_test_path(file_path):
        return []

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return []

    visitor = DangerousCallVisitor(file_path)
    visitor.visit(tree)
    return visitor.findings
