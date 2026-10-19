"""Dangerous-call detection for added code.

Equivalence of return values says nothing about safety: a patch that leaves the
return expression untouched while calling `eval` on request input is
return-equivalent and still a defect. This checker is independent of the
symbolic prover so that a proven-equivalent diff cannot suppress it.
"""

from __future__ import annotations

import ast

from verifyci_v2.contracts.attestation import VerificationFinding
from verifyci_v2.contracts.canonical import content_digest_hex

# Builtins whose mere invocation is a finding: the argument is data, not code.
_DANGEROUS_BUILTINS: dict[str, str] = {
    "eval": "executes arbitrary Python",
    "exec": "executes arbitrary Python",
    "compile": "compiles arbitrary source at runtime",
    "__import__": "dynamic import bypasses import policy",
}

# `module.attr` spellings that execute a command or deserialise untrusted data.
_DANGEROUS_ATTRIBUTES: dict[str, tuple[str, str]] = {
    "system": ("os", "runs a shell command"),
    "popen": ("subprocess", "spawns a process"),
    "spawn": ("subprocess", "spawns a process"),
    "call": ("subprocess", "spawns a process"),
    "run": ("subprocess", "spawns a process and runs a command"),
    "check_output": ("subprocess", "spawns a process and captures output"),
    "check_call": ("subprocess", "spawns a process and checks exit code"),
    "posix_spawn": ("os", "spawns a process via posix_spawn"),
    "posix_spawnp": ("os", "spawns a process via posix_spawnp"),
    "execl": ("os", "replaces current process with new executable"),
    "execle": ("os", "replaces current process with new executable"),
    "execlp": ("os", "replaces current process with new executable"),
    "execlpe": ("os", "replaces current process with new executable"),
    "execv": ("os", "replaces current process with new executable"),
    "execve": ("os", "replaces current process with new executable"),
    "execvp": ("os", "replaces current process with new executable"),
    "execvpe": ("os", "replaces current process with new executable"),
}

_DANGEROUS_NAMES: dict[str, tuple[str, str]] = {
    "loads": ("pickle", "deserialises untrusted data"),
    "load": ("pickle", "deserialises untrusted data"),
    "unsafe_load": ("yaml", "constructs arbitrary Python objects"),
    "system": ("os", "runs a shell command"),
}


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


# Modules whose import grants code-execution or unsafe-deserialisation capability.
# Inherited from the frozen cap002_heldout policy (case N-W2).
_DANGEROUS_IMPORTS: dict[str, str] = {
    "subprocess": "grants process and shell execution",
    "ctypes": "grants raw foreign-function and memory access",
    "marshal": "deserialises arbitrary code objects",
    "pickle": "deserialises untrusted data",
    "shelve": "deserialises untrusted data",
    "pty": "grants pseudo-terminal process control",
}


def scan_dangerous_calls(
    file_path: str, source: str, *, preparsed_tree: ast.Module | None = None
) -> tuple[VerificationFinding, ...]:
    """Reports dangerous-call usage, reusing a pipeline-owned AST when supplied."""
    if preparsed_tree is not None:
        tree = preparsed_tree
    else:
        try:
            tree = ast.parse(source, filename=file_path)
        except (SyntaxError, ValueError, IndentationError):
            return ()

    findings: list[VerificationFinding] = []
    seen: set[tuple[int, str]] = set()

    # Track import aliases, e.g. `import subprocess as sub` or `from subprocess import run as r`
    module_aliases: dict[str, str] = {}  # local_alias -> base_module
    symbol_aliases: dict[str, tuple[str, str]] = {}  # local_alias -> (base_module, original_attr)

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split(".")[0]
                    modules.append(root_mod)
                    local_name = alias.asname or alias.name
                    module_aliases[local_name] = root_mod
            elif node.module:
                root_mod = node.module.split(".")[0]
                modules = [root_mod]
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    symbol_aliases[local_name] = (root_mod, alias.name)
            for module in modules:
                reason = _DANGEROUS_IMPORTS.get(module)
                if reason is None:
                    continue
                key = (node.lineno, module)
                if key in seen:
                    continue
                seen.add(key)
                fid = content_digest_hex(
                    f"DANGEROUS_IMPORT:{file_path}:{node.lineno}:{module}",
                    domain="verifyci.v2.finding",
                )[:16]
                findings.append(
                    VerificationFinding(
                        finding_id=fid,
                        rule_id="VC2-DANGEROUS-IMPORT",
                        severity="MEDIUM",
                        verdict="FAIL",
                        file_path=file_path,
                        start_line=node.lineno,
                        end_line=node.lineno,
                        message=(
                            f"Dangerous import '{module}' on line {node.lineno}: "
                            f"{reason}."
                        ),
                    )
                )
            continue

        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name is None:
            continue

        reason: str | None = None
        if isinstance(node.func, ast.Name):
            reason = _DANGEROUS_BUILTINS.get(name)
            if reason is None and name in symbol_aliases:
                base_mod, orig_attr = symbol_aliases[name]
                attr_spec = _DANGEROUS_ATTRIBUTES.get(orig_attr)
                if attr_spec and attr_spec[0] == base_mod:
                    reason = attr_spec[1]
                elif (name_spec := _DANGEROUS_NAMES.get(orig_attr)) and name_spec[0] == base_mod:
                    reason = name_spec[1]
        elif isinstance(node.func, ast.Attribute):
            attr_spec = _DANGEROUS_ATTRIBUTES.get(name)
            if attr_spec and _has_module_ref(node.func.value, attr_spec[0], module_aliases):
                reason = attr_spec[1]
            elif (name_spec := _DANGEROUS_NAMES.get(name)) and _has_module_ref(node.func.value, name_spec[0], module_aliases):
                reason = name_spec[1]

        if reason is None:
            continue

        key = (node.lineno, name)
        if key in seen:
            continue
        seen.add(key)
        fid = content_digest_hex(
            f"DANGEROUS:{file_path}:{node.lineno}:{name}",
            domain="verifyci.v2.finding",
        )[:16]
        findings.append(
            VerificationFinding(
                finding_id=fid,
                rule_id="VC2-DANGEROUS-CALL",
                severity="CRITICAL",
                verdict="FAIL",
                file_path=file_path,
                start_line=node.lineno,
                end_line=node.lineno,
                message=f"Dangerous call '{name}' on line {node.lineno}: {reason}.",
            )
        )
    return tuple(findings)


def _has_module_ref(
    node: ast.AST, module: str, module_aliases: dict[str, str] | None = None
) -> bool:
    """Matches `os.system`, `subprocess.run`, `sub.run`, and `from os import system` forms."""
    if isinstance(node, ast.Name):
        if node.id == module:
            return True
        if module_aliases and module_aliases.get(node.id) == module:
            return True
    if isinstance(node, ast.Attribute):
        if node.attr == module:
            return True
    return False