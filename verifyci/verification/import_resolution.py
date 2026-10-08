"""Import resolution tripwire (Contract 1 & CAP-005).

Detects when an added line in CODE_CORE introduces an unresolvable external
module import that is neither in the Python standard library, known project
modules, nor declared repository dependencies. Import associations that
cannot be resolved safely (relative imports, unsupported non-Python imports,
or incomplete multiline syntax) are INCONCLUSIVE rather than silently PASS.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import sys
import textwrap
import tomllib

from verifyci.contracts.verification_ir import CheckResult
from verifyci.verification.diffmap import normalize_path, parse_unified_diff
from verifyci.verification.partition import FilePartition, classify_path

# Standard library modules
_STDLIB_MODULES = getattr(sys, "stdlib_module_names", set())

_KNOWN_PACKAGES = {
    "verifyci", "requests", "flask", "click", "app", "src", "core",
    "urllib3", "certifi", "idna", "charset_normalizer", "chardet",
    "jinja2", "werkzeug", "itsdangerous", "markupsafe", "pytest",
    "colorama", "six", "typing_extensions",
}

_PYTHON_EXTENSIONS = {".py", ".pyi"}
_NON_PYTHON_IMPORT_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
}
_IMPORT_MARKER_RE = re.compile(r"\b(?:import|from|require|include)\b")


def _normalize_package_name(name: str) -> str:
    return re.split(r"[<>=!~\[\];\s]", name.strip(), maxsplit=1)[0].lower().replace("-", "_")


def _manifest_packages(repo_root: Path) -> tuple[set[str], list[str]]:
    packages: set[str] = set()
    errors: list[str] = []

    pyproject = repo_root / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            deps = data.get("project", {}).get("dependencies", []) or []
            for dep in deps:
                packages.add(_normalize_package_name(str(dep)))
            for group in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
                for dep in group or []:
                    packages.add(_normalize_package_name(str(dep)))
        except Exception as exc:
            errors.append(f"manifest_parse_error:pyproject.toml:{type(exc).__name__}")

    for req_name in ("requirements.txt", "requirements-dev.txt", "requirements-dev.in"):
        req = repo_root / req_name
        if not req.exists():
            continue
        try:
            for raw in req.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith(("#", "-", "--")):
                    continue
                packages.add(_normalize_package_name(line))
        except OSError as exc:
            errors.append(f"manifest_read_error:{req_name}:{type(exc).__name__}")

    package_json = repo_root / "package.json"
    if package_json.exists():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
            for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                for dep in (data.get(key, {}) or {}):
                    packages.add(_normalize_package_name(dep))
        except Exception as exc:
            errors.append(f"manifest_parse_error:package.json:{type(exc).__name__}")

    cargo = repo_root / "Cargo.toml"
    if cargo.exists():
        try:
            data = tomllib.loads(cargo.read_text(encoding="utf-8"))
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                packages.update(_normalize_package_name(str(name)) for name in (data.get(section, {}) or {}))
        except Exception as exc:
            errors.append(f"manifest_parse_error:Cargo.toml:{type(exc).__name__}")

    return packages, errors


def _local_project_roots(repo_root: Path) -> set[str]:
    roots: set[str] = set()
    for child in repo_root.iterdir() if repo_root.exists() else ():
        if child.name.startswith("."):
            continue
        if child.is_file() and child.suffix in _PYTHON_EXTENSIONS:
            roots.add(child.stem.lower().replace("-", "_"))
        elif child.is_dir() and (child / "__init__.py").exists():
            roots.add(child.name.lower().replace("-", "_"))
    return roots


def _extract_imports_from_block(source: str) -> tuple[list[str], list[str]]:
    roots: list[str] = []
    issues: list[str] = []
    normalized = textwrap.dedent(source)
    try:
        tree = ast.parse(normalized)
    except SyntaxError:
        if _IMPORT_MARKER_RE.search(normalized):
            issues.append("import_parse_inconclusive")
        return roots, issues
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.append(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                issues.append("relative_import_requires_module_context")
            elif node.module:
                roots.append(node.module.split(".")[0])
    return roots, issues


def find_unresolvable_imports(
    diff: str | None, repo_root: str | os.PathLike[str] | None = None
) -> list[str]:
    root = Path(repo_root or os.environ.get("VERIFYCI_REPO_ROOT", os.getcwd())).resolve()
    manifest_packages, manifest_errors = _manifest_packages(root)
    local_roots = _local_project_roots(root)
    known = {
        _normalize_package_name(x)
        for x in _KNOWN_PACKAGES | _STDLIB_MODULES | manifest_packages | local_roots
    }
    out: list[str] = []
    out.extend(manifest_errors)

    for f in parse_unified_diff(diff or ""):
        filepath = normalize_path(f.path)
        if not filepath or classify_path(filepath) != FilePartition.CODE_CORE:
            continue
        ext = Path(filepath).suffix.lower()
        if ext in _NON_PYTHON_IMPORT_EXTENSIONS:
            added = "\n".join(line[1:] for h in f.hunks for line in h.lines if line.startswith("+"))
            if _IMPORT_MARKER_RE.search(added):
                out.append(f"{filepath}: non_python_import_requires_language_resolver")
            continue
        if ext not in _PYTHON_EXTENSIONS:
            continue

        roots: list[str] = []
        for hunk in f.hunks:
            added_block = "\n".join(line[1:] for line in hunk.lines if line.startswith("+"))
            block_roots, block_issues = _extract_imports_from_block(added_block)
            roots.extend(block_roots)
            out.extend(f"{filepath}: {issue}" for issue in block_issues)
        for r in roots:
            key = _normalize_package_name(r)
            if not key:
                continue
            if key in known:
                continue
            out.append(f"{filepath}: {r}: dependency_not_declared_or_local")
    return out


def import_resolution_check(
    diff: str | None, repo_root: str | os.PathLike[str] | None = None
) -> CheckResult:
    unresolvable = find_unresolvable_imports(diff, repo_root=repo_root)
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
    indeterminate_tokens = (
        "relative_import_requires_module_context",
        "non_python_import_requires_language_resolver",
        "import_parse_inconclusive",
        "manifest_parse_error",
        "manifest_read_error",
    )
    indeterminate = any(
        any(token in item for token in indeterminate_tokens)
        for item in unresolvable
    )
    return CheckResult(
        check_id="import_resolution",
        passed=False,
        score=0.0,
        evidence=list(unresolvable),
        explanation=f"import resolution could not be established at {first}{rest}",
        blocking=indeterminate,
        established=not indeterminate,
    )
