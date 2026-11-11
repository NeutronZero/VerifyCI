"""Shared module path normalization and relative import resolution for checks."""

from __future__ import annotations

import posixpath

from verifyci.scope.parsers import SUPPORTED_CODE_WITH_PYI_EXTENSIONS

_NORMALIZED_SUFFIXES = tuple(f".{ext}" for ext in sorted(SUPPORTED_CODE_WITH_PYI_EXTENSIONS))


def strip_code_suffix(path: str) -> str:
    for suffix in _NORMALIZED_SUFFIXES:
        if path.endswith(suffix):
            return path[: -len(suffix)]
    return path


def normalize_module_path(path: str, *, strip_index: bool = False) -> str:
    """Normalize a repository path or dotted module specifier to slash-separated form."""
    p = (path or "").replace("\\", "/").strip()
    p = strip_code_suffix(p)
    if strip_index and p.endswith("/index"):
        p = p[: -len("/index")]
    elif p.endswith("/__init__"):
        p = p[: -len("/__init__")]
    elif p.endswith(".__init__"):
        p = p[: -len(".__init__")]
    return p.replace(".", "/") if not strip_index else p


def python_module_name(path: str) -> str:
    """Return dotted Python module name, stripping trailing ``.__init__``."""
    mod = path.rsplit(".", 1)[0].replace("/", ".").replace("\\", ".")
    if mod.endswith(".__init__"):
        mod = mod[: -len(".__init__")]
    return mod


def resolve_python_relative_import(
    imp_module: str,
    importing_path: str,
    level: int = 0,
) -> tuple[list[str], str]:
    """Resolve Python package segments and remainder for a relative import."""
    imp_module = (imp_module or "").strip()
    if imp_module.startswith("."):
        dots = len(imp_module) - len(imp_module.lstrip("."))
        level = level or dots
        imp_module = imp_module.lstrip(".")
    base_mod = normalize_module_path(importing_path)
    parts = base_mod.split("/") if base_mod else []
    if not importing_path.endswith("__init__.py") and parts:
        parts = parts[:-1]
    if level > 1:
        if level - 1 >= len(parts):
            parts = []
        else:
            parts = parts[: len(parts) - (level - 1)]
    return parts, imp_module


def resolve_import_module(imp_module: str, importing_path: str, level: int = 0) -> str:
    """Resolve an import specifier to a slash-separated module path."""
    importing_dir = posixpath.dirname(importing_path.replace("\\", "/"))
    imp_module = (imp_module or "").strip()
    if imp_module.startswith("./") or imp_module.startswith("../"):
        joined = posixpath.normpath(posixpath.join(importing_dir, imp_module))
        return normalize_module_path(joined)
    if imp_module.startswith(".") or level > 0:
        parts, rel_mod = resolve_python_relative_import(imp_module, importing_path, level)
        pkg = "/".join(parts)
        if rel_mod:
            rel = rel_mod.replace(".", "/")
            return f"{pkg}/{rel}" if pkg else rel
        return pkg
    return normalize_module_path(imp_module)


def resolve_dotted_module(imp_module: str, importing_path: str, level: int = 0) -> str | None:
    """Resolve a Python import specifier to a dotted module name."""
    imp_module = (imp_module or "").strip()
    if imp_module.startswith("."):
        if not importing_path.endswith(".py"):
            return None
        dots = len(imp_module) - len(imp_module.lstrip("."))
        level = level or dots
        imp_module = imp_module.lstrip(".")
    if level and level > 0:
        base_mod = python_module_name(importing_path)
        if importing_path.endswith("__init__.py"):
            pkg = base_mod
        else:
            pkg = base_mod.rsplit(".", 1)[0] if "." in base_mod else ""
        parts = pkg.split(".") if pkg else []
        if level > 1:
            if level - 1 >= len(parts):
                return None
            parts = parts[: len(parts) - (level - 1)]
            pkg = ".".join(parts)
        if imp_module:
            return f"{pkg}.{imp_module}" if pkg else imp_module
        return pkg or None
    return imp_module or None


def module_candidates(imp_module: str, importing_path: str, level: int = 0) -> set[str]:
    """Return every module identity (dotted Python or slash-normalized TS/JS) an import could name."""
    spec = (imp_module or "").strip()
    candidates: set[str] = set()
    resolved = resolve_dotted_module(spec, importing_path, level)
    if resolved:
        candidates.add(resolved)
    if spec.startswith((".", "/")):
        base = posixpath.dirname((importing_path or "").replace("\\", "/"))
        joined = posixpath.normpath(posixpath.join(base, spec))
        candidates.add(normalize_module_path(joined, strip_index=True))
    elif spec:
        candidates.add(normalize_module_path(spec, strip_index=True))
    return candidates


__all__ = [
    "module_candidates",
    "normalize_module_path",
    "python_module_name",
    "resolve_dotted_module",
    "resolve_import_module",
]
