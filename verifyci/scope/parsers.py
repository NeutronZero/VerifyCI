"""Shared language/extension classification, parse budget helpers, and Tree-sitter loaders."""

from __future__ import annotations

import sys
import threading
from typing import Any, Callable, Iterable

from verifyci.runtime.budget import WorkBudget
from verifyci.scope.models import SourceFacts

PYTHON_EXTENSIONS = frozenset({"py", "pyi"})
TS_ONLY_EXTENSIONS = frozenset({"ts", "tsx", "mts", "cts"})
JS_EXTENSIONS = frozenset({"js", "jsx", "mjs", "cjs"})
TS_JS_EXTENSIONS = TS_ONLY_EXTENSIONS | JS_EXTENSIONS
SUPPORTED_CODE_EXTENSIONS = frozenset({"py"}) | TS_JS_EXTENSIONS
SUPPORTED_CODE_WITH_PYI_EXTENSIONS = PYTHON_EXTENSIONS | TS_JS_EXTENSIONS

TEXT_SUFFIXES = frozenset(
    {
        "md", "markdown", "txt", "rst", "toml", "yaml", "yml", "json", "json5",
        "ini", "cfg", "conf", "env", "lock", "csv", "tsv", "xml", "html", "htm",
        "css", "scss", "less", "svg", "sql", "proto", "graphql", "gql", "sh",
        "bash", "zsh", "ps1", "bat", "cmd",
    }
)

_PY_LANG_OBJECT: Any = None
_PY_LANG_INITIALIZED: bool = False
_TS_LANG_OBJECTS: dict[str, Any] = {}
_LANG_LOCK = threading.Lock()


def path_suffix(path: str) -> str:
    return path.rsplit(".", 1)[-1].lower() if "." in path else ""


def ts_language_for_path(path: str) -> str:
    suffix = path_suffix(path)
    if suffix == "tsx":
        return "tsx"
    if suffix in TS_ONLY_EXTENSIONS:
        return "typescript"
    return "javascript"


def frontend_identity(path: str) -> tuple[str, str]:
    suffix = path_suffix(path)
    if suffix == "py":
        return "python", f"python-ast-{sys.version_info.major}.{sys.version_info.minor}"
    if suffix in TS_ONLY_EXTENSIONS:
        return "typescript", "tree-sitter-typescript-0.23"
    if suffix in JS_EXTENSIONS:
        return "javascript", "tree-sitter-javascript-0.23"
    return "text", "other-text-v1"


def make_parser(lang_obj: Any) -> Any:
    """Build a fresh tree-sitter parser for one parse.

    Parsers are never cached or shared: a `Parser` may only be used by the
    thread that owns it, and the gate parses entries on a worker pool.  Parsed
    trees and `Language` objects are immutable, so those are shared freely.
    """
    from tree_sitter import Parser

    try:
        return Parser(lang_obj)
    except TypeError:
        parser = Parser()
        parser.set_language(lang_obj)
        return parser


def py_language() -> Any:
    """Return the cached Python `Language` object, or None when unavailable."""
    global _PY_LANG_OBJECT, _PY_LANG_INITIALIZED
    if not _PY_LANG_INITIALIZED:
        with _LANG_LOCK:
            if not _PY_LANG_INITIALIZED:
                try:
                    import tree_sitter_python as tp
                    from tree_sitter import Language

                    fn: Callable[[], Any] | None = getattr(tp, "language", None) or getattr(
                        tp, "language_python", None
                    )
                    if fn is not None:
                        _PY_LANG_OBJECT = Language(fn())  # ty: ignore[deprecated]
                except Exception:
                    _PY_LANG_OBJECT = None
                finally:
                    _PY_LANG_INITIALIZED = True
    return _PY_LANG_OBJECT


def ts_language(language: str) -> Any:
    """Return the cached TS/JS `Language` object for `language`, or None."""
    if language not in _TS_LANG_OBJECTS:
        with _LANG_LOCK:
            if language not in _TS_LANG_OBJECTS:
                try:
                    if language == "typescript":
                        import tree_sitter_typescript as ts

                        fn: Callable[[], Any] | None = getattr(
                            ts, "language_typescript", None
                        ) or getattr(ts, "language", None)
                        if fn is None:
                            raise RuntimeError("tree-sitter typescript language unavailable")
                        capsule = fn()
                    elif language == "tsx":
                        import tree_sitter_typescript as ts

                        fn = getattr(ts, "language_tsx", None) or getattr(ts, "language", None)
                        if fn is None:
                            raise RuntimeError("tree-sitter typescript language unavailable")
                        capsule = fn()
                    else:
                        import tree_sitter_javascript as js

                        fn = getattr(js, "language", None)
                        if fn is None:
                            raise RuntimeError("tree-sitter javascript language unavailable")
                        capsule = fn()
                    from tree_sitter import Language

                    _TS_LANG_OBJECTS[language] = Language(capsule)  # ty: ignore[deprecated]
                except Exception:
                    _TS_LANG_OBJECTS[language] = None

    return _TS_LANG_OBJECTS.get(language)


def parse_ts_bytes(source_bytes: bytes, language: str = "typescript") -> Any | None:
    """Parse bytes with a thread-local Tree-sitter parser for ``language``."""
    lang_obj = ts_language(language)
    if lang_obj is None:
        return None
    return make_parser(lang_obj).parse(source_bytes)


def tree_shape(root: Any, children_fn: Callable[[Any], Iterable[Any]]) -> tuple[int, int]:
    """Return (node_count, max_depth) iteratively without risking stack overflow."""
    node_count = 0
    max_depth = 0
    stack: list[tuple[Any, int]] = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        node_count += 1
        if depth > max_depth:
            max_depth = depth
        for child in children_fn(node):
            stack.append((child, depth + 1))
    return node_count, max_depth


def check_ast_budget(
    path: str,
    language: str,
    root: Any,
    children_fn: Callable[[Any], Iterable[Any]],
    budget: WorkBudget,
) -> SourceFacts | None:
    """Return a failed SourceFacts if AST node count or depth exceeds ``budget``."""
    node_count, max_depth = tree_shape(root, children_fn)
    if node_count > budget.max_ast_nodes:
        return SourceFacts(
            path=path,
            language=language,
            supported=False,
            parse_error=f"parse_resource_limit: AST node count {node_count} exceeds max_ast_nodes {budget.max_ast_nodes}",
        )
    if max_depth > budget.max_ast_depth:
        return SourceFacts(
            path=path,
            language=language,
            supported=False,
            parse_error=f"parse_resource_limit: AST depth {max_depth} exceeds max_ast_depth {budget.max_ast_depth}",
        )
    return None


__all__ = [
    "JS_EXTENSIONS",
    "PYTHON_EXTENSIONS",
    "SUPPORTED_CODE_EXTENSIONS",
    "SUPPORTED_CODE_WITH_PYI_EXTENSIONS",
    "TEXT_SUFFIXES",
    "TS_JS_EXTENSIONS",
    "TS_ONLY_EXTENSIONS",
    "check_ast_budget",
    "frontend_identity",
    "make_parser",
    "parse_ts_bytes",
    "path_suffix",
    "py_language",
    "tree_shape",
    "ts_language",
    "ts_language_for_path",
]
