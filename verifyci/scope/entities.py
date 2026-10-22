"""Entity extraction and changed-scope mapping for Python and TS/JS.

Python uses the standard-library AST.  TS/JS uses tree-sitter when the pinned
grammar is available; otherwise the file is honestly reported as unsupported
rather than mapped by guesswork.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Any, Mapping, Sequence

from verifyci.contracts.model import DiffEntry, Entity, Hunk
from verifyci.contracts.names import normalize_module_name, qualify


@dataclass(frozen=True, slots=True)
class Param:
    name: str
    kind: str
    has_default: bool

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "has_default": self.has_default}


@dataclass(frozen=True, slots=True)
class CallSite:
    callee: str
    line: int
    positional: int
    keywords: tuple[str, ...]
    has_starargs: bool = False
    has_kwargs: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "callee": self.callee,
            "line": self.line,
            "positional": self.positional,
            "keywords": list(self.keywords),
            "has_starargs": self.has_starargs,
            "has_kwargs": self.has_kwargs,
        }


@dataclass(frozen=True, slots=True)
class ImportFact:
    module: str
    names: tuple[str, ...]
    line: int


@dataclass(frozen=True, slots=True)
class SourceFacts:
    path: str
    language: str
    supported: bool
    entities: tuple[Entity, ...] = ()
    calls: tuple[CallSite, ...] = ()
    imports: tuple[ImportFact, ...] = ()
    name_loads: frozenset[str] = frozenset()
    exports: frozenset[str] = frozenset()
    parse_error: str = ""
    has_dynamic_dispatch: bool = False
    has_unknown_decorator: bool = False

    def entity_by_qname(self) -> dict[str, Entity]:
        return {e.qname: e for e in self.entities}

    def names(self) -> set[str]:
        return {e.qname.rsplit(".", 1)[-1] for e in self.entities}


def _digest(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def _annotation(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _param_kind(arg: ast.arg, index: int, args: ast.arguments) -> str:
    if arg in args.posonlyargs:
        return "posonly"
    if arg in args.args:
        return "positional"
    if arg in args.kwonlyargs:
        return "kwonly"
    return "positional"


def _function_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[Param, ...]:
    args = node.args
    params: list[Param] = []
    positional = list(args.posonlyargs) + list(args.args)
    defaults_start = len(positional) - len(args.defaults)
    for index, arg in enumerate(positional):
        kind = "posonly" if arg in args.posonlyargs else "positional"
        params.append(Param(arg.arg, kind, index >= defaults_start))
    if args.vararg:
        params.append(Param(args.vararg.arg, "vararg", False))
    for index, arg in enumerate(args.kwonlyargs):
        default = args.kw_defaults[index] if index < len(args.kw_defaults) else None
        params.append(Param(arg.arg, "kwonly", default is not None))
    if args.kwarg:
        params.append(Param(args.kwarg.arg, "kwarg", False))
    return tuple(params)


class _CallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.calls: list[CallSite] = []
        self.loads: set[str] = set()
        self.dynamic = False

    def visit_Call(self, node: ast.Call) -> None:
        callee = _callee_name(node.func)
        if callee:
            if callee in {"getattr", "setattr", "eval", "exec", "__import__", "compile"}:
                self.dynamic = True
            self.calls.append(
                CallSite(
                    callee=callee,
                    line=getattr(node, "lineno", 1),
                    positional=len(node.args),
                    keywords=tuple(
                        kw.arg for kw in node.keywords if kw.arg is not None
                    ),
                    has_starargs=any(isinstance(a, ast.Starred) for a in node.args),
                    has_kwargs=any(kw.arg is None for kw in node.keywords),
                )
            )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self.loads.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load):
            self.loads.add(node.attr)
        self.generic_visit(node)


def _callee_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _callee_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _collect_all(node: ast.Module) -> set[str]:
    out: set[str] = set()
    for stmt in node.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(stmt.value, (ast.List, ast.Tuple)):
                        for elt in stmt.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                out.add(elt.value)
        elif isinstance(stmt, ast.AnnAssign):
            if isinstance(stmt.target, ast.Name) and stmt.target.id == "__all__":
                if isinstance(stmt.value, (ast.List, ast.Tuple)):
                    for elt in stmt.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            out.add(elt.value)
    return out


def _decorator_names(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> tuple[str, ...]:
    out: list[str] = []
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name):
            out.append(dec.id)
        elif isinstance(dec, ast.Attribute):
            out.append(_callee_name(dec))
        elif isinstance(dec, ast.Call):
            out.append(_callee_name(dec.func))
    return tuple(out)


def _python_entities(
    path: str,
    source: str,
    tree: ast.Module,
    source_roots: Sequence[str],
) -> tuple[Entity, ...]:
    module = normalize_module_name(path, source_roots)
    entities: list[Entity] = []
    exports = _collect_all(tree)

    def walk(node: ast.AST, parent_qual: str, in_function: bool) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = node.name
            if parent_qual:
                if in_function:
                    qname = f"{parent_qual}.<locals>.{name}"
                else:
                    qname = f"{parent_qual}.{name}"
            else:
                qname = name
            params = _function_params(node) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else ()
            kind = "function" if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else "class"
            body = ast.dump(node, annotate_fields=False, include_attributes=False)
            signature = {
                "params": [p.to_dict() for p in params],
                "returns": _annotation(node.returns) if not isinstance(node, ast.ClassDef) else "",
                "async": isinstance(node, ast.AsyncFunctionDef),
                "decorators": list(_decorator_names(node)),
            }
            top_level = "." not in qname and "<locals>" not in qname
            is_export = bool(
                (top_level and not name.startswith("_"))
                or name in exports
                or (top_level and name in exports)
            )
            entities.append(
                Entity(
                    file_path=path,
                    qname=qualify(module, qname),
                    kind=kind,
                    start_line=getattr(node, "lineno", 1),
                    end_line=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                    body_digest=_digest(body),
                    is_export=is_export,
                    is_async=isinstance(node, ast.AsyncFunctionDef),
                    signature_digest=_digest(repr(signature)),
                    parameters=tuple((p.name, p.kind, p.has_default) for p in params),
                    returns=_annotation(node.returns) if not isinstance(node, ast.ClassDef) else "",
                )
            )
            child_in_function = in_function or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            for child in ast.iter_child_nodes(node):
                walk(child, qname, child_in_function)
            return
        for child in ast.iter_child_nodes(node):
            walk(child, parent_qual, in_function)

    walk(tree, "", False)
    return tuple(entities)


def analyze_python(path: str, source: str, source_roots: Sequence[str] = ()) -> SourceFacts:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return SourceFacts(
            path=path,
            language="python",
            supported=False,
            parse_error=f"line {exc.lineno}: {exc.msg}",
        )
    visitor = _CallVisitor()
    visitor.visit(tree)
    imports: list[ImportFact] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(ImportFact(alias.name, (alias.asname or alias.name,), node.lineno))
        elif isinstance(node, ast.ImportFrom):
            imports.append(
                ImportFact(
                    node.module or "",
                    tuple(alias.name for alias in node.names),
                    node.lineno,
                )
            )
    entities = _python_entities(path, source, tree, source_roots)
    unknown_decorators = False
    for entity in entities:
        # Decorators are conservatively opaque unless policy says otherwise;
        # the semantic check consumes this flag.
        pass
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if _decorator_names(node):
                unknown_decorators = True
                break
    return SourceFacts(
        path=path,
        language="python",
        supported=True,
        entities=entities,
        calls=tuple(visitor.calls),
        imports=tuple(imports),
        name_loads=frozenset(visitor.loads),
        exports=frozenset(_collect_all(tree)),
        has_dynamic_dispatch=visitor.dynamic,
        has_unknown_decorator=unknown_decorators,
    )


# ---------------------------------------------------------------------------
# TS / JS
# ---------------------------------------------------------------------------

_TS_LANGUAGE_CACHE: dict[str, Any] = {}


def _ts_language(language: str) -> Any:
    if language in _TS_LANGUAGE_CACHE:
        return _TS_LANGUAGE_CACHE[language]
    try:
        if language == "typescript":
            import tree_sitter_typescript as ts

            capsule = getattr(ts, "language_typescript", ts.language)()
        elif language == "tsx":
            import tree_sitter_typescript as ts

            capsule = getattr(ts, "language_tsx", ts.language)()
        else:
            import tree_sitter_javascript as js

            capsule = js.language()
        from tree_sitter import Language, Parser

        result = Parser(Language(capsule))
    except Exception:
        result = None
    _TS_LANGUAGE_CACHE[language] = result
    return result


def _node_text(node: Any) -> str:
    return node.text.decode("utf-8", "replace")


def _ts_name(node: Any) -> str:
    for child in node.children:
        if child.type in ("identifier", "property_identifier", "type_identifier", "name"):
            return _node_text(child)
    for child in node.children:
        if "name" in child.type:
            return _node_text(child)
    return ""


def _ts_signature(node: Any) -> tuple[tuple[str, str, bool], ...]:
    params = None
    for child in node.children:
        if child.type in ("formal_parameters", "parameters"):
            params = child
            break
    if params is None:
        return ()
    out: list[tuple[str, str, bool]] = []
    for child in params.children:
        if child.type in ("identifier", "required_parameter", "optional_parameter", "rest_pattern"):
            text = _node_text(child).strip()
            if not text or text in (",",):
                continue
            name = text.split(":", 1)[0].split("=", 1)[0].strip()
            if name.startswith("..."):
                name = name[3:]
            has_default = "=" in text
            kind = "vararg" if text.startswith("...") else "positional"
            if text.endswith("?") or "?" in text.split(":", 1)[0]:
                has_default = True
            out.append((name, kind, has_default))
    return tuple(out)


def _ts_entities(path: str, source: str) -> tuple[Entity, ...] | None:
    suffix = path.rsplit(".", 1)[-1].lower()
    language = "tsx" if suffix == "tsx" else ("typescript" if suffix in ("ts", "mts", "cts") else "javascript")
    parser = _ts_language(language)
    if parser is None:
        return None
    try:
        tree = parser.parse(source.encode("utf-8"))
    except Exception:
        return None
    module = path.rsplit(".", 1)[0]
    entities: list[Entity] = []

    def walk(node: Any, parent_class: str = "") -> None:
        name = ""
        kind = ""
        if node.type in ("function_declaration", "class_declaration", "interface_declaration", "method_definition"):
            name = _ts_name(node)
            kind = "class" if node.type == "class_declaration" else ("interface" if node.type == "interface_declaration" else "function")
        elif node.type in ("lexical_declaration", "variable_declaration"):
            # Find the first declarator with a function/arrow initializer.
            for child in node.children:
                if child.type == "variable_declarator":
                    init = next((c for c in child.children if c.type in ("arrow_function", "function_expression", "function")), None)
                    if init is not None:
                        name = _ts_name(child)
                        kind = "function"
                        break
        if name and kind:
            qname = f"{parent_class}.{name}" if parent_class else name
            start = node.start_point.row + 1
            end = node.end_point.row + 1
            is_export = False
            p = node.parent
            while p is not None:
                if p.type == "export_statement":
                    is_export = True
                    break
                p = p.parent
            text = _node_text(node)
            params = _ts_signature(node)
            entities.append(
                Entity(
                    file_path=path,
                    qname=qualify(module, qname),
                    kind=kind,
                    start_line=start,
                    end_line=end,
                    body_digest=_digest(text),
                    is_export=is_export or name == "default",
                    is_async="async" in text.split("{", 1)[0],
                    signature_digest=_digest(repr(params)),
                    parameters=params,
                )
            )
            if kind == "class":
                for child in node.children:
                    walk(child, qname)
                return
        for child in node.children:
            walk(child, parent_class)

    walk(tree.root_node)
    return tuple(entities)


def analyze_typescript(path: str, source: str) -> SourceFacts:
    entities = _ts_entities(path, source)
    if entities is None:
        return SourceFacts(
            path=path,
            language="typescript",
            supported=False,
            parse_error="tree-sitter TypeScript/JavaScript grammar unavailable",
        )
    calls: list[CallSite] = []
    imports: list[ImportFact] = []
    loads: set[str] = set()
    dynamic = False
    suffix = path.rsplit(".", 1)[-1].lower()
    language = "tsx" if suffix == "tsx" else ("typescript" if suffix in ("ts", "mts", "cts") else "javascript")
    parser = _ts_language(language)
    tree = parser.parse(source.encode("utf-8"))
    def walk(node: Any) -> None:
        nonlocal dynamic
        if node.type == "call_expression":
            callee = _node_text(node.children[0]).strip() if node.children else ""
            args_node = next((c for c in node.children if c.type == "arguments"), None)
            positional = 0
            keywords: list[str] = []
            if args_node is not None:
                for arg in args_node.children:
                    if arg.type in (",", "(", ")"):
                        continue
                    if arg.type == "object":
                        for pair in arg.children:
                            if pair.type == "pair" and pair.children:
                                keywords.append(_node_text(pair.children[0]).strip().strip("\"'"))
                    elif arg.type == "spread_element":
                        dynamic = True
                    else:
                        positional += 1
            if callee:
                calls.append(CallSite(callee, node.start_point.row + 1, positional, tuple(keywords)))
                if callee in ("eval", "Function", "require"):
                    dynamic = True
        elif node.type in ("import_statement", "import_declaration"):
            text = _node_text(node)
            m = re.search(r"from\s+['\"]([^'\"]+)['\"]", text)
            if m:
                imports.append(ImportFact(m.group(1), (), node.start_point.row + 1))
        elif node.type in ("identifier", "property_identifier"):
            loads.add(_node_text(node))
        for child in node.children:
            walk(child)
    walk(tree.root_node)
    return SourceFacts(
        path=path,
        language="typescript",
        supported=True,
        entities=entities,
        calls=tuple(calls),
        imports=tuple(imports),
        name_loads=frozenset(loads),
        has_dynamic_dispatch=dynamic,
    )


_TEXT_SUFFIXES = {
    "md", "markdown", "txt", "rst", "toml", "yaml", "yml", "json", "json5",
    "ini", "cfg", "conf", "env", "lock", "csv", "tsv", "xml", "html", "htm",
    "css", "scss", "less", "svg", "sql", "proto", "graphql", "gql", "sh",
    "bash", "zsh", "ps1", "bat", "cmd",
}


def analyze_source(path: str, source: str, source_roots: Sequence[str] = ()) -> SourceFacts:
    suffix = path.rsplit(".", 1)[-1].lower()
    if suffix == "py":
        return analyze_python(path, source, source_roots)
    if suffix in ("ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"):
        return analyze_typescript(path, source)
    if suffix in _TEXT_SUFFIXES or "/" not in path and "." not in path:
        return SourceFacts(path=path, language="text", supported=True)
    return SourceFacts(path=path, language=suffix or "unknown", supported=False, parse_error="unsupported language frontend")


@dataclass(frozen=True, slots=True)
class ChangedScope:
    base_facts: Mapping[str, SourceFacts]
    head_facts: Mapping[str, SourceFacts]
    changed_entities: frozenset[str]
    base_entities: frozenset[str]
    head_entities: frozenset[str]
    unmapped_hunks: tuple[Mapping[str, Any], ...] = ()
    rename_limit_exceeded: bool = False

    def entity(self, qname: str) -> Entity | None:
        for facts in self.head_facts.values():
            for entity in facts.entities:
                if entity.qname == qname:
                    return entity
        for facts in self.base_facts.values():
            for entity in facts.entities:
                if entity.qname == qname:
                    return entity
        return None


def build_changed_scope(
    entries: Sequence[DiffEntry],
    *,
    source_roots: Sequence[str] = (),
    rename_limit_exceeded: bool = False,
) -> ChangedScope:
    base_facts: dict[str, SourceFacts] = {}
    head_facts: dict[str, SourceFacts] = {}
    changed: set[str] = set()
    base_entities: set[str] = set()
    head_entities: set[str] = set()
    unmapped: list[dict[str, Any]] = []
    for entry in entries:
        if entry.base_path and not entry.is_binary and not entry.is_submodule:
            bf = analyze_source(entry.base_path, entry.base_source, source_roots)
            base_facts[entry.base_path] = bf
            base_entities.update(e.qname for e in bf.entities)
        if entry.head_path and not entry.is_binary and not entry.is_submodule:
            hf = analyze_source(entry.head_path, entry.head_source, source_roots)
            head_facts[entry.head_path] = hf
            head_entities.update(e.qname for e in hf.entities)
        if entry.is_binary or entry.is_submodule:
            continue
        if not entry.hunks:
            # Rename-only or mode-only changes do not alter entity bodies.
            continue
        base_map = base_facts.get(entry.base_path)
        head_map = head_facts.get(entry.head_path)
        for hunk in entry.hunks:
            matched_base = _overlapping(base_map, hunk.old_start, hunk.old_end()) if base_map else []
            matched_head = _overlapping(head_map, hunk.new_start, hunk.new_end()) if head_map else []
            matched = set(matched_base) | set(matched_head)
            if matched:
                changed.update(matched)
            else:
                unmapped.append(
                    {
                        "path": entry.head_path or entry.base_path,
                        "hunk": hunk.to_dict(),
                        "reason_code": "mapping_unresolved",
                    }
                )
    return ChangedScope(
        base_facts=base_facts,
        head_facts=head_facts,
        changed_entities=frozenset(changed),
        base_entities=frozenset(base_entities),
        head_entities=frozenset(head_entities),
        unmapped_hunks=tuple(unmapped),
        rename_limit_exceeded=rename_limit_exceeded,
    )


def _overlapping(facts: SourceFacts | None, start: int, end: int) -> list[str]:
    if facts is None:
        return []
    return [e.qname for e in facts.entities if e.overlaps(start, end)]


def changed_hunks(entry: DiffEntry) -> tuple[Hunk, ...]:
    return entry.hunks


__all__ = [
    "CallSite",
    "ChangedScope",
    "ImportFact",
    "Param",
    "SourceFacts",
    "analyze_python",
    "analyze_source",
    "analyze_typescript",
    "build_changed_scope",
    "changed_hunks",
]
