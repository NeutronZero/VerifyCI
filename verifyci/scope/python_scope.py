"""Python AST/tree-sitter entity, call, import, and safety analysis."""

from __future__ import annotations

import ast
import collections
from typing import Any, Sequence

from verifyci.contracts.model import Entity
from verifyci.contracts.names import normalize_repo_path, qualify
from verifyci.runtime.budget import DEFAULT_BUDGET, WorkBudget
from verifyci.scope.models import (
    CallSite,
    ImportFact,
    Param,
    SourceFacts,
    blob_id_from_hash,
    sha256_text,
)
from verifyci.scope.parsers import check_ast_budget, make_parser, py_language


def _annotation(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _callee_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _callee_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _decorator_names(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
) -> tuple[str, ...]:
    out: list[str] = []
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name):
            out.append(dec.id)
        elif isinstance(dec, ast.Attribute):
            out.append(_callee_name(dec))
        elif isinstance(dec, ast.Call):
            out.append(_callee_name(dec.func))
    return tuple(out)


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
        self.imports: list[ImportFact] = []
        self.loads: set[str] = set()
        self.dynamic = False
        self.has_decorators = False
        self.scope_stack: list[set[str]] = []

    def _collect_local_bindings(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda
    ) -> set[str]:
        locals_found: set[str] = set()
        if hasattr(node, "args"):
            for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                locals_found.add(arg.arg)
            if node.args.vararg:
                locals_found.add(node.args.vararg.arg)
            if node.args.kwarg:
                locals_found.add(node.args.kwarg.arg)
        globals_declared: set[str] = set()
        todo = collections.deque(ast.iter_child_nodes(node))
        while todo:
            child = todo.popleft()
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                locals_found.add(child.name)
                continue
            elif isinstance(child, ast.Global):
                globals_declared.update(child.names)
            elif isinstance(child, ast.Assign):
                for target in child.targets:
                    for t in ast.walk(target):
                        if isinstance(t, ast.Name):
                            locals_found.add(t.id)
            elif isinstance(child, (ast.AnnAssign, ast.AugAssign)):
                for t in ast.walk(child.target):
                    if isinstance(t, ast.Name):
                        locals_found.add(t.id)
            elif isinstance(child, (ast.For, ast.AsyncFor)):
                for t in ast.walk(child.target):
                    if isinstance(t, ast.Name):
                        locals_found.add(t.id)
            elif isinstance(child, (ast.With, ast.AsyncWith)):
                for item in child.items:
                    if item.optional_vars:
                        for t in ast.walk(item.optional_vars):
                            if isinstance(t, ast.Name):
                                locals_found.add(t.id)
            elif isinstance(child, ast.ExceptHandler):
                if child.name:
                    locals_found.add(child.name)
            elif isinstance(child, ast.NamedExpr):
                if isinstance(child.target, ast.Name):
                    locals_found.add(child.target.id)
            todo.extend(ast.iter_child_nodes(child))
        return locals_found - globals_declared

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if not self.has_decorators and _decorator_names(node):
            self.has_decorators = True
        self.scope_stack.append(self._collect_local_bindings(node))
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if not self.has_decorators and _decorator_names(node):
            self.has_decorators = True
        self.scope_stack.append(self._collect_local_bindings(node))
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if not self.has_decorators and _decorator_names(node):
            self.has_decorators = True
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name
            self.imports.append(
                ImportFact(
                    module=alias.name,
                    names=(local,),
                    line=node.lineno,
                    level=0,
                    aliases=((alias.name, local),),
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        aliases = tuple((alias.name, alias.asname or alias.name) for alias in node.names)
        self.imports.append(
            ImportFact(
                module=node.module or "",
                names=tuple(alias.name for alias in node.names),
                line=node.lineno,
                level=node.level,
                aliases=aliases,
            )
        )

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.scope_stack.append(self._collect_local_bindings(node))
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        callee = _callee_name(node.func)
        if isinstance(node.func, ast.Subscript):
            self.dynamic = True
        if callee:
            if callee in {"getattr", "setattr", "eval", "exec", "__import__", "compile"}:
                self.dynamic = True
            is_shadowed = False
            if "." not in callee:
                is_shadowed = any(callee in scope for scope in self.scope_stack)
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
                    is_shadowed=is_shadowed,
                )
            )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self.loads.add(node.id)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if isinstance(node.ctx, ast.Load):
            self.loads.add(node.attr)
        self.generic_visit(node)


def _collect_all(node: ast.Module) -> set[str]:
    out: set[str] = set()
    for stmt in node.body:
        targets: Sequence[ast.expr] = ()
        if isinstance(stmt, ast.Assign):
            targets = stmt.targets
        elif isinstance(stmt, ast.AnnAssign):
            targets = (stmt.target,)
        else:
            continue
        if any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets) and isinstance(
            stmt.value, (ast.List, ast.Tuple)
        ):
            for elt in stmt.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    out.add(elt.value)
    return out


def _build_python_entity(
    *,
    path: str,
    module: str,
    qname: str,
    name: str,
    kind: str,
    ast_node: ast.AST | None,
    exports: frozenset[str] | set[str],
    blob_id: str,
    is_async: bool,
    start_line: int,
    end_line: int,
    start_col: int,
    end_col: int,
    start_byte: int,
    end_byte: int,
) -> Entity:
    params = (
        _function_params(ast_node)
        if ast_node is not None and isinstance(ast_node, (ast.FunctionDef, ast.AsyncFunctionDef))
        else ()
    )
    returns = (
        _annotation(ast_node.returns)
        if ast_node is not None and isinstance(ast_node, (ast.FunctionDef, ast.AsyncFunctionDef))
        else ""
    )
    decorators = list(_decorator_names(ast_node)) if isinstance(ast_node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else []
    body = ast.dump(ast_node, annotate_fields=False, include_attributes=False) if ast_node is not None else ""
    signature = {
        "params": [p.to_dict() for p in params],
        "returns": returns,
        "async": is_async,
        "decorators": decorators,
    }
    top_level = "." not in qname
    is_export = bool((top_level and not name.startswith("_")) or name in exports)
    return Entity(
        file_path=path,
        qname=qualify(module, qname),
        kind=kind,
        start_line=start_line,
        end_line=end_line,
        start_col=start_col,
        end_col=end_col,
        start_byte=start_byte,
        end_byte=end_byte,
        blob_id=blob_id,
        body_digest=sha256_text(body),
        is_export=is_export,
        is_async=is_async,
        signature_digest=sha256_text(repr(signature)),
        parameters=tuple((p.name, p.kind, p.has_default) for p in params),
        returns=returns,
    )


def _python_entities_via_tree_sitter(
    ts_parser: Any,
    path: str,
    module: str,
    exports: frozenset[str] | set[str],
    blob_id: str,
    tree: ast.Module,
    source_bytes: bytes,
) -> tuple[Entity, ...]:
    """Extract Python entity spans from a tree-sitter parse.

    Runs on the calling thread with a parser owned by that thread; see `make_parser`.
    """
    ts_tree = ts_parser.parse(source_bytes)
    ast_nodes: dict[str, Any] = {}

    def map_ast(node: ast.AST, parent_qual: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            qname = f"{parent_qual}.{node.name}" if parent_qual else node.name
            ast_nodes[qname] = node
            for child in ast.iter_child_nodes(node):
                map_ast(child, qname)
            return
        for child in ast.iter_child_nodes(node):
            map_ast(child, parent_qual)

    map_ast(tree, "")
    entities: list[Entity] = []

    def walk_ts(node: Any, parent_qual: str) -> None:
        name = ""
        kind = ""
        if node.type in ("function_definition", "class_definition"):
            name_node = next((c for c in node.children if c.type == "identifier"), None)
            if name_node:
                name = name_node.text.decode("utf-8")
                kind = "class" if node.type == "class_definition" else "function"
        if name and kind:
            qname = f"{parent_qual}.{name}" if parent_qual else name
            span_node = node.parent if (node.parent and node.parent.type == "decorated_definition") else node
            ast_node = ast_nodes.get(qname)
            is_async = any(c.type == "async" for c in node.children) or bool(
                ast_node and isinstance(ast_node, ast.AsyncFunctionDef)
            )
            entities.append(
                _build_python_entity(
                    path=path,
                    module=module,
                    qname=qname,
                    name=name,
                    kind=kind,
                    ast_node=ast_node,
                    exports=exports,
                    blob_id=blob_id,
                    is_async=is_async,
                    start_line=span_node.start_point.row + 1,
                    end_line=span_node.end_point.row + 1,
                    start_col=span_node.start_point.column,
                    end_col=span_node.end_point.column,
                    start_byte=span_node.start_byte,
                    end_byte=span_node.end_byte,
                )
            )
            for child in node.children:
                walk_ts(child, qname)
            return
        for child in node.children:
            walk_ts(child, parent_qual)

    walk_ts(ts_tree.root_node, "")
    return tuple(entities)


def _python_entities(
    path: str,
    source: str,
    tree: ast.Module,
    exports: frozenset[str] | set[str] | None = None,
    blob_hash: str = "",
) -> tuple[Entity, ...]:
    source_bytes = source.encode("utf-8")
    blob_id = blob_id_from_hash(blob_hash, source_bytes)
    module = normalize_repo_path(path).rsplit(".", 1)[0]
    if exports is None:
        exports = _collect_all(tree)

    ts_lang = py_language()
    if ts_lang is not None:
        try:
            return _python_entities_via_tree_sitter(
                make_parser(ts_lang), path, module, exports, blob_id, tree, source_bytes
            )
        except Exception:
            pass

    entities: list[Entity] = []
    line_byte_offsets = [0]
    pos = 0
    while True:
        pos = source_bytes.find(b"\n", pos)
        if pos == -1:
            break
        pos += 1
        line_byte_offsets.append(pos)

    def _byte_offset(lineno: int, col: int) -> int:
        idx = min(max(lineno - 1, 0), len(line_byte_offsets) - 1)
        return line_byte_offsets[idx] + col

    def walk(node: ast.AST, parent_qual: str) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = node.name
            qname = f"{parent_qual}.{name}" if parent_qual else name
            kind = "function" if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else "class"
            if node.decorator_list:
                first_dec = node.decorator_list[0]
                s_line = first_dec.lineno
                line_offset = line_byte_offsets[s_line - 1] if s_line - 1 < len(line_byte_offsets) else 0
                next_line_offset = line_byte_offsets[s_line] if s_line < len(line_byte_offsets) else len(source_bytes)
                at_pos = source_bytes.find(b"@", line_offset, next_line_offset)
                s_col = at_pos - line_offset if at_pos != -1 else getattr(first_dec, "col_offset", 0)
                s_byte = at_pos if at_pos != -1 else _byte_offset(s_line, s_col)
            else:
                s_line = getattr(node, "lineno", 1)
                s_col = getattr(node, "col_offset", 0)
                s_byte = _byte_offset(s_line, s_col)

            e_line = getattr(node, "end_lineno", s_line)
            e_col = getattr(node, "end_col_offset", 0)
            e_byte = _byte_offset(e_line, e_col)
            entities.append(
                _build_python_entity(
                    path=path,
                    module=module,
                    qname=qname,
                    name=name,
                    kind=kind,
                    ast_node=node,
                    exports=exports,
                    blob_id=blob_id,
                    is_async=isinstance(node, ast.AsyncFunctionDef),
                    start_line=s_line,
                    end_line=e_line,
                    start_col=s_col,
                    end_col=e_col,
                    start_byte=s_byte,
                    end_byte=e_byte,
                )
            )
            for child in ast.iter_child_nodes(node):
                walk(child, qname)
            return
        for child in ast.iter_child_nodes(node):
            walk(child, parent_qual)

    walk(tree, "")
    return tuple(entities)


def analyze_python(
    path: str,
    source: str,
    source_roots: Sequence[str] = (),
    blob_hash: str = "",
    budget: WorkBudget = DEFAULT_BUDGET,
) -> SourceFacts:
    encoded = source.encode("utf-8")
    if len(encoded) > budget.max_file_bytes:
        return SourceFacts(
            path=path,
            language="python",
            supported=False,
            parse_error=f"parse_resource_limit: file size {len(encoded)} exceeds max_file_bytes {budget.max_file_bytes}",
        )
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return SourceFacts(
            path=path,
            language="python",
            supported=False,
            parse_error=f"line {exc.lineno}: {exc.msg}",
        )
    budget_err = check_ast_budget(path, "python", tree, ast.iter_child_nodes, budget)
    if budget_err is not None:
        return budget_err
    visitor = _CallVisitor()
    visitor.visit(tree)
    exports_set = frozenset(_collect_all(tree))
    entities = _python_entities(
        path, source, tree, exports=exports_set, blob_hash=blob_hash
    )
    return SourceFacts(
        path=path,
        language="python",
        supported=True,
        entities=entities,
        calls=tuple(visitor.calls),
        imports=tuple(visitor.imports),
        name_loads=frozenset(visitor.loads),
        exports=exports_set,
        has_dynamic_dispatch=visitor.dynamic,
        has_unknown_decorator=visitor.has_decorators,
    )


def _is_safe_constant_value(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_safe_constant_value(elt) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (k is None or _is_safe_constant_value(k)) and _is_safe_constant_value(v)
            for k, v in zip(node.keys, node.values)
        )
    if isinstance(node, ast.Call):
        callee = _callee_name(node.func)
        if callee in {"Path", "pathlib.Path", "int", "float", "str", "bool", "tuple", "list", "dict", "set", "frozenset"}:
            return all(_is_safe_constant_value(arg) for arg in node.args)
        return False
    if isinstance(node, ast.UnaryOp):
        return _is_safe_constant_value(node.operand)
    if isinstance(node, ast.BinOp):
        return _is_safe_constant_value(node.left) and _is_safe_constant_value(node.right)
    return False


def _is_safe_range_tree(tree: ast.Module, start_line: int, end_line: int) -> bool:
    for stmt in tree.body:
        s_start = getattr(stmt, "lineno", 1)
        if s_start > end_line:
            break
        s_end = getattr(stmt, "end_lineno", s_start)
        if s_end < start_line:
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, ast.Assign) and _is_safe_constant_value(stmt.value):
            continue
        if isinstance(stmt, ast.AnnAssign) and (stmt.value is None or _is_safe_constant_value(stmt.value)):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        return False
    return True


def is_safe_module_construct(
    base_source: str,
    old_start: int,
    old_count: int,
    head_source: str,
    new_start: int,
    new_count: int,
    base_tree: ast.Module | None = None,
    head_tree: ast.Module | None = None,
) -> bool:
    """Validate that changes outside entities only touch safe module declarations."""
    if old_count > 0 and (base_source or base_tree is not None):
        if base_tree is None:
            try:
                base_tree = ast.parse(base_source)
            except SyntaxError:
                return False
        if not _is_safe_range_tree(base_tree, old_start, old_start + old_count - 1):
            return False
    if new_count > 0 and (head_source or head_tree is not None):
        if head_tree is None:
            try:
                head_tree = ast.parse(head_source)
            except SyntaxError:
                return False
        if not _is_safe_range_tree(head_tree, new_start, new_start + new_count - 1):
            return False
    if old_count == 0 and new_count == 0:
        return False
    return True


__all__ = [
    "analyze_python",
    "is_safe_module_construct",
]
