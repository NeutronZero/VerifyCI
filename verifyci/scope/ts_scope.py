"""TypeScript and JavaScript tree-sitter entity, call, and import analysis."""

from __future__ import annotations

import re
from typing import Any

from verifyci.contracts.model import Entity
from verifyci.contracts.names import normalize_repo_path, qualify
from verifyci.runtime.budget import DEFAULT_BUDGET, WorkBudget
from verifyci.scope.models import (
    CallSite,
    ImportFact,
    SourceFacts,
    blob_id_from_hash,
    sha256_text,
)
from verifyci.scope.parsers import (
    check_ast_budget,
    make_parser,
    ts_language,
    ts_language_for_path,
)


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


def _ts_entities(
    path: str, source: str, blob_hash: str = "", tree: Any = None
) -> tuple[Entity, ...] | None:
    language = ts_language_for_path(path)
    source_bytes = source.encode("utf-8")
    if tree is None:
        lang_obj = ts_language(language)
        if lang_obj is None:
            return None
        try:
            tree = make_parser(lang_obj).parse(source_bytes)
        except Exception:
            return None
    module = normalize_repo_path(path).rsplit(".", 1)[0]
    blob_id = blob_id_from_hash(blob_hash, source_bytes)
    entities: list[Entity] = []

    def walk(node: Any, parent_class: str = "") -> None:
        name = ""
        kind = ""
        if node.type in ("function_declaration", "class_declaration", "interface_declaration", "method_definition"):
            name = _ts_name(node)
            kind = (
                "class"
                if node.type == "class_declaration"
                else (
                    "interface"
                    if node.type == "interface_declaration"
                    else ("method" if node.type == "method_definition" else "function")
                )
            )
        elif node.type in ("lexical_declaration", "variable_declaration"):
            for child in node.children:
                if child.type == "variable_declarator":
                    init = next(
                        (c for c in child.children if c.type in ("arrow_function", "function_expression", "function")),
                        None,
                    )
                    if init is not None:
                        name = _ts_name(child)
                        kind = "function"
                        break
        if name and kind:
            qname = f"{parent_class}.{name}" if parent_class else name
            is_export = (node.parent and node.parent.type == "export_statement") or name == "default"
            span_node = node.parent if (node.parent and node.parent.type == "export_statement") else node
            text = _node_text(span_node)
            params = _ts_signature(node)
            is_async = "async" in text.split("{", 1)[0] if "{" in text else "async" in text
            entities.append(
                Entity(
                    file_path=path,
                    qname=qualify(module, qname),
                    kind=kind,
                    start_line=span_node.start_point.row + 1,
                    end_line=span_node.end_point.row + 1,
                    start_col=span_node.start_point.column,
                    end_col=span_node.end_point.column,
                    start_byte=span_node.start_byte,
                    end_byte=span_node.end_byte,
                    blob_id=blob_id,
                    body_digest=sha256_text(text),
                    is_export=is_export,
                    is_async=is_async,
                    signature_digest=sha256_text(repr(params)),
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


def analyze_typescript(
    path: str,
    source: str,
    blob_hash: str = "",
    budget: WorkBudget = DEFAULT_BUDGET,
) -> SourceFacts:
    """Analyze a TS/JS file with a parser owned by the calling thread."""
    language = ts_language_for_path(path)
    lang_obj = ts_language(language)
    if lang_obj is None:
        return SourceFacts(
            path=path,
            language=language,
            supported=False,
            parse_error="tree-sitter TypeScript/JavaScript grammar unavailable",
        )
    parser = make_parser(lang_obj)
    source_bytes = source.encode("utf-8")
    if len(source_bytes) > budget.max_file_bytes:
        return SourceFacts(
            path=path,
            language=language,
            supported=False,
            parse_error=f"parse_resource_limit: file size {len(source_bytes)} exceeds max_file_bytes {budget.max_file_bytes}",
        )
    try:
        tree = parser.parse(source_bytes)
    except Exception as exc:
        return SourceFacts(
            path=path,
            language=language,
            supported=False,
            parse_error=f"line 1: {exc}",
        )
    budget_err = check_ast_budget(path, language, tree.root_node, lambda n: n.children, budget)
    if budget_err is not None:
        return budget_err
    entities = _ts_entities(path, source, blob_hash=blob_hash, tree=tree)
    if entities is None:
        return SourceFacts(
            path=path,
            language=language,
            supported=False,
            parse_error="tree-sitter TypeScript/JavaScript grammar unavailable",
        )
    calls: list[CallSite] = []
    imports: list[ImportFact] = []
    loads: set[str] = set()
    dynamic = False

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
                        positional += 1
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
                mod = m.group(1)
                names: list[str] = []
                aliases: list[tuple[str, str]] = []
                clause = text.split("from", 1)[0].replace("import", "").strip()
                if "{" in clause and "}" in clause:
                    specifiers = clause[clause.find("{") + 1 : clause.rfind("}")].split(",")
                    for spec in specifiers:
                        spec = spec.strip()
                        if not spec:
                            continue
                        if " as " in spec:
                            orig, local = spec.split(" as ", 1)
                            orig, local = orig.strip(), local.strip()
                            names.append(orig)
                            aliases.append((orig, local))
                        else:
                            names.append(spec)
                            aliases.append((spec, spec))
                elif "* as " in clause:
                    local = clause.split("* as ", 1)[1].strip()
                    names.append(local)
                    aliases.append(("*", local))
                elif clause:
                    local = clause.strip()
                    names.append(local)
                    aliases.append(("default", local))
                imports.append(
                    ImportFact(
                        module=mod,
                        names=tuple(names),
                        line=node.start_point.row + 1,
                        level=0,
                        aliases=tuple(aliases),
                    )
                )
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


__all__ = ["analyze_typescript"]
