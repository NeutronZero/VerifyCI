import time
from typing import Any, Optional

from src.contracts.entity import Entity, EntityType
from src.contracts.edge import Edge, EdgeType, CPGEdgeSubtype
from src.contracts.identity import compute_logical_entity_id, compute_revision_entity_id
from src.ingestion.parser import ParsedFile

CALL_NODES = ("call", "call_expression")
FUNC_NODES = ("function_definition", "function_declaration", "method_definition")
CLASS_NODES = ("class_definition", "class_specifier")


def _make_entity(
    repository_id: str, revision_id: str, file_path: str, name: str,
    entity_type: EntityType, language: str, source_hash: str,
    line_start: int, line_end: int, now: float, scope: str = "",
) -> Entity:
    logical_id = compute_logical_entity_id(repository_id, file_path, name, entity_type, scope)
    metadata = {"scope": scope} if scope else {}
    return Entity(
        repository_id=repository_id,
        logical_entity_id=logical_id,
        revision_entity_id=compute_revision_entity_id(logical_id, revision_id),
        type=entity_type,
        name=name,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        language=language,
        source_hash=source_hash,
        revision_id=revision_id,
        valid_from=now,
        t_created=now,
        metadata=metadata,
    )


def _make_edge(
    revision_id: str, src: str, dst: str,
    edge_type: EdgeType, subtype: CPGEdgeSubtype, now: float,
) -> Edge:
    short_rev = revision_id[:12]
    return Edge(
        id=f"edge_{short_rev}_{src}_{dst}_{edge_type.value}_{subtype.value}",
        revision_id=revision_id,
        src_entity_id=src,
        dst_entity_id=dst,
        type=edge_type,
        subtype=subtype,
        valid_from=now,
        observed_at=now,
        t_created=now,
    )


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _scope_name(node, source: bytes) -> Optional[str]:
    for child in node.children:
        if child.type in ("identifier", "type_identifier"):
            return _text(child, source)
    if node.type in FUNC_NODES:
        for child in node.children:
            if child.type in ("function_declarator", "declarator", "method_declarator"):
                found = _scope_name(child, source)
                if found:
                    return found
    return None


def _walk_scoped(node, source: bytes, stack: list[tuple[str, str]]):
    """Yield (node, enclosing stack). Stack entries are (kind, name) with
    kind in {"class", "func"}. A def node itself reports the outer stack;
    descendants see it pushed."""
    yield node, stack
    kind = "class" if node.type in CLASS_NODES else ("func" if node.type in FUNC_NODES else None)
    child_stack = stack
    if kind is not None:
        name = _scope_name(node, source)
        if name:
            child_stack = stack + [(kind, name)]
    for child in node.children:
        yield from _walk_scoped(child, source, child_stack)


def _classify_node(node, language: str, stack: Optional[list[tuple[str, str]]] = None) -> Optional[EntityType]:
    stack = stack or []
    if language == "python":
        if node.type == "function_definition":
            return EntityType.METHOD if stack and stack[-1][0] == "class" else EntityType.FUNCTION
        if node.type == "class_definition":
            return EntityType.CLASS
    elif language in ("c", "cpp"):
        if node.type == "function_definition":
            return EntityType.METHOD if stack and stack[-1][0] == "class" else EntityType.FUNCTION
        if node.type in ("class_specifier", "struct_specifier"):
            return EntityType.CLASS
    return None


def extract_entities(parsed: ParsedFile, repository_id: str, revision_id: str) -> list[Entity]:
    now = time.time()
    module = _make_entity(
        repository_id, revision_id, parsed.file_path, parsed.file_path,
        EntityType.MODULE, parsed.language, parsed.source_hash, 1, 1, now,
    )
    entities = [module]
    if parsed.tree is None:
        return entities

    root = parsed.tree.root_node
    for node, stack in _walk_scoped(root, parsed.source, []):
        entity_type = _classify_node(node, parsed.language, stack)
        if entity_type is None:
            continue
        name = _scope_name(node, parsed.source)
        if not name:
            continue
        scope = ".".join(n for _, n in stack)
        entities.append(_make_entity(
            repository_id, revision_id, parsed.file_path, name, entity_type,
            parsed.language, parsed.source_hash,
            node.start_point[0] + 1, node.end_point[0] + 1, now, scope,
        ))
        if entity_type in (EntityType.FUNCTION, EntityType.METHOD):
            param_scope = f"{scope}.{name}" if scope else name
            for pname in _extract_params(node, parsed.source, parsed.language):
                entities.append(_make_entity(
                    repository_id, revision_id, parsed.file_path, pname,
                    EntityType.PARAMETER, parsed.language, parsed.source_hash,
                    node.start_point[0] + 1, node.end_point[0] + 1, now, param_scope,
                ))

    for node in _walk(root):
        if node.type in ("import_statement", "import_from_statement"):
            module_name = _extract_import_module(node, parsed.source)
            if module_name:
                entities.append(_make_entity(
                    repository_id, revision_id, parsed.file_path, module_name,
                    EntityType.IMPORT, parsed.language, parsed.source_hash,
                    node.start_point[0] + 1, node.end_point[0] + 1, now,
                ))
    return entities


def extract_edges(parsed: ParsedFile, entities: list[Entity], revision_id: str) -> list[Edge]:
    now = time.time()
    edges: list[Edge] = []
    if parsed.tree is None:
        return edges

    by_name: dict[str, list[Entity]] = {}
    for e in entities:
        by_name.setdefault(e.name, []).append(e)
    modules = [e for e in entities if e.type == EntityType.MODULE]
    module = modules[0] if modules else None
    imports = [e for e in entities if e.type == EntityType.IMPORT]

    def scope_of(e: Entity) -> str:
        return (e.metadata or {}).get("scope", "")

    def resolve(name: str, caller_scope: str) -> Optional[Entity]:
        candidates = [c for c in by_name.get(name, [])
                      if c.type in (EntityType.FUNCTION, EntityType.METHOD, EntityType.CLASS)]
        if not candidates:
            return None
        for c in candidates:
            if scope_of(c) == caller_scope:
                return c
        for c in candidates:
            if not scope_of(c):
                return c
        return candidates[0]

    root = parsed.tree.root_node
    for node, stack in _walk_scoped(root, parsed.source, []):
        if node.type not in FUNC_NODES:
            continue
        caller_name = _scope_name(node, parsed.source)
        if not caller_name:
            continue
        caller_scope = ".".join(n for _, n in stack)
        caller = resolve(caller_name, caller_scope)
        if caller is None:
            continue
        for child in _walk(node):
            if child is node or child.type not in CALL_NODES:
                continue
            callee_name = _extract_callee_name(child, parsed.source)
            if not callee_name:
                continue
            callee = resolve(callee_name, caller_scope)
            if callee is None:
                continue
            if callee.revision_entity_id == caller.revision_entity_id:
                edges.append(_make_edge(
                    revision_id, caller.revision_entity_id, callee.revision_entity_id,
                    EdgeType.CALLS, CPGEdgeSubtype.CALLS_RECURSIVE, now))
            else:
                edges.append(_make_edge(
                    revision_id, caller.revision_entity_id, callee.revision_entity_id,
                    EdgeType.CALLS, CPGEdgeSubtype.CALLS_DIRECT, now))
                edges.append(_make_edge(
                    revision_id, caller.revision_entity_id, callee.revision_entity_id,
                    EdgeType.REFERENCES, CPGEdgeSubtype.REFERENCES, now))

    for node in _walk(root):
        if node.type in CLASS_NODES:
            class_name = _scope_name(node, parsed.source)
            candidates = by_name.get(class_name, []) if class_name else []
            cls = next((c for c in candidates if c.type == EntityType.CLASS), None)
            if cls:
                for child in node.children:
                    if child.type == "superclasses":
                        parents = [g for g in child.children if g.type == "identifier"]
                    elif child.type == "argument_list":
                        parents = [g for g in _walk(child) if g.type == "identifier"]
                    else:
                        continue
                    for parent_node in parents:
                        parent = resolve(_text(parent_node, parsed.source), scope_of(cls))
                        if parent:
                            edges.append(_make_edge(
                                revision_id, cls.revision_entity_id, parent.revision_entity_id,
                                EdgeType.INHERITS, CPGEdgeSubtype.INHERITS, now))

    if module is not None:
        for imp in imports:
            edges.append(_make_edge(
                revision_id, module.revision_entity_id, imp.revision_entity_id,
                EdgeType.IMPORTS, CPGEdgeSubtype.IMPORTS, now))
        for entity in entities:
            if entity.revision_entity_id == module.revision_entity_id:
                continue
            if entity.type in (EntityType.FUNCTION, EntityType.METHOD, EntityType.CLASS,
                               EntityType.TYPE, EntityType.VARIABLE):
                edges.append(_make_edge(
                    revision_id, module.revision_entity_id, entity.revision_entity_id,
                    EdgeType.CONTAINS, CPGEdgeSubtype.HAS_NAME, now))

    for parent in entities:
        for child in entities:
            if parent.revision_entity_id == child.revision_entity_id:
                continue
            if parent.file_path == child.file_path:
                if parent.line_start <= child.line_start and parent.line_end >= child.line_end:
                    if parent.type == EntityType.MODULE or (
                        parent.line_start != child.line_start or parent.line_end != child.line_end
                    ):
                        edges.append(_make_edge(
                            revision_id, parent.revision_entity_id, child.revision_entity_id,
                            EdgeType.CONTAINS, CPGEdgeSubtype.CONTAINS, now))
    return edges


def _extract_name(node, source: bytes, language: str = "python") -> Optional[str]:
    return _scope_name(node, source)


def _extract_params(node, source: bytes, language: str = "python") -> list[str]:
    params: list[str] = []
    if language in ("c", "cpp"):
        for child in node.children:
            if child.type in ("function_declarator", "declarator"):
                for decl in _walk(child):
                    if decl.type == "parameter_list":
                        for pdecl in decl.children:
                            if pdecl.type == "parameter_declaration":
                                name = _c_param_name(pdecl, source)
                                if name and name not in params:
                                    params.append(name)
        return params
    for child in node.children:
        if child.type == "parameters":
            for part in child.children:
                if part.type == "identifier":
                    text = _text(part, source)
                    if text not in params:
                        params.append(text)
                elif part.type in ("typed_parameter", "default_parameter", "typed_default_parameter"):
                    for sub in part.children:
                        if sub.type == "identifier":
                            text = _text(sub, source)
                            if text not in params:
                                params.append(text)
                            break
    return params


def _c_param_name(pdecl, source: bytes) -> Optional[str]:
    """Last bare identifier in a parameter declaration, skipping type nodes."""
    found = None
    for desc in _walk(pdecl):
        if desc.type == "identifier":
            found = _text(desc, source)
    return found


def _extract_callee_name(node, source: bytes) -> Optional[str]:
    for child in node.children:
        if child.type == "identifier":
            return _text(child, source)
    for child in node.children:
        if child.type in ("attribute", "field_expression", "scoped_identifier"):
            ids = [d for d in _walk(child) if d.type in ("identifier", "type_identifier", "field_identifier")]
            if ids:
                return _text(ids[-1], source)
    for desc in _walk(node):
        if desc.type in ("identifier", "field_identifier") and desc is not node:
            return _text(desc, source)
    return None


def _extract_import_module(node, source: bytes) -> Optional[str]:
    for child in node.children:
        if child.type == "dotted_name":
            return _text(child, source)
        if child.type == "aliased_import":
            for grandchild in child.children:
                if grandchild.type == "dotted_name":
                    return _text(grandchild, source)
    return None
