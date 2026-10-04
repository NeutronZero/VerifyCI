import time
from typing import Optional

from verifyci.contracts.entity import Entity, EntitySnippetRecord, EntityType
from verifyci.contracts.edge import Edge, EdgeType, CPGEdgeSubtype
from verifyci.contracts.identity import compute_logical_entity_id, compute_revision_entity_id
from verifyci.ingestion.file_slice import slice_source
from verifyci.ingestion.parser import ParsedFile

CALL_NODES = ("call", "call_expression")
FUNC_NODES = ("function_definition", "function_declaration", "method_definition")
CLASS_NODES = ("class_definition", "class_specifier", "struct_specifier")
#: Declarator node types that can wrap a C/C++ function name. Beyond the
#: plain trio, functions returning pointers/references nest the real
#: declarator inside pointer/reference wrappers — without these,
#: `char *f()` and `T& f()` emit no entity at all. Array/parenthesized
#: wrappers (`int f()[10]`, `int (f)(void)`) are included on the same
#: grounds; abstract declarators (no identifier inside) still yield
#: nothing, so function pointers stay silent.
DECLARATOR_TYPES = ("function_declarator", "declarator", "method_declarator",
                    "pointer_declarator", "reference_declarator",
                    "array_declarator", "parenthesized_declarator")


def _make_entity(
    repository_id: str, revision_id: str, file_path: str, name: str,
    entity_type: EntityType, language: str, source_hash: str,
    line_start: int, line_end: int, now: float, scope: str = "",
    snippet: str = "", identity_scope: Optional[str] = None,
    qualified_name: str = "",
    snippet_is_complete: bool = True,
    snippet_truncated_at_line: Optional[int] = None,
    signature: str = "",
    accessor: str = "",
    slices: Optional[list[str]] = None,
) -> Entity:
    # identity_scope pins the logical id: namespace entries are filtered
    # out of it, so wrapping code in `namespace ns {}` renames nothing
    # already stored. `scope` (full path, namespaces included) travels in
    # metadata for scope-aware matching; `qualified_name` ("ns::Base",
    # C/C++ only) is the canonical name the deferred resolver matches
    # qualified references against.
    lid_scope = scope if identity_scope is None else identity_scope
    logical_id = compute_logical_entity_id(
        repository_id, file_path, name, entity_type, lid_scope, signature=signature
    )
    metadata = {"scope": scope} if scope else {}
    if qualified_name:
        metadata["qualified_name"] = qualified_name
    if snippet:
        metadata["snippet"] = snippet
        metadata["snippet_is_complete"] = snippet_is_complete
        if snippet_truncated_at_line is not None:
            metadata["snippet_truncated_at_line"] = snippet_truncated_at_line
        metadata["snippet_char_count"] = len(snippet)
    if slices:
        metadata["slices"] = list(slices)
    if accessor:
        metadata["accessor"] = accessor
    if signature:
        metadata["signature"] = signature
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


def _make_unresolved(
    revision_id: str, src: str, kind: str, name: str, scope: str,
    now: float, site: str = "",
) -> Edge:
    """A reference the current file cannot resolve: calls to functions
    defined (or only declared) elsewhere, bases from other headers.
    `dst_entity_id` stays empty so the builder never links it; the
    post-build resolver fills it in when the name is unambiguous.
    """
    if kind == "inherits":
        edge_type: EdgeType = EdgeType.INHERITS_UNRESOLVED
        meta = {"base": name, "scope": scope}
        eid = f"edge_{revision_id[:12]}_{src}_unresolved_inherits_{name}"
    else:
        edge_type = EdgeType.CALLS_UNRESOLVED
        meta = {"callee": name, "caller_scope": scope}
        eid = f"edge_{revision_id[:12]}_{src}_unresolved_calls_{name}_{site}"
    return Edge(
        id=eid,
        revision_id=revision_id,
        src_entity_id=src,
        dst_entity_id="",
        type=edge_type,
        subtype=None,
        valid_from=now,
        observed_at=now,
        t_created=now,
        metadata=meta,
    )


def _make_edge(
    revision_id: str, src: str, dst: str,
    edge_type: EdgeType, subtype: CPGEdgeSubtype, now: float,
    site: str = "",
) -> Edge:
    # `site` (e.g. call-site line) keeps parallel edges distinct so call-site
    # multiplicity survives; structural edges share one row per pair.
    site_suffix = f"_{site}" if site else ""
    return Edge(
        id=f"edge_{revision_id[:12]}_{src}_{dst}_{edge_type.value}_{subtype.value}{site_suffix}",
        revision_id=revision_id,
        src_entity_id=src,
        dst_entity_id=dst,
        type=edge_type,
        subtype=subtype,
        valid_from=now,
        observed_at=now,
        t_created=now,
    )


def _node_key(node) -> tuple[str, int, int]:
    """Stable node identity: py-tree-sitter wrapper objects are recreated
    per access (``node.parent`` / ``node.child`` return distinct objects
    for the same node), so the builtin object identity is unstable and
    recyclable after GC. ``(type, start_byte, end_byte)`` is stable
    across wrappers."""
    return (node.type, node.start_byte, node.end_byte)


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _split_source_lines(source: bytes) -> list[str]:
    """Split exactly the way tree-sitter and git count lines: on `\n`
    only, with a trailing `\r` stripped per line. `str.splitlines()`
    also splits on `\x0b\x0c\u2028\u2029`, which misaligns stored
    snippets against both the AST and the diff for files containing
    form feeds — removal provenance then hallucinated "fabricated"
    verdicts on honest diffs."""
    return [line[:-1] if line.endswith("\r") else line
            for line in source.decode("utf-8", errors="replace").split("\n")]


def _source_snippet_record(
    source: bytes, line_start: int, line_end: int, limit: int = 2000
) -> EntitySnippetRecord:
    """Citeable source fragment record stored at ingest time. Truncates
    strictly at a newline boundary when exceeding limit."""
    try:
        if line_start <= 0 and line_end <= 0:
            return EntitySnippetRecord(
                lines=(),
                is_complete=True,
                truncated_at_line=None,
                char_count=0,
                encoding="utf-8",
            )
        lines = _split_source_lines(source)
        eff_start = max(1, line_start)
        if eff_start > line_end or eff_start > len(lines):
            return EntitySnippetRecord(
                lines=(),
                is_complete=True,
                truncated_at_line=None,
                char_count=0,
                encoding="utf-8",
            )
        start_idx = eff_start - 1
        end_idx = max(0, line_end)
        span_lines = lines[start_idx:end_idx]
        span = line_end - eff_start + 1

        kept_lines: list[str] = []
        current_len = 0
        for line in span_lines:
            add_len = len(line) + (1 if kept_lines else 0)
            if current_len + add_len <= limit:
                kept_lines.append(line)
                current_len += add_len
            else:
                break

        is_complete = len(kept_lines) == span
        truncated_at_line = None if is_complete else (eff_start + len(kept_lines))
        return EntitySnippetRecord(
            lines=kept_lines,
            is_complete=is_complete,
            truncated_at_line=truncated_at_line,
            char_count=current_len,
            encoding="utf-8",
        )
    except Exception:  # noqa: BLE001, S110
        return EntitySnippetRecord(
            lines=(),
            is_complete=False,
            truncated_at_line=max(1, line_start) if line_start > 0 else None,
            char_count=0,
            encoding="utf-8",
        )


def _source_snippet(source: bytes, line_start: int, line_end: int, limit: int = 2000) -> str:
    """Citeable source fragment stored at ingest time, so evidence never
    depends on the working tree still containing the file."""
    return _source_snippet_record(source, line_start, line_end, limit=limit).text


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _walk_pruned(node):
    """Walk a function body for call sites without descending into
    nested named definitions. A nested `def inner` is visited as its
    own entity; descending into it here attributes every inner call to
    the outer function too (double count). Lambdas and comprehensions
    are anonymous and stay in scope."""
    for child in node.children:
        if child.type in FUNC_NODES or child.type in CLASS_NODES:
            continue
        yield child
        yield from _walk_pruned(child)


def _find_qualified(node):
    """First qualified/scoped identifier under a declarator, walking down
    through ``pointer_declarator`` / ``reference_declarator`` (and
    ``function_declarator`` etc.) wrappers. Breadth-first in source order:
    the name's own qualifier is found before anything deeper, and the
    descent never enters ``parameter_list``, so qualified parameter types
    (``void f(ns::T x)``) cannot shadow the function name."""
    from collections import deque
    queue = deque([node])
    while queue:
        cur = queue.popleft()
        for child in cur.children:
            if child.type in ("qualified_identifier", "scoped_identifier"):
                return child
        for child in cur.children:
            if child.type in DECLARATOR_TYPES:
                queue.append(child)
    return None


def _qualified_name(node, source: bytes) -> Optional[tuple[str, str]]:
    """(qualifier, name) for `App::run`-style declarators, else None.

    The declarator holds a `qualified_identifier` (this grammar version;
    others emit `scoped_identifier`) whose parts are the scope chain plus
    the name: `App::run` -> ("App", "run"). Pointer/reference returns
    (`Foo* Foo::create()`) nest it one level down, so the whole
    declarator spine is searched. A single part (`::run`) or no
    qualified node means "no qualifier here", not "unnamed".
    """
    found = _find_qualified(node)
    if found is None:
        return None
    raw = _qualified_raw(found, source)
    if not raw:
        return None
    parts = raw.lstrip(":").split("::")
    if len(parts) >= 2:
        return "::".join(parts[:-1]), parts[-1]
    return None


def _scope_name(node, source: bytes, language: str = "python") -> Optional[str]:
    if node.type in FUNC_NODES:
        # Direct `identifier` is the name in Python. In C/C++ the name lives
        # inside the declarator, and a bare direct identifier on a C/C++
        # function node is a grammar misparsing (e.g. `enum class X {}`
        # parsed as a function_definition whose "name" is the enum tag) —
        # never trust it, so it is not even a fallback there.
        for child in node.children:
            if child.type in DECLARATOR_TYPES:
                qualified = _qualified_name(child, source)
                if qualified is not None:
                    return qualified[1]
                found = _scope_name(child, source, language)
                if found:
                    return found
        if language == "python":
            for child in node.children:
                if child.type == "identifier":
                    return _text(child, source)
        return None
    if node.type in DECLARATOR_TYPES:
        # A qualified name nested anywhere down the declarator spine
        # (`Foo* Foo::create()`) is the name; without this the recursion
        # below finds no bare identifier and the entity is dropped.
        qualified = _qualified_name(node, source)
        if qualified is not None:
            return qualified[1]
        for child in node.children:
            if child.type in DECLARATOR_TYPES:
                found = _scope_name(child, source, language)
                if found:
                    return found
        for child in node.children:
            # Destructors and operators have neither identifier nor
            # qualified node: `~W` and `operator==` are the whole name.
            # field_identifier marks in-class members; it is safe here
            # because declarations (field_declaration nodes) never reach
            # this frame — only definitions do.
            if child.type in ("destructor_name", "operator_name"):
                return _text(child, source)
            if child.type in ("identifier", "type_identifier", "field_identifier"):
                return _text(child, source)
        return None
    if node.type == "type_definition":
        # C typedef names the NEW type: `typedef Bar Baz` defines Baz.
        # First-identifier-wins named the old type.
        found = None
        for child in node.children:
            if child.type in ("identifier", "type_identifier"):
                found = _text(child, source)
        return found
    for child in node.children:
        if child.type in ("identifier", "type_identifier"):
            return _text(child, source)
    return None


def _qualified_raw(node, source: bytes) -> Optional[str]:
    """Raw qualified token sequence (`ns::Base`, `::Global`) for a
    qualified/scoped identifier node, else None. Whitespace around `::`
    is normalized away; a leading `::` (global scope anchor) is kept."""
    parts = [
        _text(c, source) for c in node.children
        if c.type in ("identifier", "type_identifier", "namespace_identifier",
                      "field_identifier", "destructor_name")
    ]
    if not parts:
        return None
    text = _text(node, source).lstrip()
    return ("::" if text.startswith("::") else "") + "::".join(parts)


def _qualified_scope(node, source: bytes) -> str:
    """Out-of-class scope for `void App::run() {}`: "App", else "".

    A definition qualified with its class is a method of that class even
    though the AST stack is empty at namespace scope. Drives both the
    METHOD classification and the entity scope, so the definition and its
    intra-class callers resolve against each other.
    """
    if node.type not in FUNC_NODES:
        return ""
    for child in node.children:
        if child.type in DECLARATOR_TYPES:
            qualified = _qualified_name(child, source)
            if qualified is not None:
                return qualified[0]
    return ""


def _ns_name(node, source: bytes) -> Optional[str]:
    """Name of a `namespace_definition`, or None for anonymous ones."""
    if node.type != "namespace_definition":
        return None
    for child in node.children:
        if child.type in ("namespace_identifier", "identifier"):
            return _text(child, source)
    return None


def _walk_scoped(node, source: bytes, stack: list[tuple[str, str]],
                 language: str = "python"):
    """Yield (node, enclosing stack). Stack entries are (kind, name) with
    kind in {"class", "func", "ns"}. A def node itself reports the outer
    stack; descendants see it pushed. Namespace entries feed qualified
    naming only — they are filtered out of identity scopes so logical
    ids stay stable for code that never moved."""
    yield node, stack
    kind = "class" if node.type in CLASS_NODES else ("func" if node.type in FUNC_NODES else None)
    child_stack = stack
    if kind is not None:
        name = _scope_name(node, source, language)
        if name:
            child_stack = stack + [(kind, name)]
    elif node.type == "namespace_definition":
        name = _ns_name(node, source)
        if name:
            child_stack = stack + [("ns", name)]
    for child in node.children:
        yield from _walk_scoped(child, source, child_stack, language)


def _classify_node(node, language: str, stack: Optional[list[tuple[str, str]]] = None,
                   qualified_scope: str = "") -> Optional[EntityType]:
    stack = stack or []
    if language == "python":
        if node.type == "function_definition":
            return EntityType.METHOD if stack and stack[-1][0] == "class" else EntityType.FUNCTION
        if node.type == "class_definition":
            return EntityType.CLASS
    elif language in ("c", "cpp"):
        if node.type == "function_definition":
            # `void App::run() {}` at namespace scope is a method of App,
            # not a free function: the qualifier is the scope the AST
            # stack cannot see.
            if qualified_scope or (stack and stack[-1][0] == "class"):
                return EntityType.METHOD
            return EntityType.FUNCTION
        if node.type in ("class_specifier", "struct_specifier"):
            # A bare `struct Foo` in type position (elaborated type
            # specifier, forward declaration) is a *reference*, not a
            # definition. Only a body makes it an entity.
            if not any(c.type == "field_declaration_list" for c in node.children):
                return None
            return EntityType.CLASS
        if node.type == "type_definition":
            return EntityType.TYPE
    return None


def _extract_param_types(node, source: bytes) -> list[str]:
    """Extract canonicalized C/C++ parameter types in declaration order.
    Parameter names are strictly excluded. Pointer/ref spacing and const
    qualifiers are normalized. void f(void) is normalized to empty [].
    Templates are deferred to V1.2.
    """
    param_list = None
    for child in _walk(node):
        if child.type == "parameter_list":
            param_list = child
            break
    if param_list is None:
        return []
    types = []
    for p in param_list.children:
        if p.type != "parameter_declaration":
            continue
        is_const = False
        type_parts = []
        is_ptr = 0
        is_ref = 0
        for c in p.children:
            if c.type == "type_qualifier" and "const" in _text(c, source):
                is_const = True
            elif c.type in ("primitive_type", "type_identifier", "sized_type_specifier"):
                t_str = _text(c, source).strip()
                if "const" in t_str.split():
                    is_const = True
                    t_str = " ".join(part for part in t_str.split() if part != "const")
                type_parts.append(t_str)
            elif c.type in ("pointer_declarator", "abstract_pointer_declarator"):
                for sc in _walk(c):
                    if sc.type == "*":
                        is_ptr += 1
            elif c.type in ("reference_declarator", "abstract_reference_declarator"):
                for sc in _walk(c):
                    if sc.type == "&":
                        is_ref += 1
        base_type = " ".join(type_parts).strip()
        if not base_type:
            continue
        # C void parameter list: void f(void) -> empty
        if base_type == "void" and is_ptr == 0 and is_ref == 0:
            continue
        type_str = ("const " if is_const else "") + base_type + ("*" * is_ptr) + ("&" * is_ref)
        types.append(type_str)
    return types


def extract_entities(parsed: ParsedFile, repository_id: str, revision_id: str) -> list[Entity]:
    now = time.time()
    num_lines = max(1, len(parsed.source.splitlines()))
    module = _make_entity(
        repository_id, revision_id, parsed.file_path, parsed.file_path,
        EntityType.MODULE, parsed.language, parsed.source_hash, 1, num_lines, now,
    )
    entities = [module]
    if parsed.tree is None:
        return entities

    root = parsed.tree.root_node
    parents = {}
    for node in _walk(root):
        for child in node.children:
            parents[_node_key(child)] = node

    is_c_like = parsed.language in ("c", "cpp")
    for node, stack in _walk_scoped(root, parsed.source, [], parsed.language):
        qualified_scope = (
            _qualified_scope(node, parsed.source) if is_c_like else ""
        )
        entity_type = _classify_node(node, parsed.language, stack, qualified_scope)
        if entity_type is None:
            continue
        name = _scope_name(node, parsed.source, parsed.language)
        if not name:
            continue
        scope = qualified_scope or ".".join(n for _, n in stack)
        identity_scope = qualified_scope or ".".join(
            n for k, n in stack if k != "ns")
        qualified_name = ""
        if is_c_like and (qualified_scope or any(k == "ns" for k, _ in stack)):
            qparts = ([qualified_scope] if qualified_scope
                      else [n for _, n in stack])
            qualified_name = "::".join(qparts + [name])

        # G-01: Inherit decorator start line if wrapped in decorated_definition
        parent = parents.get(_node_key(node))
        if parent is not None and parent.type == "decorated_definition":
            line_start = parent.start_point[0] + 1
        else:
            line_start = node.start_point[0] + 1
        line_end = node.end_point[0] + 1
        snip_rec = _source_snippet_record(parsed.source, line_start, line_end)
        slices = None
        snippet_text = snip_rec.text
        if not snip_rec.is_complete:
            raw_slices = slice_source(parsed.source, line_start, line_end, max_chars=2000)
            if len(raw_slices) > 1:
                snippet_text = raw_slices[0]
                slices = raw_slices[1:]
                snip_rec = EntitySnippetRecord(
                    lines=snip_rec.lines,
                    is_complete=True,
                    truncated_at_line=None,
                    char_count=snip_rec.char_count,
                    encoding="utf-8",
                    slices=tuple(slices),
                )

        # G-02: Overload and property accessor disambiguation
        signature = ""
        accessor = ""
        if is_c_like and entity_type in (EntityType.FUNCTION, EntityType.METHOD):
            param_types = _extract_param_types(node, parsed.source)
            signature = ", ".join(param_types)
        elif parsed.language == "python" and parent is not None and parent.type == "decorated_definition":
            for dec in parent.children:
                if dec.type == "decorator":
                    dec_text = _text(dec, parsed.source).strip()
                    if dec_text == "@property":
                        accessor = "getter"
                        signature = "getter"
                        break
                    elif dec_text.endswith(".setter"):
                        accessor = "setter"
                        signature = "setter"
                        break
                    elif dec_text.endswith(".deleter"):
                        accessor = "deleter"
                        signature = "deleter"
                        break

        entities.append(_make_entity(
            repository_id, revision_id, parsed.file_path, name, entity_type,
            parsed.language, parsed.source_hash,
            line_start, line_end, now, scope,
            snippet=snippet_text,
            identity_scope=identity_scope,
            qualified_name=qualified_name,
            snippet_is_complete=snip_rec.is_complete,
            snippet_truncated_at_line=snip_rec.truncated_at_line,
            signature=signature,
            accessor=accessor,
            slices=list(snip_rec.slices) if snip_rec.slices else None,
        ))
        if entity_type in (EntityType.FUNCTION, EntityType.METHOD):
            param_scope = f"{identity_scope}.{name}" if identity_scope else name
            for pname in _extract_params(node, parsed.source, parsed.language):
                entities.append(_make_entity(
                    repository_id, revision_id, parsed.file_path, pname,
                    EntityType.PARAMETER, parsed.language, parsed.source_hash,
                    line_start, line_end, now, param_scope,
                ))

    seen_imports = set()
    for node in _walk(root):
        if node.type in ("import_statement", "import_from_statement"):
            # One statement can import several modules (`import os, sys`);
            # taking only the first silently drops the rest.
            for module_name in _extract_import_modules(node, parsed.source):
                if module_name and module_name not in seen_imports:
                    seen_imports.add(module_name)
                    entities.append(_make_entity(
                        repository_id, revision_id, parsed.file_path, module_name,
                        EntityType.IMPORT, parsed.language, parsed.source_hash,
                        node.start_point[0] + 1, node.end_point[0] + 1, now,
                    ))
        elif node.type == "preproc_include" and parsed.language in ("c", "cpp"):
            # `#include <flask.h>` / `#include "util.h"`: without this,
            # C/C++ translation units have no IMPORT entities and
            # forbid_import cannot work for C at all.
            header = _include_header(node, parsed.source)
            if header and header not in seen_imports:
                seen_imports.add(header)
                line_end = node.end_point[0] if (node.end_point[1] == 0 and node.end_point[0] > node.start_point[0]) else node.end_point[0] + 1
                entities.append(_make_entity(
                    repository_id, revision_id, parsed.file_path, header,
                    EntityType.IMPORT, parsed.language, parsed.source_hash,
                    node.start_point[0] + 1, line_end, now,
                ))
    return entities


def _include_header(node, source: bytes) -> Optional[str]:
    parts = [
        _text(c, source).strip().strip("<>\"' \t")
        for c in node.children
        if c.type in ("string_literal", "system_lib_string")
    ]
    return parts[-1] if parts else None


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
        if len(candidates) <= 1:
            return candidates[0] if candidates else None
        for c in candidates:
            if scope_of(c) == caller_scope:
                return c
        unscoped = [c for c in candidates if not scope_of(c)]
        if len(unscoped) == 1:
            return unscoped[0]
        # Several same-named candidates, none matching the caller's
        # scope and no unique top-level fallback: any pick is a guess,
        # and a wrong link invents impact while a missing one merely
        # undercounts it. Emit unresolved; the post-build resolver
        # links it only when exactly one entity with that name exists
        # anywhere, else it stays unlinked.
        return None

    def _emit_call(caller: Entity, caller_scope: str, site_node) -> None:
        callee_name = _extract_callee_name(site_node, parsed.source)
        if not callee_name:
            return
        callee = resolve(callee_name, caller_scope)
        site = f"{site_node.start_point[0] + 1}:{site_node.start_byte}"
        if callee is None:
            # Callee not defined in this file: emit an unresolved
            # reference, not silence. A post-build resolver links it
            # when exactly one entity with that name exists anywhere;
            # builtins and ambiguous names stay unlinked.
            edges.append(_make_unresolved(
                revision_id, caller.revision_entity_id, "calls",
                callee_name, caller_scope, now, site))
            return
        if callee.revision_entity_id == caller.revision_entity_id:
            edges.append(_make_edge(
                revision_id, caller.revision_entity_id, callee.revision_entity_id,
                EdgeType.CALLS, CPGEdgeSubtype.CALLS_RECURSIVE, now, site))
        else:
            edges.append(_make_edge(
                revision_id, caller.revision_entity_id, callee.revision_entity_id,
                EdgeType.CALLS, CPGEdgeSubtype.CALLS_DIRECT, now, site))
            edges.append(_make_edge(
                revision_id, caller.revision_entity_id, callee.revision_entity_id,
                EdgeType.REFERENCES, CPGEdgeSubtype.REFERENCES, now, site))

    root = parsed.tree.root_node
    parents = {}
    for _n in _walk(root):
        for _c in _n.children:
            parents.setdefault(_node_key(_c), _n)

    decorated_sites: set[tuple[str, int, int]] = set()
    for node, stack in _walk_scoped(root, parsed.source, [], parsed.language):
        if node.type not in FUNC_NODES:
            continue
        caller_name = _scope_name(node, parsed.source, parsed.language)
        if not caller_name:
            continue
        caller_scope = (
            _qualified_scope(node, parsed.source)
            or ".".join(n for _, n in stack)
        )
        caller = resolve(caller_name, caller_scope)
        if caller is None:
            continue
        for child in _walk_pruned(node):
            if child.type not in CALL_NODES:
                continue
            _emit_call(caller, caller_scope, child)
        # Decorators live on the parent decorated_definition, outside
        # the function body — without this, `@app.route(...)` calls
        # are never captured at all.
        parent = parents.get(_node_key(node))
        if parent is not None and parent.type == "decorated_definition":
            for dec in parent.children:
                if dec.type != "decorator":
                    continue
                for site_node in _walk(dec):
                    if site_node.type in CALL_NODES:
                        decorated_sites.add(_node_key(site_node))
                        _emit_call(caller, caller_scope, site_node)

    # Module- and class-body calls (`if __name__ == "__main__": main()`,
    # `x = compute()` in a class body) execute but belong to no function.
    # Attribute them to the innermost enclosing class, else the module —
    # previously they produced no edge at all.
    for node, stack in _walk_scoped(root, parsed.source, [], parsed.language):
        if node.type not in CALL_NODES or _node_key(node) in decorated_sites:
            continue
        if any(kind == "func" for kind, _ in stack):
            continue  # attributed to the enclosing function above
        names = [n for _, n in stack]
        class_names = [n for kind, n in stack if kind == "class"]
        if class_names:
            caller = resolve(class_names[-1], ".".join(names[:-1]))
            caller_scope = ".".join(names[:-1])
        else:
            caller, caller_scope = module, ""
        if caller is None:
            continue
        _emit_call(caller, caller_scope, node)

    for node in _walk(root):
        if node.type in CLASS_NODES:
            class_name = _scope_name(node, parsed.source)
            candidates = by_name.get(class_name, []) if class_name else []
            cls = next((c for c in candidates if c.type == EntityType.CLASS), None)
            if cls:
                for child in node.children:
                    if child.type == "superclasses":
                        parent_names = [_text(g, parsed.source)
                                        for g in child.children if g.type == "identifier"]
                    elif child.type == "base_class_clause":
                        # C++: `class App : public Base, protected Mixin`.
                        # Direct children only — a _walk would also catch
                        # template arguments (`Base<T>` yields T) as bogus
                        # parents. Qualified bases keep their raw token
                        # sequence (`ns::Base`, `::Global`) for the
                        # deferred resolver to match canonically.
                        parent_names = []
                        for g in child.children:
                            if g.type in ("identifier", "type_identifier"):
                                parent_names.append(_text(g, parsed.source))
                            elif g.type in ("qualified_identifier", "scoped_identifier"):
                                q = _qualified_raw(g, parsed.source)
                                if q:
                                    parent_names.append(q)
                    elif child.type == "argument_list":
                        parent_names = [_text(g, parsed.source)
                                        for g in _walk(child) if g.type == "identifier"]
                    else:
                        continue
                    for parent_name in parent_names:
                        # Qualified refs resolve only by canonical name in
                        # the deferred pass: a same-file bare `Base` must
                        # not capture an `ns::Base` reference.
                        parent = resolve(parent_name, scope_of(cls))
                        if parent:
                            edges.append(_make_edge(
                                revision_id, cls.revision_entity_id, parent.revision_entity_id,
                                EdgeType.INHERITS, CPGEdgeSubtype.INHERITS, now))
                        else:
                            edges.append(_make_unresolved(
                                revision_id, cls.revision_entity_id, "inherits",
                                parent_name, scope_of(cls), now))

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
            if child.type == EntityType.MODULE:
                continue
            if parent.file_path == child.file_path:
                if (parent.type in (EntityType.FUNCTION, EntityType.METHOD)
                        and child.type == EntityType.PARAMETER):
                    parent_scope = f"{scope_of(parent)}.{parent.name}" if scope_of(parent) else parent.name
                    if scope_of(child) == parent_scope:
                        edges.append(_make_edge(
                            revision_id, parent.revision_entity_id, child.revision_entity_id,
                            EdgeType.CONTAINS, CPGEdgeSubtype.CONTAINS, now))
                elif parent.line_start <= child.line_start and parent.line_end >= child.line_end:
                    if parent.type == EntityType.MODULE or (
                        parent.line_start != child.line_start or parent.line_end != child.line_end
                    ):
                        edges.append(_make_edge(
                            revision_id, parent.revision_entity_id, child.revision_entity_id,
                            EdgeType.CONTAINS, CPGEdgeSubtype.CONTAINS, now))
    return edges


def _extract_params(node, source: bytes, language: str = "python") -> list[str]:
    params: list[str] = []
    if language in ("c", "cpp"):
        for child in node.children:
            if child.type in DECLARATOR_TYPES:
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


def _extract_import_modules(node, source: bytes) -> list[str]:
    if node.type == "import_statement":
        modules = []
        for child in node.children:
            if child.type == "dotted_name":
                modules.append(_text(child, source))
            elif child.type == "aliased_import":
                for grandchild in child.children:
                    if grandchild.type == "dotted_name":
                        modules.append(_text(grandchild, source))
                        break
        return modules
    # import_from_statement: the module precedes the `import` keyword, either
    # as a relative_import (`from ..config import X`) or a dotted_name
    # (`from flask import X`). Names after the keyword are imported symbols,
    # never the module — taking them misattributes the edge.
    seen_import_kw = False
    for child in node.children:
        if child.type == "import":
            seen_import_kw = True
            continue
        if child.type == "relative_import":
            found = _relative_module(child, source)
            return [found] if found else []
        if child.type == "dotted_name" and not seen_import_kw:
            return [_text(child, source)]
        if child.type == "aliased_import" and not seen_import_kw:
            for grandchild in child.children:
                if grandchild.type == "dotted_name":
                    return [_text(grandchild, source)]
    return []


def _relative_module(node, source: bytes) -> Optional[str]:
    dots = 0
    mod = None
    for child in node.children:
        if child.type == "import_prefix":
            dots = _text(child, source).count(".")
        elif child.type == "dotted_name" and mod is None:
            mod = _text(child, source)
    if mod:
        return "." * dots + mod
    return "." * dots if dots else None
