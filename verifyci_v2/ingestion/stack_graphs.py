from __future__ import annotations

try:
    from verifyci_v2.ingestion.ts_symbols import extract_defs_and_calls as _ts_extract
except Exception:  # pragma: no cover
    _ts_extract = None

import ast
import functools
import re
from typing import Any, Iterable

from verifyci_v2.contracts.canonical import blake3_hex, xxh3_64_hex
from verifyci_v2.contracts.ssa_ir import (
    FileStackGraph,
    StackGraphEdge,
    StackGraphNode,
)

_TS_FUNC_RE = re.compile(
    r"(?P<export>export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\(",
    re.MULTILINE,
)
_TS_IMPORT_RE = re.compile(
    r"import\s+\{(?P<syms>[^}]+)\}\s+from\s+['\"](?P<mod>[^'\"]+)['\"]",
    re.MULTILINE,
)
_C_FUNC_RE = re.compile(
    r"^(?:[A-Za-z_][\w\s\*]+?)\s+(?P<name>[A-Za-z_]\w*)\s*\([^;]*\)\s*\{",
    re.MULTILINE,
)
_GENERIC_CALL_RE = re.compile(r"\b(?P<callee>[A-Za-z_][\w\.]*)\s*\(")
_CONTROL_KEYWORDS = frozenset(
    {"if", "for", "while", "switch", "return", "catch", "sizeof", "typeof"}
)


@functools.lru_cache(maxsize=4096)
def _module_prefix_from_path(file_path: str) -> str:
    cleaned = file_path.replace("\\", "/").lstrip("./")
    for ext in (".py", ".ts", ".tsx", ".js", ".jsx", ".c", ".cpp", ".h", ".rs", ".go"):
        if cleaned.endswith(ext):
            cleaned = cleaned[: -len(ext)]
            break
    return cleaned.replace("/", ".")


def _strip_comments_and_strings(src: str) -> str:
    def repl(m: re.Match[str]) -> str:
        return "\n" * m.group(0).count("\n")

    src = re.sub(r"/\*.*?\*/", repl, src, flags=re.DOTALL)
    src = re.sub(r"//[^\n]*", "", src)
    src = re.sub(r'"(?:\\.|[^"\\])*"', '""', src)
    src = re.sub(r"'(?:\\.|[^'\\])*'", "''", src)
    src = re.sub(r"`(?:\\.|[^`\\])*`", repl, src, flags=re.DOTALL)
    return src


def build_file_stack_graph(
    file_path: str, source: str, language: str = "python"
) -> FileStackGraph:
    """Computes a per-file scope graph with PUSH_SYMBOL and POP_SYMBOL nodes in isolation."""
    file_xxh3 = xxh3_64_hex(source)
    mod_prefix = _module_prefix_from_path(file_path)
    root_id = f"{file_path}::ROOT"

    nodes: list[StackGraphNode] = [
        StackGraphNode(
            node_id=root_id,
            file_path=file_path,
            kind="ROOT",
            symbol=mod_prefix,
            qualified_name=mod_prefix,
            line=1,
            is_exported=True,
        )
    ]
    edges: list[StackGraphEdge] = []
    defined: list[str] = []
    referenced: set[str] = set()
    imports: list[tuple[str, str]] = []

    if language == "python":
        tree = ast.parse(source, filename=file_path)
        explicit_exports: set[str] | None = None
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == "__all__":
                        if isinstance(stmt.value, (ast.List, ast.Tuple)):
                            explicit_exports = {
                                elt.value
                                for elt in stmt.value.elts
                                if isinstance(elt, ast.Constant)
                                and isinstance(elt.value, str)
                            }

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    imports.append((local_name, alias.name))
            elif isinstance(node, ast.ImportFrom):
                base_mod = node.module or ""
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    target = f"{base_mod}.{alias.name}" if base_mod else alias.name
                    imports.append((local_name, target))

        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                sym = stmt.name
                qname = f"{mod_prefix}.{sym}"
                is_exp = (
                    sym in explicit_exports
                    if explicit_exports is not None
                    else not sym.startswith("_")
                )
                pop_id = f"{file_path}::POP::{qname}"
                nodes.append(
                    StackGraphNode(
                        node_id=pop_id,
                        file_path=file_path,
                        kind="POP_SYMBOL",
                        symbol=sym,
                        qualified_name=qname,
                        line=stmt.lineno,
                        is_exported=is_exp,
                    )
                )
                edges.append(
                    StackGraphEdge(src_id=root_id, dst_id=pop_id, precedence=1)
                )
                defined.append(qname)

                for child in ast.walk(stmt):
                    if isinstance(child, ast.Call):
                        callee_name: str | None = None
                        if isinstance(child.func, ast.Name):
                            callee_name = child.func.id
                        elif isinstance(child.func, ast.Attribute):
                            if isinstance(child.func.value, ast.Name):
                                callee_name = f"{child.func.value.id}.{child.func.attr}"
                            else:
                                callee_name = child.func.attr
                        if callee_name:
                            referenced.add(callee_name)
                            push_id = f"{file_path}::PUSH::{qname}::{callee_name}::{getattr(child, 'lineno', stmt.lineno)}"
                            nodes.append(
                                StackGraphNode(
                                    node_id=push_id,
                                    file_path=file_path,
                                    kind="PUSH_SYMBOL",
                                    symbol=callee_name,
                                    qualified_name=qname,
                                    line=getattr(child, "lineno", stmt.lineno),
                                    is_exported=False,
                                )
                            )
                            edges.append(
                                StackGraphEdge(
                                    src_id=pop_id, dst_id=push_id, precedence=1
                                )
                            )
    else:
        # Polyglot extraction. Prefer tree-sitter CST parsing when available
        # (spec Sec. 3.2); fall back to the legacy regex extractors otherwise
        # so behaviour is preserved on inputs the parser cannot handle.
        clean_source = _strip_comments_and_strings(source)
        _ts_defs = None
        if _ts_extract is not None:
            try:
                _ts_defs, _ts_calls = _ts_extract(language, source)
            except Exception:
                _ts_defs = None
        if _ts_defs is not None and len(_ts_defs) >= 0:
            if language in ("typescript", "javascript"):
                for match in _TS_IMPORT_RE.finditer(clean_source):
                    mod = match.group("mod").lstrip("./").replace("/", ".")
                    for raw_sym in match.group("syms").split(","):
                        sym = raw_sym.strip()
                        if sym:
                            imports.append((sym, f"{mod}.{sym}"))
            for sym, line, is_exp in _ts_defs:
                qname = f"{mod_prefix}.{sym}"
                pop_id = f"{file_path}::POP::{qname}"
                nodes.append(
                    StackGraphNode(
                        node_id=pop_id,
                        file_path=file_path,
                        kind="POP_SYMBOL",
                        symbol=sym,
                        qualified_name=qname,
                        line=line,
                        is_exported=is_exp,
                    )
                )
                edges.append(StackGraphEdge(src_id=root_id, dst_id=pop_id, precedence=1))
                defined.append(qname)
                for callee, call_line in _ts_calls.get(sym, []):
                    if callee in _CONTROL_KEYWORDS or callee == sym:
                        continue
                    referenced.add(callee)
                    push_id = f"{file_path}::PUSH::{qname}::{callee}::{call_line}"
                    nodes.append(
                        StackGraphNode(
                            node_id=push_id,
                            file_path=file_path,
                            kind="PUSH_SYMBOL",
                            symbol=callee,
                            qualified_name=qname,
                            line=call_line,
                            is_exported=False,
                        )
                    )
                    edges.append(
                        StackGraphEdge(src_id=pop_id, dst_id=push_id, precedence=1)
                    )
        else:
            if language in ("typescript", "javascript"):
                for match in _TS_IMPORT_RE.finditer(clean_source):
                    mod = match.group("mod").lstrip("./").replace("/", ".")
                    for raw_sym in match.group("syms").split(","):
                        sym = raw_sym.strip()
                        if sym:
                            imports.append((sym, f"{mod}.{sym}"))
                func_matches = list(_TS_FUNC_RE.finditer(clean_source))
            else:
                func_matches = list(_C_FUNC_RE.finditer(clean_source))

            for idx, match in enumerate(func_matches):
                sym = match.group("name")
                if sym in _CONTROL_KEYWORDS:
                    continue
                qname = f"{mod_prefix}.{sym}"
                line = source.count("\n", 0, match.start()) + 1
                is_exp = True if language == "c" else bool(match.groupdict().get("export"))
                pop_id = f"{file_path}::POP::{qname}"
                nodes.append(
                    StackGraphNode(
                        node_id=pop_id,
                        file_path=file_path,
                        kind="POP_SYMBOL",
                        symbol=sym,
                        qualified_name=qname,
                        line=line,
                        is_exported=is_exp,
                    )
                )
                edges.append(StackGraphEdge(src_id=root_id, dst_id=pop_id, precedence=1))
                defined.append(qname)

                body_start = match.end()
                body_end = (
                    func_matches[idx + 1].start()
                    if idx + 1 < len(func_matches)
                    else len(source)
                )
                body_slice = source[body_start:body_end]
                for call_match in _GENERIC_CALL_RE.finditer(body_slice):
                    callee = call_match.group("callee")
                    if callee in _CONTROL_KEYWORDS or callee == sym:
                        continue
                    referenced.add(callee)
                    call_line = line + body_slice.count("\n", 0, call_match.start())
                    push_id = f"{file_path}::PUSH::{qname}::{callee}::{call_line}"
                    nodes.append(
                        StackGraphNode(
                            node_id=push_id,
                            file_path=file_path,
                            kind="PUSH_SYMBOL",
                            symbol=callee,
                            qualified_name=qname,
                            line=call_line,
                            is_exported=False,
                        )
                    )
                    edges.append(
                        StackGraphEdge(src_id=pop_id, dst_id=push_id, precedence=1)
                    )

    return FileStackGraph(
        file_path=file_path,
        language=language,
        file_xxh3=file_xxh3,
        nodes=tuple(nodes),
        edges=tuple(edges),
        defined_symbols=tuple(sorted(set(defined))),
        referenced_symbols=tuple(sorted(referenced)),
        imports=tuple(sorted(set(imports))),
    )


class StackGraphStitcher:
    """Incrementally stitches per-file StackGraphs to resolve cross-file symbols and blast radius."""

    def __init__(self) -> None:
        self._file_graphs: dict[str, FileStackGraph] = {}
        self._symbol_to_qnames: dict[str, set[str]] = {}
        self._qname_to_file: dict[str, str] = {}
        self._callers_of: dict[str, set[str]] = {}
        self._callees_of: dict[str, set[str]] = {}
        self._bridge_edges: list[tuple[str, str]] = []
        self._unresolved_references: list[dict[str, Any]] = []

    def upsert_file(
        self, file_path: str, source: str, language: str = "python"
    ) -> bool:
        """Updates a file's stack graph only if its XXH3 digest changed. Returns True if recomputed."""
        new_xxh3 = xxh3_64_hex(source)
        existing = self._file_graphs.get(file_path)
        if existing is not None and existing.file_xxh3 == new_xxh3:
            return False

        fsg = build_file_stack_graph(file_path, source, language)
        self._file_graphs[file_path] = fsg
        self._rebuild_indices()
        return True

    def batch_upsert(
        self, files: Iterable[tuple[str, str] | tuple[str, str, str]]
    ) -> int:
        """Batch upserts multiple files, building indices once across all updated files."""
        changed = 0
        for entry in files:
            file_path = entry[0]
            source = entry[1]
            language = entry[2] if len(entry) > 2 else "python"
            new_xxh3 = xxh3_64_hex(source)
            existing = self._file_graphs.get(file_path)
            if existing is not None and existing.file_xxh3 == new_xxh3:
                continue
            self._file_graphs[file_path] = build_file_stack_graph(
                file_path, source, language
            )
            changed += 1
        if changed > 0:
            self._rebuild_indices()
        return changed

    def remove_file(self, file_path: str) -> None:
        if file_path in self._file_graphs:
            del self._file_graphs[file_path]
            self._rebuild_indices()

    def _rebuild_indices(self) -> None:
        self._symbol_to_qnames.clear()
        self._qname_to_file.clear()
        self._callers_of.clear()
        self._callees_of.clear()
        self._unresolved_references.clear()

        for f_path, fsg in self._file_graphs.items():
            for node in fsg.nodes:
                if node.kind == "POP_SYMBOL":
                    self._symbol_to_qnames.setdefault(node.symbol, set()).add(
                        node.qualified_name
                    )
                    self._qname_to_file[node.qualified_name] = f_path

        for f_path, fsg in self._file_graphs.items():
            import_map = dict(fsg.imports)
            mod_prefix = _module_prefix_from_path(f_path)
            for node in fsg.nodes:
                if node.kind == "PUSH_SYMBOL":
                    caller_qname = node.qualified_name
                    resolved = self.resolve_symbol(
                        node.symbol,
                        from_module=mod_prefix,
                        import_map=import_map,
                    )
                    if resolved:
                        for target_qname in resolved:
                            self._callees_of.setdefault(caller_qname, set()).add(
                                target_qname
                            )
                            self._callers_of.setdefault(target_qname, set()).add(
                                caller_qname
                            )
                    else:
                        self._unresolved_references.append(
                            {
                                "caller_qname": caller_qname,
                                "symbol": node.symbol,
                                "file_path": f_path,
                                "line": node.line,
                            }
                        )

        for caller, callee in self._bridge_edges:
            self._callees_of.setdefault(caller, set()).add(callee)
            self._callers_of.setdefault(callee, set()).add(caller)

    def get_unresolved_references(self) -> tuple[dict[str, Any], ...]:
        """Returns all unresolved PUSH_SYMBOL references across all loaded file stack graphs."""
        return tuple(self._unresolved_references)

    def resolve_symbol(
        self,
        raw_symbol: str,
        *,
        from_module: str,
        import_map: dict[str, str],
    ) -> tuple[str, ...]:
        """Resolves a PUSH_SYMBOL reference against same-module POP_SYMBOLs, imports, or global exports."""
        # 1. Same-module local definition
        local_candidate = f"{from_module}.{raw_symbol}"
        if local_candidate in self._qname_to_file:
            return (local_candidate,)

        if raw_symbol in import_map:
            imported_target = import_map[raw_symbol]
            if imported_target in self._qname_to_file:
                return (imported_target,)
            # Check if imported_target matches any known qualified name exactly
            last_sym = imported_target.split(".")[-1]
            candidates = self._symbol_to_qnames.get(last_sym, ())
            matching = [
                qn
                for qn in candidates
                if qn == imported_target or qn.endswith(f".{imported_target}")
            ]
            if len(matching) == 1:
                return (matching[0],)
            return tuple(sorted(matching))

        if "." in raw_symbol:
            prefix, attr = raw_symbol.split(".", 1)
            if prefix in import_map:
                candidate = f"{import_map[prefix]}.{attr}"
                if candidate in self._qname_to_file:
                    return (candidate,)

        # Soundness: Never blindly link short symbols globally across unrelated files
        return ()

    def register_bridge_edge(self, caller_qname: str, callee_qname: str) -> None:
        """Injects a cross-language FFI or HTTP bridge edge into the stitched call graph."""
        self._bridge_edges.append((caller_qname, callee_qname))
        self._callees_of.setdefault(caller_qname, set()).add(callee_qname)
        self._callers_of.setdefault(callee_qname, set()).add(caller_qname)

    def direct_callers(self, qualified_name: str) -> tuple[str, ...]:
        return tuple(sorted(self._callers_of.get(qualified_name, ())))

    def transitive_blast_radius(
        self,
        seed_qualified_names: Iterable[str],
        *,
        max_depth: int = 8,
    ) -> tuple[str, ...]:
        """Computes deterministic transitive callers Callers+(f) up to max_depth."""
        seeds = set(seed_qualified_names)
        visited: set[str] = set()
        frontier = list(sorted(seeds))
        depth = 0
        while frontier and depth < max_depth:
            next_frontier: set[str] = set()
            for curr in frontier:
                for caller in self._callers_of.get(curr, ()):
                    if caller not in visited and caller not in seeds:
                        visited.add(caller)
                        next_frontier.add(caller)
            frontier = sorted(next_frontier)
            depth += 1
        return tuple(sorted(visited))

    def graph_merkle_root(self) -> str:
        digests = [
            f"{path}:{fsg.file_xxh3}" for path, fsg in sorted(self._file_graphs.items())
        ]
        return blake3_hex("|".join(digests), domain="verifyci.v2.stackgraph")
