from __future__ import annotations

import ast
import re

from verifyci_v2.contracts.canonical import content_digest_hex
from verifyci_v2.contracts.ssa_ir import CPGEdge
from verifyci_v2.ingestion.stack_graphs import (
    StackGraphStitcher,
    _module_prefix_from_path,
)

_ROUTE_DECORATOR_RE = re.compile(
    r"@(?P<obj>[A-Za-z_]\w*)\.(?P<verb>route|get|post|put|delete|patch)\(\s*['\"](?P<path>[^'\"]+)['\"]"
)
_TS_FETCH_RE = re.compile(
    r"(?:fetch|axios\.(?:get|post|put|delete|patch))\(\s*[`'\"](?P<url>[^`'\"]+)[`'\"]"
)
_PARAM_SEGMENT_RE = re.compile(r"(\$\{[^}]+\}|<[^>]+>|\{[^}]+\})")


def normalize_route_template(raw_path: str) -> str:
    """
    Normalizes FastAPI (`/users/{id}`), Flask (`/users/<int:id>`), and TS template literals
    (``/users/${userId}``) into a canonical path template (`/users/{}`).
    """
    path = raw_path.strip()
    if "://" in path:
        path = "/" + path.split("://", 1)[1].split("/", 1)[-1]
    path = path.split("?", 1)[0]
    normalized = _PARAM_SEGMENT_RE.sub("{}", path)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized.rstrip("/") or "/"


class PolyglotBridgeResolver:
    """Discovers and links Python <-> C FFI calls and TypeScript/JS <-> Python HTTP routes."""

    def __init__(self) -> None:
        self._c_functions: dict[str, str] = {}  # c_symbol -> qualified_name
        self._py_ffi_Waiters: list[tuple[str, str]] = []  # (py_caller_qname, c_symbol)
        self._http_routes: dict[str, str] = {}  # normalized_route -> py_handler_qname
        self._http_clients: list[
            tuple[str, str]
        ] = []  # (ts_caller_qname, normalized_route)

    def scan_file(self, file_path: str, source: str, language: str) -> None:
        mod_prefix = _module_prefix_from_path(file_path)

        if language in ("c", "cpp"):
            for match in re.finditer(
                r"^(?:[A-Za-z_][\w\s\*]+?)\s+(?P<name>[A-Za-z_]\w*)\s*\([^;]*\)\s*\{",
                source,
                re.MULTILINE,
            ):
                c_sym = match.group("name")
                self._c_functions[c_sym] = f"{mod_prefix}.{c_sym}"

        elif language == "python":
            tree = ast.parse(source, filename=file_path)
            ffi_handles: set[str] = set()

            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    func = node.value.func
                    fn_name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else None)
                    if fn_name in {"CDLL", "LoadLibrary", "dlopen"} or (fn_name and any(tok in ast.unparse(func) for tok in ("CDLL", "LoadLibrary", "dlopen", "ffi.dlopen"))):
                        for tgt in node.targets:
                            if isinstance(tgt, ast.Name):
                                ffi_handles.add(tgt.id)

            for stmt in tree.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qname = f"{mod_prefix}.{stmt.name}"
                    # Check route decorators
                    for dec in stmt.decorator_list:
                        if not isinstance(dec, ast.Call):
                            continue
                        dec_src = "@" + ast.unparse(dec)
                        rm = _ROUTE_DECORATOR_RE.search(dec_src)
                        if rm:
                            norm_route = normalize_route_template(rm.group("path"))
                            self._http_routes[norm_route] = qname

                    # Check FFI calls inside function body
                    for child in ast.walk(stmt):
                        if isinstance(child, ast.Call) and isinstance(
                            child.func, ast.Attribute
                        ):
                            if (
                                isinstance(child.func.value, ast.Name)
                                and child.func.value.id in ffi_handles
                            ):
                                self._py_ffi_Waiters.append((qname, child.func.attr))

        elif language in ("typescript", "javascript"):
            # Match exported/local TS functions and scan their bodies for fetch/axios calls
            func_matches = list(
                re.finditer(
                    r"(?:export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\(",
                    source,
                )
            )
            for idx, fm in enumerate(func_matches):
                fn_qname = f"{mod_prefix}.{fm.group('name')}"
                start = fm.end()
                end = (
                    func_matches[idx + 1].start()
                    if idx + 1 < len(func_matches)
                    else len(source)
                )
                body = source[start:end]
                for fetch_m in _TS_FETCH_RE.finditer(body):
                    norm_url = normalize_route_template(fetch_m.group("url"))
                    self._http_clients.append((fn_qname, norm_url))

    def resolve_bridges(
        self, stitcher: StackGraphStitcher | None = None
    ) -> tuple[CPGEdge, ...]:
        """Emits FFI_BRIDGE and HTTP_BRIDGE edges and registers them in the StackGraphStitcher."""
        edges: list[CPGEdge] = []

        for py_caller, c_symbol in self._py_ffi_Waiters:
            c_target = self._c_functions.get(c_symbol)
            if c_target:
                edge_uid = content_digest_hex(
                    f"FFI:{py_caller}->{c_target}",
                    domain="verifyci.v2.bridge",
                )[:24]
                edges.append(
                    CPGEdge(
                        edge_uid=edge_uid,
                        src_node_uid=py_caller,
                        dst_node_uid=c_target,
                        edge_kind="FFI_BRIDGE",
                        predicate_label=f"ctypes:{c_symbol}",
                    )
                )
                if stitcher is not None:
                    stitcher.register_bridge_edge(py_caller, c_target)

        for ts_caller, route_template in self._http_clients:
            py_handler = self._http_routes.get(route_template)
            if py_handler:
                edge_uid = content_digest_hex(
                    f"HTTP:{ts_caller}->{py_handler}:{route_template}",
                    domain="verifyci.v2.bridge",
                )[:24]
                edges.append(
                    CPGEdge(
                        edge_uid=edge_uid,
                        src_node_uid=ts_caller,
                        dst_node_uid=py_handler,
                        edge_kind="HTTP_BRIDGE",
                        predicate_label=route_template,
                    )
                )
                if stitcher is not None:
                    stitcher.register_bridge_edge(ts_caller, py_handler)

        return tuple(sorted(edges, key=lambda e: e.edge_uid))
