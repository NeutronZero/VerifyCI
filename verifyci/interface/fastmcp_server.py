"""Real MCP transport over FastMCP (stdio / streamable HTTP).

Loads the persisted graph once, then exposes the six V1 tools. The
in-process ``MCPServer`` dict-class remains for embedding/tests; this
module is the network boundary.
"""
from typing import Any
import hmac
import ipaddress

from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from verifyci.interface.limits import MAX_DIFF_CHARS, MAX_TASK_DIFF_CHARS

__all__ = [
    "MAX_DIFF_CHARS",
    "MAX_TASK_DIFF_CHARS",
    "create_fastmcp_server",
    "create_inner_server",
    "create_fastmcp_http_app",
    "serve",
    "FastMCPAuthMiddleware",
]


def create_inner_server(graph=None, store=None, node_map: dict | None = None,
                        dense_provider: Any = None, ledger: Any = None,
                        entities: list | None = None,
                        rw_store: Any = None) -> Any:
    """Canonical in-process tool server: the six V1 tools over shared caps/gates.

    Single source of truth for tool construction. ``create_fastmcp_server``
    builds on this; ``verifyci.interface.mcp_server.create_mcp_server`` is a
    deprecated facade delegating here.
    """
    from verifyci.interface.mcp_server import MCPServer, MCPServerHandlers

    handlers = MCPServerHandlers(
        graph=graph,
        store=store,
        node_map=node_map,
        dense_provider=dense_provider,
        ledger=ledger,
        entities=entities,
        rw_store=rw_store,
    )
    server = MCPServer()
    server.register_tool("code.search", handlers.code_search, "Hybrid BM25 + graph retrieval with RRF + rerank")
    server.register_tool("code.definition", handlers.code_definition, "Symbol lookup")
    server.register_tool("graph.query", handlers.graph_query, "Bitemporal graph lookup with asOf")
    server.register_tool("verify.diff", handlers.verify_diff, "Semi-formal + blast radius verification")
    server.register_tool("task.run", handlers.task_run, "Planner → Compiler → Scheduler")
    server.register_tool("task.status", handlers.task_status, "Scheduler-backed DAG execution status")
    return server


def create_fastmcp_server(db_path: str | None, name: str = "verifyci"):
    from fastmcp import FastMCP

    from verifyci.interface.commands import resolve_db
    from verifyci.interface.commands.graph_loader import load_graph, payload_entities

    db = resolve_db(db_path)
    from verifyci.memory.ledger import EventLedger
    from verifyci.storage.graph_store import GraphStore
    import os as _os
    # I-01: Dual-store boundary. Observation tools run on ro_store;
    # task execution uses rw_store for event ledger persistence.
    ro_store = GraphStore(db, read_only=True) if _os.path.exists(db) else None
    rw_store = GraphStore(db, read_only=False) if _os.path.exists(db) else None
    graph, node_map, entities = load_graph(db)
    if not entities:
        entities = payload_entities(graph)
    # Without a ledger, task.run executions leave no audit trail and
    # report ledger_head None. The server is long-lived; the scheduler
    # keeps one ledger per task (plus this aggregate mirror), so
    # interleaved tasks keep verifiable per-task subchains and heads.
    inner = create_inner_server(graph=graph, store=ro_store, rw_store=rw_store,
                              node_map=node_map, ledger=EventLedger(), entities=entities)

    mcp = FastMCP(name)

    @mcp.tool()
    async def code_search(query: str, k: int = 10, conversation_id: str = "",
                          rerank: bool = False) -> dict[str, Any]:
        """Hybrid code search: BM25 + dense + graph expansion, RRF fused. Rerank opt-in."""
        from verifyci.interface.ingress import IngressValidationError, validate_query_ingress
        try:
            query, k = validate_query_ingress(query, k=k)
        except IngressValidationError as exc:
            return {"results": [], "query": query, "methods": [], "error": exc.code}
        return await inner.call_tool("code.search", query=query, k=k,
                                     conversation_id=conversation_id, rerank=rerank)

    @mcp.tool()
    async def code_definition(symbol: str) -> dict[str, Any]:
        """Look up a symbol definition (file + lines + entity id)."""
        return await inner.call_tool("code.definition", symbol=symbol)

    @mcp.tool()
    async def graph_query(query: str, asOf: float | None = None) -> dict[str, Any]:
        """Bitemporal graph lookup with optional as-of timestamp."""
        return await inner.call_tool("graph.query", query=query, asOf=asOf)

    @mcp.tool()
    async def verify_diff(diff: str, revision_id: str = "", conversation_id: str = "") -> dict[str, Any]:
        """Verify a unified diff: semi-formal certificate + blast radius + policy decision."""
        from verifyci.interface.ingress import IngressValidationError, validate_diff_ingress
        try:
            validate_diff_ingress(diff)
        except IngressValidationError as exc:
            return {"revision_id": revision_id, "status": "FAILED", "error": exc.code or "diff_too_large"}
        return await inner.call_tool("verify.diff", diff=diff, revision_id=revision_id,
                                     conversation_id=conversation_id)

    @mcp.tool()
    async def task_run(task: str, conversation_id: str = "", diff: str = "") -> dict[str, Any]:
        """Plan, compile, schedule and gate a task; returns the terminal decision."""
        from verifyci.interface.ingress import IngressValidationError, validate_task_ingress
        try:
            validate_task_ingress(task, diff=diff)
        except IngressValidationError as exc:
            return {"task": task, "status": "FAILED", "error": exc.code, "ledger_head": None}
        return await inner.call_tool("task.run", task=task, conversation_id=conversation_id, diff=diff)

    @mcp.tool()
    async def task_status(task_id: str) -> dict[str, Any]:
        """Scheduler execution status for a submitted task."""
        return await inner.call_tool("task.status", task_id=task_id)

    return mcp


def _is_loopback(host: str) -> bool:
    if host in ("127.0.0.1", "localhost", "::1"):
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(host).is_loopback
    except Exception:
        return False


class FastMCPAuthMiddleware(BaseHTTPMiddleware):
    """Enforce request-level authentication on FastMCP HTTP transport.

    When VERIFYCI_API_TOKEN (or legacy ACI_API_TOKEN) is configured, every HTTP request
    must present valid `Authorization: Bearer <token>`.
    When unset (local-CLI default), only loopback clients (127.0.0.1, localhost, ::1)
    are permitted; non-loopback requests without valid token receive 401.
    """

    async def dispatch(self, request, call_next):
        from verifyci.env import get_env
        token = get_env("API_TOKEN", "")
        if token:
            auth_header = request.headers.get("authorization", "")
            try:
                expected = f"Bearer {token}".encode("utf-8")
                presented = auth_header.encode("utf-8")
            except (UnicodeEncodeError, AttributeError):
                return JSONResponse({"detail": "unauthorized"}, status_code=401)
            if not hmac.compare_digest(presented, expected):
                return JSONResponse({"detail": "unauthorized"}, status_code=401)
            return await call_next(request)

        host = ""
        try:
            client = request.client
            host = client.host if hasattr(client, "host") else ""
        except Exception:
            host = ""
        if host in ("127.0.0.1", "localhost", "::1"):
            return await call_next(request)
        try:
            if host and ipaddress.ip_address(host).is_loopback:
                return await call_next(request)
        except ValueError:
            pass
        return JSONResponse({"detail": "unauthorized"}, status_code=401)


def create_fastmcp_http_app(db_path: str | None = ""):
    """Create a Starlette HTTP app with FastMCPAuthMiddleware attached."""
    mcp = create_fastmcp_server(db_path or None)
    return mcp.http_app(middleware=[Middleware(FastMCPAuthMiddleware)])


def serve(db_path: str | None = "", transport: str = "stdio", host: str = "127.0.0.1",
          port: int = 8000) -> None:
    from verifyci.env import get_env
    if transport == "http" and not _is_loopback(host):
        token = get_env("API_TOKEN", "")
        if not token:
            raise PermissionError(
                "unauthenticated_network_transport: Non-loopback FastMCP HTTP requires "
                "VERIFYCI_API_TOKEN (or legacy ACI_API_TOKEN)"
            )
    mcp = create_fastmcp_server(db_path or None)
    if transport == "stdio":
        # Banner and logs must stay off stdout: stdio is a framed JSON-RPC
        # byte stream, and any decoration corrupts every client read.
        mcp.run(show_banner=False)
    else:
        middleware = [Middleware(FastMCPAuthMiddleware)]
        mcp.run(transport="http", host=host, port=port, middleware=middleware, show_banner=False)
