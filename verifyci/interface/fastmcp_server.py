"""Real MCP transport over FastMCP (stdio / streamable HTTP).

Loads the persisted graph once, then exposes the six V1 tools. The
in-process ``MCPServer`` dict-class remains for embedding/tests; this
module is the network boundary.
"""
from typing import Any


MAX_DIFF_CHARS = 1_000_000
MAX_TASK_DIFF_CHARS = 100_000


def create_fastmcp_server(db_path: str, name: str = "verifyci"):
    from fastmcp import FastMCP

    from verifyci.interface.commands import resolve_db
    from verifyci.interface.commands.graph_loader import load_graph, payload_entities
    from verifyci.interface.mcp_server import create_mcp_server

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
    inner = create_mcp_server(graph=graph, store=ro_store, rw_store=rw_store,
                              node_map=node_map, ledger=EventLedger(), entities=entities)

    mcp = FastMCP(name)

    @mcp.tool()
    async def code_search(query: str, k: int = 10, conversation_id: str = "",
                          rerank: bool = False) -> dict[str, Any]:
        """Hybrid code search: BM25 + dense + graph expansion, RRF fused. Rerank opt-in."""
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
        if len(diff) > MAX_DIFF_CHARS:
            return {"revision_id": revision_id, "status": "FAILED", "error": "diff_too_large"}
        return await inner.call_tool("verify.diff", diff=diff, revision_id=revision_id,
                                     conversation_id=conversation_id)

    @mcp.tool()
    async def task_run(task: str, conversation_id: str = "", diff: str = "") -> dict[str, Any]:
        """Plan, compile, schedule and gate a task; returns the terminal decision."""
        if len(diff) > MAX_TASK_DIFF_CHARS:
            return {"task": task, "status": "FAILED", "error": "diff_too_large", "ledger_head": None}
        if len(task) > MAX_TASK_DIFF_CHARS:
            return {"task": task, "status": "FAILED", "error": "task_too_large", "ledger_head": None}
        return await inner.call_tool("task.run", task=task, conversation_id=conversation_id, diff=diff)

    @mcp.tool()
    async def task_status(task_id: str) -> dict[str, Any]:
        """Scheduler execution status for a submitted task."""
        return await inner.call_tool("task.status", task_id=task_id)

    return mcp


def serve(db_path: str = "", transport: str = "stdio", host: str = "127.0.0.1",
          port: int = 8000) -> None:
    mcp = create_fastmcp_server(db_path or None)
    if transport == "stdio":
        # Banner and logs must stay off stdout: stdio is a framed JSON-RPC
        # byte stream, and any decoration corrupts every client read.
        mcp.run(show_banner=False)
    else:
        mcp.run(transport="http", host=host, port=port, show_banner=False)
