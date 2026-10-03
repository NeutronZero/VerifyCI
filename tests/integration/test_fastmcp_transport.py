"""FastMCP transport wrappers: size caps and serve wiring.

The passthrough wrappers delegate to the inner MCP server; the load-bearing
gate behavior lives there (and in run_verify/run_task). These tests pin the
transport-owned logic: oversize diffs/tasks rejected before any gate runs,
and serve() keeping stdio framing clean.
"""

import asyncio

from verifyci.interface.fastmcp_server import (
    MAX_DIFF_CHARS,
    MAX_TASK_DIFF_CHARS,
    create_fastmcp_server,
    serve,
)


def _call(mcp, name, args):
    return asyncio.run(mcp.call_tool(name, args)).structured_content


def test_verify_diff_cap_rejects_before_gate(tmp_path):
    mcp = create_fastmcp_server(str(tmp_path / "missing.db"))
    out = _call(mcp, "verify_diff", {"diff": "x" * (MAX_DIFF_CHARS + 1)})
    assert out["status"] == "FAILED"
    assert out["error"] == "diff_too_large"


def test_task_run_caps_reject_before_gate(tmp_path):
    mcp = create_fastmcp_server(str(tmp_path / "missing.db"))
    big_diff = _call(
        mcp, "task_run", {"task": "t", "diff": "x" * (MAX_TASK_DIFF_CHARS + 1)}
    )
    assert big_diff == {
        "task": "t",
        "status": "FAILED",
        "error": "diff_too_large",
        "ledger_head": None,
    }
    big_task = _call(mcp, "task_run", {"task": "t" * (MAX_TASK_DIFF_CHARS + 1)})
    assert big_task["status"] == "FAILED"
    assert big_task["error"] == "task_too_large"
    assert big_task["ledger_head"] is None


def test_task_status_passthrough_on_empty_graph(tmp_path):
    mcp = create_fastmcp_server(str(tmp_path / "missing.db"))
    out = _call(mcp, "task_status", {"task_id": "no-such-task"})
    assert isinstance(out, dict)


def test_passthrough_wrappers_fail_honest_on_empty_graph(tmp_path):
    # No store/graph loaded: wrappers delegate and return error dicts,
    # never raise through the transport.
    mcp = create_fastmcp_server(str(tmp_path / "missing.db"))
    search = _call(mcp, "code_search", {"query": "auth"})
    assert search["results"] == [] and search["error"] == "no_graph_loaded"
    definition = _call(mcp, "code_definition", {"symbol": "f"})
    assert definition["definition"] is None
    assert definition["error"] == "no_store_loaded"
    query = _call(mcp, "graph_query", {"query": "f"})
    assert query["results"] == [] and query["error"] == "no_store_loaded"
    small = _call(mcp, "verify_diff", {"diff": "not a diff"})
    assert small["status"] == "INCONCLUSIVE"


def test_serve_stdio_and_http_wiring(tmp_path, monkeypatch):
    import fastmcp

    calls = []

    def fake_run(self, *a, **k):
        calls.append((a, k))

    monkeypatch.setattr(fastmcp.FastMCP, "run", fake_run)
    serve(str(tmp_path / "missing.db"), transport="stdio")
    assert calls and calls[-1][1].get("show_banner") is False
    serve(str(tmp_path / "missing.db"), transport="http", host="127.0.0.1", port=8123)
    assert calls[-1][1].get("transport") == "http"
    assert calls[-1][1].get("port") == 8123
