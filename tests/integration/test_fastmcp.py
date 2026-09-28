"""FastMCP transport: tool surface parity + stdio hygiene.

Stdio is a framed byte stream; any decoration on stdout corrupts every
client read. These tests pin the surface without launching a server
(serving is verified manually against a real client handshake).
"""
from src.interface.fastmcp_server import create_fastmcp_server


async def _tools(mcp):
    return sorted([t.name for t in await mcp._list_tools()])


def test_fastmcp_exposes_six_v1_tools(tmp_path):
    import asyncio

    mcp = create_fastmcp_server(str(tmp_path / "missing.db"))
    assert asyncio.run(_tools(mcp)) == [
        "code_definition",
        "code_search",
        "graph_query",
        "task_run",
        "task_status",
        "verify_diff",
    ]


def test_fastmcp_serve_hides_banner():
    import inspect
    from src.interface import fastmcp_server
    src = inspect.getsource(fastmcp_server.serve)
    assert "show_banner=False" in src
