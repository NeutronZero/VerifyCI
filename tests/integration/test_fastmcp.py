"""FastMCP transport: tool surface parity + stdio hygiene.

Stdio is a framed byte stream; any decoration on stdout corrupts every
client read. These tests pin the surface without launching a server
(serving is verified manually against a real client handshake).

NOTE: verifyci imports stay function-level in this file. The test runner's
system interpreter carries C:\\Projects\\verifyci on sys.path; a top-level
import would bind that stale checkout at collection time instead of the
worktree under test.
"""


async def _tools(mcp):
    return sorted([t.name for t in await mcp._list_tools()])


def test_fastmcp_exposes_six_v1_tools(tmp_path):
    import asyncio
    from verifyci.interface.fastmcp_server import create_fastmcp_server

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
    from verifyci.interface import fastmcp_server
    src = inspect.getsource(fastmcp_server.serve)
    assert "show_banner=False" in src


class _Payload:
    def __init__(self, eid="e1"):
        self.revision_entity_id = eid
        self.logical_entity_id = "logical:" + eid
        self.name = "func"
        self.file_path = "src/app.py"
        self.line_start = 10
        self.line_end = 20
        self.source_hash = "abc123"


class _FakeGraph:
    def nodes(self):
        return [_Payload()]

    def node_indices(self):
        return [0]

    def predecessors(self, idx):
        return []

    def successors(self, idx):
        return []


def test_fastmcp_server_attaches_ledger():
    # MCP task executions must leave an audit trail, not ledger_head None.
    import inspect
    from verifyci.interface import fastmcp_server
    src = inspect.getsource(fastmcp_server.create_fastmcp_server)
    assert "EventLedger()" in src


def test_search_hits_carry_definition_coordinates():
    import asyncio
    from verifyci.interface.mcp_server import create_mcp_server
    server = create_mcp_server(graph=_FakeGraph(), node_map={"e1": 0},
                               entities=[_Payload()])
    out = asyncio.run(server.call_tool("code.search", query="func"))
    assert out["results"]
    hit = out["results"][0]
    assert hit["id"] == "e1"
    assert hit["name"] == "func"
    assert hit["file_path"] == "src/app.py"
    assert (hit["line_start"], hit["line_end"]) == (10, 20)


def test_definition_resolves_search_revision_id():
    # The chaining loop: search returns a revision id, definition
    # accepts it directly — no logical-id derivation needed.
    import asyncio
    from verifyci.interface.mcp_server import create_mcp_server
    server = create_mcp_server(graph=_FakeGraph(), node_map={"e1": 0},
                               entities=[_Payload()], store=None)
    found = asyncio.run(server.call_tool("code.search", query="func"))
    rid = found["results"][0]["id"]
    definition = asyncio.run(server.call_tool("code.definition", symbol=rid))
    assert definition["definition"]["file_path"] == "src/app.py"
    assert definition["definition"]["line_start"] == 10
    missing = asyncio.run(server.call_tool("code.definition", symbol="nope"))
    assert missing["definition"] is None


def test_mcp_task_run_records_ledger_and_head():
    import asyncio
    from verifyci.contracts.scheduler import TERMINAL_STATUSES
    from verifyci.interface.mcp_server import create_mcp_server
    from verifyci.memory.ledger import EventLedger
    ledger = EventLedger()
    server = create_mcp_server(graph=_FakeGraph(), node_map={"e1": 0},
                               entities=[_Payload()], ledger=ledger, store=None)
    out = asyncio.run(server.call_tool("task.run", task="probe", diff=""))
    from verifyci.contracts.scheduler import TaskStatus
    assert TaskStatus(out["status"]) in TERMINAL_STATUSES
    assert out["ledger_head"] == ledger.head_hash()
    assert out["ledger_head"] is not None
    assert len(ledger.get_events()) >= 2


def test_mcp_server_facade_preserves_signature():
    import inspect
    import verifyci.interface.mcp_server as legacy
    assert "create_mcp_server" in legacy.__all__
    sig = inspect.signature(legacy.create_mcp_server)
    assert {"graph", "store", "node_map", "ledger", "entities"} <= set(sig.parameters)


def test_mcp_server_facade_emits_deprecation_and_delegates():
    import warnings
    from verifyci.interface.mcp_server import create_mcp_server
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        server = create_mcp_server(graph=None, store=None, node_map={}, entities=[])
    assert any(issubclass(w.category, DeprecationWarning)
               and "verifyci.interface.fastmcp_server.create_fastmcp_server" in str(w.message)
               for w in caught), [str(w.message) for w in caught]
    assert sorted(server.list_tools()) == [
        "code.definition",
        "code.search",
        "graph.query",
        "task.run",
        "task.status",
        "verify.diff",
    ]
