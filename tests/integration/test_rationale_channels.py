"""The PASS qualifier must survive every output channel.

`all_checks_passed_behavior_not_verified` is the change a reviewer sees at
decision time. If any serializer strips it, the overclaim returns in
exactly that channel. Each test below asserts the literal string in one
channel's output: CLI result, MCP tool result, HTTP response, ledger event.
"""
import pytest

QUALIFIER = "all_checks_passed_behavior_not_verified"

DIFF = (
    "diff --git a/src/app.py b/src/app.py\n"
    "--- a/src/app.py\n"
    "+++ b/src/app.py\n"
    "@@ -1 +2 @@\n"
    " x = 1\n"
    "+x = 2\n"
)


class _Payload:
    def __init__(self, eid="e1"):
        self.revision_entity_id = eid
        self.logical_entity_id = "logical:" + eid
        self.name = "func"
        self.file_path = "src/app.py"
        # Span covers the diff's changed lines (1-2): the changed-line
        # coverage rule declines edits outside every span, so the
        # fixture must place the entity where the diff edits.
        self.line_start = 1
        self.line_end = 2
        self.source_hash = "abc123"


class _FakeGraph:
    def __init__(self):
        self._payloads = [_Payload()]

    def nodes(self):
        return list(self._payloads)

    def node_indices(self):
        return [0]

    def predecessors(self, idx):
        return []

    def successors(self, idx):
        return []


def _context(diff=DIFF):
    from types import SimpleNamespace
    return SimpleNamespace(
        task_id="t1", conversation_id="c1",
        graph=_FakeGraph(), node_map={"e1": 0},
        entities=[_Payload()], diff=diff,
        changed_entities=[], test_entities=[],
        invariants=[], vuln_cache=None, dependency_graph=None,
    )


def test_cli_result_carries_rationale():
    from verifyci.interface.commands.verify import run_verify
    # CLI prints result['status'] and result['rationale'] verbatim;
    # pin the source dict, not the echo formatting.
    import tempfile
    import os
    from verifyci.storage.graph_store import GraphStore
    from verifyci.storage.revision import create_revision
    from verifyci.ingestion.parser import TreeSitterParser
    from verifyci.ingestion.extractor import extract_entities, extract_edges

    db = os.path.join(tempfile.mkdtemp(), "q.db")
    store = GraphStore(db)
    try:
        rev = create_revision(repository_id="r", files=[("src/app.py", "h")])
        store.insert_revision(rev)
        parsed = TreeSitterParser().parse(
            "src/app.py", b"def func():\n    return 1\n", "python")
        for e in extract_entities(parsed, "r", rev.revision_id):
            store.insert_entity(e)
        for edge in extract_edges(parsed, extract_entities(parsed, "r", rev.revision_id),
                                  rev.revision_id):
            store.insert_edge(edge)
        result = run_verify(DIFF, db_path=db)
        assert result["status"] == "PASS"
        assert result["rationale"] == QUALIFIER
    finally:
        store.close()


@pytest.mark.asyncio
async def test_mcp_result_carries_rationale():
    from verifyci.interface.mcp_server import create_mcp_server
    server = create_mcp_server(graph=_FakeGraph(), node_map={"e1": 0})
    result = await server.call_tool("verify.diff", diff=DIFF)
    assert result["status"] == "PASS"
    assert result["rationale"] == QUALIFIER


def test_http_response_carries_rationale(monkeypatch):
    from verifyci.interface import http as http_module

    class _Req:
        diff = DIFF
        revision_id = ""
        task_id = "http_verify"

    monkeypatch.setattr(
        http_module, "run_verify",
        lambda *a, **k: {"status": "PASS", "rationale": QUALIFIER,
                         "report_id": "r", "revision_id": "",
                         "files": [], "changed_entities": []},
    )
    response = http_module.verify(_Req())
    assert response["rationale"] == QUALIFIER


@pytest.mark.asyncio
async def test_ledger_event_carries_rationale():
    import asyncio
    from verifyci.contracts.scheduler import TaskStatus
    from verifyci.memory.ledger import EventLedger
    from verifyci.orchestration.scheduler import AsyncDAGScheduler

    ledger = EventLedger()
    scheduler = AsyncDAGScheduler(ledger=ledger)
    dag = {"nodes": [{
        "step_id": "s1", "type": "llm_call", "config": {},
        "pre_commit_hook_id": "default", "depends_on": [],
    }]}
    context = {
        "graph": _FakeGraph(), "node_map": {"e1": 0},
        "entities": [_Payload()], "diff": DIFF, "invariants": [],
    }
    task_id = await scheduler.submit(dag, conversation_id="c1", context=context)
    for _ in range(200):
        status = await scheduler.status(task_id)
        if status not in (TaskStatus.PENDING, TaskStatus.RUNNING):
            break
        await asyncio.sleep(0.05)
    assert await scheduler.status(task_id) == TaskStatus.COMPLETED
    completed = [e for e in ledger.get_events() if e.type == "TASK_COMPLETED"]
    assert completed, "TASK_COMPLETED must be emitted to the ledger"
    assert completed[-1].payload.get("rationale") == QUALIFIER
