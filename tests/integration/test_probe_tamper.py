"""PROBES item 2: tamper-evidence (subchain continuity, per-task ledgers,
fail-closed anchors, insertion-order events, cancel persistence)."""
import asyncio

from verifyci.contracts.canonical import event_hash
from verifyci.memory.ledger import EventLedger


def _ledger_two_tasks():
    ledger = EventLedger()
    ledger.append(type="A", payload={}, provenance={}, task_id="t1")
    ledger.append(type="B", payload={}, provenance={}, task_id="t2")
    ledger.append(type="C", payload={}, provenance={}, task_id="t2")
    ledger.append(type="D", payload={}, provenance={}, task_id="t1")
    return ledger


def test_probe_task_subchain_interleaved_valid():
    from verifyci.memory.ledger import verify_task_subchain
    events = _ledger_two_tasks().get_events()
    assert verify_task_subchain(events, "t1") is True
    assert verify_task_subchain(events, "t2") is True
    head = event_hash([e for e in events if e.task_id == "t2"][-1])
    assert verify_task_subchain(events, "t2", expected_head=head) is True
    assert verify_task_subchain(events, "t2", expected_head="deadbeef") is False


def test_probe_task_subchain_truncation_breaks():
    from verifyci.memory.ledger import verify_task_subchain
    events = _ledger_two_tasks().get_events()
    truncated = [e for i, e in enumerate(events) if i != 1]
    assert verify_task_subchain(truncated, "t2") is False


def test_probe_task_subchain_tampered_link_breaks():
    import dataclasses
    from verifyci.memory.ledger import verify_task_subchain
    events = _ledger_two_tasks().get_events()
    tampered = list(events)
    tampered[2] = dataclasses.replace(tampered[2], prev_event_hash="forged")
    assert verify_task_subchain(tampered, "t2") is False
    assert verify_task_subchain(tampered, "t1") is False


def test_probe_per_task_ledgers_isolated():
    import os
    import tempfile
    from verifyci.contracts.scheduler import ExecutableDAG, TERMINAL_STATUSES
    from verifyci.orchestration.scheduler import AsyncDAGScheduler
    from verifyci.storage.graph_store import GraphStore

    async def _go():
        db = os.path.join(tempfile.mkdtemp(prefix="vci_probe_"), "v.db")
        store = GraphStore(db)
        try:
            sched = AsyncDAGScheduler()
            dag = ExecutableDAG(dag_id="d", nodes=[
                {"step_id": "s1", "type": "noop", "config": {}, "depends_on": []}])
            t1 = await sched.submit(dag, context={"store": store})
            t2 = await sched.submit(dag, context={"store": store})
            for _ in range(200):
                s1 = await sched.status(t1)
                s2 = await sched.status(t2)
                if s1 in TERMINAL_STATUSES and s2 in TERMINAL_STATUSES:
                    break
                await asyncio.sleep(0.05)
            assert await sched.status(t1) in TERMINAL_STATUSES
            assert await sched.status(t2) in TERMINAL_STATUSES
            h1, h2 = sched.ledger_head(t1), sched.ledger_head(t2)
            assert h1 and h2 and h1 != h2
            ev1 = [e for e in store.get_events() if e.task_id == t1]
            ev2 = [e for e in store.get_events() if e.task_id == t2]
            assert h1 == event_hash(ev1[-1])
            assert h2 == event_hash(ev2[-1])
            n = store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            assert n == len(ev1) + len(ev2)
            await sched._persist(t1)
            await sched._persist(t2)
            n2 = store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            assert n2 == n, "re-persist duplicated events"
        finally:
            store.close()

    asyncio.run(_go())


def test_probe_anchor_typo_fails_closed(tmp_path):
    from verifyci.interface.commands.anchor import run_verify_chain
    from verifyci.interface.commands.run import run_task
    from verifyci.storage.graph_store import GraphStore
    db = str(tmp_path / "v.db")
    GraphStore(db).close()
    out = run_task("probe task", diff="", db_path=db)
    assert out["ledger_head"]
    r = run_verify_chain(db, str(tmp_path / "anker.jsonl"), None)
    assert r["status"] == "HEAD_MISMATCH", r
    assert "error" in r
    empty = str(tmp_path / "empty.jsonl")
    open(empty, "w").close()
    r2 = run_verify_chain(db, empty, None)
    assert r2["status"] == "HEAD_MISMATCH", r2
    assert "error" in r2


def test_probe_get_events_insertion_order(tmp_path):
    from verifyci.contracts.event import Event
    from verifyci.storage.graph_store import GraphStore
    db = str(tmp_path / "v.db")
    store = GraphStore(db)
    try:
        store.insert_event(Event(id="e1", type="T", timestamp=200.0, task_id="t",
                                 conversation_id="c", payload={}, provenance={},
                                 prev_event_hash=None))
        store.insert_event(Event(id="e2", type="T", timestamp=100.0, task_id="t",
                                 conversation_id="c", payload={}, provenance={},
                                 prev_event_hash="x"))
        ids = [e.id for e in store.get_events()]
        assert ids == ["e1", "e2"], ids
    finally:
        store.close()


def test_probe_insert_event_no_replace(tmp_path):
    from verifyci.contracts.event import Event
    from verifyci.storage.graph_store import GraphStore
    db = str(tmp_path / "v.db")
    store = GraphStore(db)
    try:
        store.insert_event(Event(id="e1", type="T", timestamp=1.0, task_id="t",
                                 conversation_id="c", payload={"v": 1},
                                 provenance={}, prev_event_hash=None))
        store.insert_event(Event(id="e2", type="T", timestamp=2.0, task_id="t",
                                 conversation_id="c", payload={},
                                 provenance={}, prev_event_hash="x"))
        store.insert_event(Event(id="e1", type="T", timestamp=999.0, task_id="t",
                                 conversation_id="c", payload={"v": 2},
                                 provenance={}, prev_event_hash=None))
        events = store.get_events()
        assert [e.id for e in events] == ["e1", "e2"]
        assert events[0].payload == {"v": 1}
    finally:
        store.close()


def test_probe_cancel_event_persisted_and_pinned():
    import os
    import tempfile
    from verifyci.contracts.scheduler import ExecutableDAG, TaskStatus
    from verifyci.orchestration import executor as exmod
    from verifyci.orchestration.scheduler import AsyncDAGScheduler
    from verifyci.storage.graph_store import GraphStore

    async def slow(self, node, ctx):
        await asyncio.sleep(2.0)
        from verifyci.contracts.task_ir import NodeResult
        return NodeResult(step_id="s1", status="COMPLETED", output=None)

    real = exmod.Executor.execute_node
    exmod.Executor.execute_node = slow
    try:
        async def _go():
            db = os.path.join(tempfile.mkdtemp(prefix="vci_probecancel_"), "v.db")
            store = GraphStore(db)
            try:
                sched = AsyncDAGScheduler()
                dag = ExecutableDAG(dag_id="d", nodes=[
                    {"step_id": "s1", "type": "x", "config": {}, "depends_on": []}])
                tid = await sched.submit(dag, context={"store": store})
                await asyncio.sleep(0.15)
                await sched.cancel(tid)
                for _ in range(100):
                    if await sched.status(tid) == TaskStatus.CANCELLED:
                        break
                    await asyncio.sleep(0.05)
                assert await sched.status(tid) == TaskStatus.CANCELLED
                mine = [e for e in store.get_events() if e.task_id == tid]
                types = [e.type for e in mine]
                assert "TASK_CANCELLED" in types, types
                assert sched.ledger_head(tid) == event_hash(mine[-1])
                assert mine[-1].type == "TASK_CANCELLED"
            finally:
                store.close()

        asyncio.run(_go())
    finally:
        exmod.Executor.execute_node = real
