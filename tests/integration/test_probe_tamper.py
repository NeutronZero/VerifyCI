"""PROBES item 2: tamper-evidence (subchain continuity, per-task ledgers,
fail-closed anchors, insertion-order events, cancel persistence)."""
import asyncio

from verifyci.contracts.canonical import event_hash
from verifyci.memory.ledger import EventLedger


def _interleaved_task_ledgers():
    """Production shape (anchor.py docstring + AsyncDAGScheduler): one
    ledger per task, persisted into one interleaved events table. A
    single global ledger cannot express this: its events link to the
    previous GLOBAL event, which is exactly what the pre-fix
    verify_task_subchain assumed and what no run_task ever produced."""
    la, lb = EventLedger(), EventLedger()
    a1 = la.append(type="A1", payload={}, provenance={}, task_id="A")
    b1 = lb.append(type="B1", payload={}, provenance={}, task_id="B")
    a2 = la.append(type="A2", payload={}, provenance={}, task_id="A")
    b2 = lb.append(type="B2", payload={}, provenance={}, task_id="B")
    a3 = la.append(type="A3", payload={}, provenance={}, task_id="A")
    return [a1, b1, a2, b2, a3]  # stored order: interleaved


def test_probe_task_subchain_interleaved_valid():
    from verifyci.memory.ledger import verify_task_subchain
    events = _interleaved_task_ledgers()
    assert verify_task_subchain(events, "A") is True
    assert verify_task_subchain(events, "B") is True
    head = [e for e in events if e.task_id == "B"][-1]
    from verifyci.contracts.canonical import event_hash
    head_hash = event_hash(head)
    assert verify_task_subchain(events, "B", expected_head=head_hash) is True
    assert verify_task_subchain(events, "B", expected_head="deadbeef") is False


def test_probe_task_subchain_single_task():
    import dataclasses
    from verifyci.memory.ledger import verify_task_subchain
    ledger = EventLedger()
    ledger.append(type="E1", payload={}, provenance={}, task_id="t")
    ledger.append(type="E2", payload={}, provenance={}, task_id="t")
    events = ledger.get_events()
    assert verify_task_subchain(events, "t") is True
    broken = [events[0], dataclasses.replace(events[1], prev_event_hash="x")]
    assert verify_task_subchain(broken, "t") is False


def test_probe_task_subchain_three_interleaved_tasks():
    from verifyci.memory.ledger import verify_task_subchain
    ledgers = {t: EventLedger() for t in "XYZ"}
    order = ["X", "Y", "Z", "Z", "X", "Y", "X"]
    events = []
    for task in order:
        events.append(ledgers[task].append(type="E", payload={},
                                           provenance={}, task_id=task))
    for task in "XYZ":
        assert verify_task_subchain(events, task) is True, task


def test_probe_task_subchain_broken_link_in_a_does_not_break_b():
    """Unrelated events must not participate: tampering inside chain A
    changes nothing about chain B's verdict, and vice versa."""
    import dataclasses
    from verifyci.memory.ledger import verify_task_subchain
    events = _interleaved_task_ledgers()
    idx_a2 = next(i for i, e in enumerate(events)
                  if e.task_id == "A" and e.type == "A2")
    tampered_a = list(events)
    tampered_a[idx_a2] = dataclasses.replace(tampered_a[idx_a2],
                                             prev_event_hash="forged")
    assert verify_task_subchain(tampered_a, "A") is False
    assert verify_task_subchain(tampered_a, "B") is True
    idx_b2 = next(i for i, e in enumerate(events)
                  if e.task_id == "B" and e.type == "B2")
    tampered_b = list(events)
    tampered_b[idx_b2] = dataclasses.replace(tampered_b[idx_b2],
                                             prev_event_hash="forged")
    assert verify_task_subchain(tampered_b, "B") is False
    assert verify_task_subchain(tampered_b, "A") is True


def test_probe_task_subchain_first_event_with_predecessor_fails():
    """A task's first stored event carrying a prev hash is a truncation/
    splice signal: the event it referenced was removed or renamed."""
    import dataclasses
    from verifyci.contracts.canonical import event_hash
    from verifyci.memory.ledger import verify_task_subchain
    events = _interleaved_task_ledgers()
    a1 = events[0]
    b1 = next(e for e in events if e.type == "B1")
    spliced = [dataclasses.replace(a1, prev_event_hash=event_hash(b1))] + events[1:]
    assert verify_task_subchain(spliced, "A") is False


def test_probe_task_subchain_persisted_events(tmp_path):
    """Integration: two sequential run_task calls sharing one DB. The
    old global-comparison verifier reported CHAIN_BROKEN for the second
    task with zero tampering — its first event legitimately links to
    the previous run's last event, not to global index 0."""
    from verifyci.interface.commands.anchor import run_verify_chain
    from verifyci.interface.commands.run import run_task
    from verifyci.storage.graph_store import GraphStore
    db = str(tmp_path / "v.db")
    GraphStore(db).close()
    r1 = run_task("first task", diff="", db_path=db)
    r2 = run_task("second task", diff="", db_path=db)
    assert r1["task_id"] != r2["task_id"]
    assert run_verify_chain(db, None, r1["task_id"])["status"] == "CHAIN_VALID"
    assert run_verify_chain(db, None, r2["task_id"])["status"] == "CHAIN_VALID"
    assert run_verify_chain(db, None, None)["status"] == "CHAIN_VALID"


def test_probe_task_subchain_truncation_breaks():
    from verifyci.memory.ledger import verify_task_subchain
    events = _interleaved_task_ledgers()
    truncated = [e for i, e in enumerate(events) if i != 1]
    assert verify_task_subchain(truncated, "B") is False


def test_probe_task_subchain_tampered_link_breaks():
    import dataclasses
    from verifyci.memory.ledger import verify_task_subchain
    events = _interleaved_task_ledgers()
    tampered = list(events)
    idx_b1 = next(i for i, e in enumerate(events) if e.type == "B2")
    tampered[idx_b1] = dataclasses.replace(tampered[idx_b1],
                                           prev_event_hash="forged")
    assert verify_task_subchain(tampered, "B") is False
    assert verify_task_subchain(tampered, "A") is True


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
        await asyncio.sleep(0.4)
        from verifyci.contracts.task_ir import NodeResult
        return NodeResult(step_id="s1", status="COMPLETED", output=None)

    real = exmod.Executor.execute_node
    exmod.Executor.execute_node = slow  # ty: ignore[invalid-assignment] — timing double with intentionally loose signature
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
