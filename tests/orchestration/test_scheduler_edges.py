"""Scheduler edge paths: unknown tasks, broken ledgers, cancel/resume,
mid-run cancellation, sibling cancellation, persist/emit failures.

Timing-sensitive paths are made deterministic with direct calls,
monkeypatched levels, and cyclic DAGs (fail-fast) — no sleeps on
the happy path except bounded terminal polling.
"""

import asyncio

from verifyci.contracts.scheduler import TaskStatus
from verifyci.memory.ledger import EventLedger
from verifyci.orchestration.scheduler import AsyncDAGScheduler


def _submit_blocking(coro):
    return asyncio.run(coro)


async def _wait_terminal(
    sched,
    tid,
    want=(
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.HUMAN_REVIEW,
        TaskStatus.INCONCLUSIVE,
    ),
):
    for _ in range(200):
        st = await sched.status(tid)
        if st in want:
            return st
        await asyncio.sleep(0.02)
    raise AssertionError(f"task {tid} never terminal: {st}")


def test_unknown_task_accessors():
    async def go():
        sched = AsyncDAGScheduler()
        assert await sched.status("ghost") == TaskStatus.UNKNOWN
        assert sched.decision("ghost") is None
        assert sched.ledger_head("ghost") is None
        await sched.cancel("ghost")  # noop, must not raise
        await sched.resume("ghost")  # noop, must not raise
        await sched._persist("ghost")  # noop, must not raise
        sched._emit("X", "ghost", "c", {})  # no ledger anywhere: noop

    _submit_blocking(go())


def test_broken_task_ledger_falls_back_and_pins_none():
    class Raiser:
        def head_hash(self):
            raise RuntimeError("boom")

    async def go():
        sched = AsyncDAGScheduler()
        tid = await sched.submit({"task_id": "t", "nodes": []})
        await _wait_terminal(sched, tid)
        task = sched._tasks[tid]
        task["ledger_head"] = "pinned"
        task["ledger"] = Raiser()
        assert sched.ledger_head(tid) == "pinned"  # live read failed, fallback
        sched._pin_head(tid)
        assert task["ledger_head"] is None  # pin failure records None
        sched._pin_head("ghost")  # unknown task: noop

    _submit_blocking(go())


def test_submit_unknown_shape_completes_empty():
    async def go():
        sched = AsyncDAGScheduler()
        tid = await sched.submit(object())
        assert await _wait_terminal(sched, tid) == TaskStatus.COMPLETED
        assert sched.decision(tid) is None

    _submit_blocking(go())


def test_cycle_dag_fails_with_named_error():
    async def go():
        sched = AsyncDAGScheduler()
        tid = await sched.submit(
            {
                "task_id": "t",
                "nodes": [
                    {
                        "step_id": "a",
                        "type": "x",
                        "config": {},
                        "pre_commit_hook_id": None,
                        "depends_on": ["b"],
                    },
                    {
                        "step_id": "b",
                        "type": "x",
                        "config": {},
                        "pre_commit_hook_id": None,
                        "depends_on": ["a"],
                    },
                ],
            }
        )
        assert await _wait_terminal(sched, tid) == TaskStatus.FAILED
        assert "cycle_detected" in sched._tasks[tid]["error"]

    _submit_blocking(go())


def test_execute_guard_rejects_rerun_after_cancel():
    async def go():
        sched = AsyncDAGScheduler()
        tid = await sched.submit({"task_id": "t", "nodes": []})
        await sched.cancel(tid)
        assert await sched.status(tid) == TaskStatus.CANCELLED
        await sched._execute(tid)  # duplicate run: guard returns
        assert await sched.status(tid) == TaskStatus.CANCELLED

    _submit_blocking(go())


def test_cancel_then_resume_reruns_to_terminal():
    async def go():
        sched = AsyncDAGScheduler()
        tid = await sched.submit(
            {
                "task_id": "t",
                "nodes": [
                    {
                        "step_id": "a",
                        "type": "x",
                        "config": {},
                        "pre_commit_hook_id": None,
                        "depends_on": ["b"],
                    },
                    {
                        "step_id": "b",
                        "type": "x",
                        "config": {},
                        "pre_commit_hook_id": None,
                        "depends_on": ["a"],
                    },
                ],
            }
        )
        assert await _wait_terminal(sched, tid) == TaskStatus.FAILED
        await sched.resume(tid)  # FAILED + idle: requeue
        assert await sched.status(tid) in (
            TaskStatus.PENDING,
            TaskStatus.RUNNING,
            TaskStatus.FAILED,
        )
        assert await _wait_terminal(sched, tid) == TaskStatus.FAILED
        assert "cycle_detected" in sched._tasks[tid]["error"]

    _submit_blocking(go())


def test_cancelled_mid_levels_persists_and_returns():
    async def go():
        sched = AsyncDAGScheduler()
        calls = []

        async def fake_run_level(executor, level, task_id, conversation_id, shared):
            calls.append([n["step_id"] for n in level])
            if len(calls) == 2:
                sched._tasks[task_id]["status"] = TaskStatus.CANCELLED
            return []

        sched._run_level = fake_run_level
        tid = await sched.submit(
            {
                "task_id": "t",
                "nodes": [
                    {
                        "step_id": "a",
                        "type": "x",
                        "config": {},
                        "pre_commit_hook_id": None,
                        "depends_on": [],
                    },
                    {
                        "step_id": "b",
                        "type": "x",
                        "config": {},
                        "pre_commit_hook_id": None,
                        "depends_on": ["a"],
                    },
                    {
                        "step_id": "c",
                        "type": "x",
                        "config": {},
                        "pre_commit_hook_id": None,
                        "depends_on": ["b"],
                    },
                ],
            }
        )
        assert await _wait_terminal(sched, tid) == TaskStatus.CANCELLED
        assert calls == [["a"], ["b"]]

    _submit_blocking(go())


def test_execute_cancelled_error_path_sets_cancelled():
    async def go():
        sched = AsyncDAGScheduler()

        async def boom(*a, **k):
            raise asyncio.CancelledError()

        sched._run_level = boom
        tid = await sched.submit(
            {
                "task_id": "t",
                "nodes": [
                    {
                        "step_id": "a",
                        "type": "x",
                        "config": {},
                        "pre_commit_hook_id": None,
                        "depends_on": [],
                    },
                ],
            }
        )
        handle = sched._tasks[tid]["handle"]
        try:
            await handle
        except asyncio.CancelledError:
            pass
        assert await sched.status(tid) == TaskStatus.CANCELLED
        assert sched._tasks[tid]["error"] == "cancelled"

    _submit_blocking(go())


def test_run_level_cancelled_sibling_marked():
    from types import SimpleNamespace

    async def go():
        sched = AsyncDAGScheduler()
        block_dec = SimpleNamespace(status="FAIL", rationale="blocked")

        async def fake_run_node(executor, node, task_id, conversation_id, shared):
            if node["step_id"] == "fast":
                return ("block", block_dec)
            await asyncio.sleep(30)
            return ("ok", None)

        sched._run_node = fake_run_node
        level = [
            {"step_id": "fast", "type": "x", "config": {}},
            {"step_id": "slow", "type": "x", "config": {}},
        ]
        results = await sched._run_level(None, level, "t", "c", {})
        assert ("block", block_dec) in results
        slow = [r for r in results if r == ("error", ("slow", "cancelled"))]
        assert slow, results

    _submit_blocking(go())


def test_run_level_self_cancelled_node_marked():
    # A node cancelled by anything OTHER than _run_level's own sibling
    # preemption surfaces via t.cancelled() on the next wait cycle —
    # the sibling path never reaches that branch because the loop exits
    # once pending drains.
    async def go():
        sched = AsyncDAGScheduler()

        async def fake_run_node(executor, node, task_id, conversation_id, shared):
            if node["step_id"] == "fast":
                return ("ok", None)
            asyncio.current_task().cancel()
            await asyncio.sleep(30)
            return ("ok", None)  # unreachable

        sched._run_node = fake_run_node
        level = [
            {"step_id": "fast", "type": "x", "config": {}},
            {"step_id": "selfcancel", "type": "x", "config": {}},
        ]
        results = await sched._run_level(None, level, "t", "c", {})
        assert ("ok", None) in results
        assert ("error", ("selfcancel", "cancelled")) in results

    _submit_blocking(go())


def test_run_level_node_exception_attributed():
    async def go():
        sched = AsyncDAGScheduler()

        async def raiser(executor, node, task_id, conversation_id, shared):
            raise ValueError("kablam")

        sched._run_node = raiser
        level = [{"step_id": "s1", "type": "x", "config": {}}]
        results = await sched._run_level(None, level, "t", "c", {})
        assert results == [("error", ("s1", "ValueError: kablam"))]

    _submit_blocking(go())


def test_persist_store_without_batch_inserts():
    async def go():
        sched = AsyncDAGScheduler()
        tid = await sched.submit({"task_id": "t", "nodes": []})
        await sched.cancel(tid)
        inserted = []

        class NoBatchStore:
            def insert_event(self, e):
                inserted.append(e)

        sched._tasks[tid]["context"] = {"store": NoBatchStore()}
        await sched._persist(tid)
        task = sched._tasks[tid]
        assert task["persisted_count"] == len(inserted) > 0

    _submit_blocking(go())


def test_persist_error_recorded_not_swallowed(capfd):
    async def go():
        sched = AsyncDAGScheduler()
        tid = await sched.submit({"task_id": "t", "nodes": []})
        await sched.cancel(tid)

        class Batch:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class BrokenStore:
            def batch(self):
                return Batch()

            def insert_event(self, e):
                raise RuntimeError("disk gone")

        sched._tasks[tid]["context"] = {"store": BrokenStore()}
        await sched._persist(tid)
        assert sched._tasks[tid]["persist_error"] == "RuntimeError: disk gone"

    _submit_blocking(go())
    capfd.readouterr()  # persist prints a traceback; keep output clean


def test_emit_broken_task_ledger_records_error(capfd):
    class Raiser:
        def append(self, **k):
            raise RuntimeError("ledger gone")

    sched = AsyncDAGScheduler()
    sched._tasks["t"] = {"ledger": Raiser()}
    sched._emit("X", "t", "c", {})
    assert sched._tasks["t"]["emit_error"] == "RuntimeError: ledger gone"
    capfd.readouterr()


def test_emit_mirror_adopt_error_recorded(capfd):
    class BadMirror:
        def adopt(self, event):
            raise RuntimeError("mirror gone")

    sched = AsyncDAGScheduler(ledger=BadMirror())
    sched._tasks["t"] = {"ledger": EventLedger()}
    sched._emit("X", "t", "c", {})
    assert sched._tasks["t"]["emit_error"] == "RuntimeError: mirror gone"
    capfd.readouterr()
