import pytest

from verifyci.orchestration.intent import build_intent_package
from verifyci.orchestration.planner import Planner
from verifyci.orchestration.scheduler import AsyncDAGScheduler
from verifyci.contracts.scheduler import TERMINAL_STATUSES, TaskStatus


async def _drain(scheduler, task_id, tries=100):
    import asyncio
    for _ in range(tries):
        if await scheduler.status(task_id) in TERMINAL_STATUSES:
            break
        await asyncio.sleep(0.05)
    return await scheduler.status(task_id)


def test_build_intent_package():
    intent = build_intent_package("do things")
    assert intent.intent_package_id
    assert len(intent.invariants) >= 1
    assert intent.verification_plan_id


def test_planner_three_steps_chained():
    task = Planner().plan("goal", "intent1", "pol1")
    assert len(task.steps) == 3
    assert task.steps[0].depends_on == []
    assert task.steps[1].depends_on == [task.steps[0].step_id]
    gated = [s for s in task.steps if s.pre_commit_hook_id]
    assert len(gated) == 1 and gated[0].type == "verify_change"


@pytest.mark.asyncio
async def test_gated_dag_without_evidence_ends_inconclusive():
    # Only verify_change is gated; with no graph and no diff the
    # semi-formal checker RUNS once but establishes nothing (ungrounded) and no
    # invariant rejects → INCONCLUSIVE, never a misleading FAIL or PASS.
    scheduler = AsyncDAGScheduler()
    planner_task = Planner().plan("goal", "intent1", "pol1")
    task_id = await scheduler.submit(planner_task)
    status = await _drain(scheduler, task_id)
    assert status == TaskStatus.INCONCLUSIVE
    decision = scheduler.decision(task_id)
    assert decision is not None
    assert decision.status == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_ungated_dag_completes():
    from verifyci.contracts.scheduler import ExecutableDAG
    scheduler = AsyncDAGScheduler()
    dag = ExecutableDAG(dag_id="d", nodes=[
        {"step_id": "s1", "type": "noop", "config": {}, "depends_on": []},
        {"step_id": "s2", "type": "noop", "config": {}, "depends_on": ["s1"]},
    ])
    task_id = await scheduler.submit(dag)
    assert await _drain(scheduler, task_id) == TaskStatus.COMPLETED
    assert scheduler.decision(task_id) is None


@pytest.mark.asyncio
async def test_scheduler_budget_breach():
    from verifyci.contracts.scheduler import ExecutableDAG
    scheduler = AsyncDAGScheduler()
    dag = ExecutableDAG(dag_id="d", nodes=[{"step_id": "s1"}, {"step_id": "s2"}], budget_nano_usd=1)
    task_id = await scheduler.submit(dag)
    assert await _drain(scheduler, task_id) == TaskStatus.FAILED


@pytest.mark.asyncio
async def test_scheduler_no_budget_means_unlimited():
    # None (the default) is "no budget set". The old default of 0
    # silently disabled the guard via `if budget`.
    from verifyci.contracts.scheduler import ExecutableDAG
    assert ExecutableDAG(dag_id="d").budget_nano_usd is None
    scheduler = AsyncDAGScheduler()
    dag = ExecutableDAG(dag_id="d", nodes=[
        {"step_id": "s1", "type": "noop", "config": {}, "depends_on": []},
    ])
    task_id = await scheduler.submit(dag)
    assert await _drain(scheduler, task_id) == TaskStatus.COMPLETED


@pytest.mark.asyncio
async def test_scheduler_zero_budget_breaches():
    # 0 is a real zero budget now, not a falsy alias for unlimited.
    from verifyci.contracts.scheduler import ExecutableDAG
    scheduler = AsyncDAGScheduler()
    dag = ExecutableDAG(dag_id="d", nodes=[{"step_id": "s1"}], budget_nano_usd=0)
    task_id = await scheduler.submit(dag)
    assert await _drain(scheduler, task_id) == TaskStatus.FAILED
    assert scheduler._tasks[task_id]["error"] == "BUDGET_BREACHED"


@pytest.mark.asyncio
async def test_scheduler_pins_head_on_failure_paths():
    # L1: the ledger head is pinned in a finally, so every terminal
    # path — including budget breach — leaves a head behind.
    from verifyci.contracts.scheduler import ExecutableDAG
    from verifyci.memory.ledger import EventLedger
    scheduler = AsyncDAGScheduler(ledger=EventLedger())
    dag = ExecutableDAG(dag_id="d", nodes=[{"step_id": "s1"}], budget_nano_usd=0)
    task_id = await scheduler.submit(dag)
    assert await _drain(scheduler, task_id) == TaskStatus.FAILED
    assert scheduler.ledger_head(task_id)
    assert scheduler.ledger_head("no-such-task") is None


@pytest.mark.asyncio
async def test_scheduler_persists_failed_runs():
    # The audit trail must contain failures, not just successes: the
    # budget-breach path persists before returning.
    from verifyci.contracts.scheduler import ExecutableDAG
    from verifyci.memory.ledger import EventLedger
    from verifyci.storage.graph_store import GraphStore
    import tempfile
    import os
    db = os.path.join(tempfile.mkdtemp(prefix="vci_"), "v.db")
    store = GraphStore(db)
    try:
        ledger = EventLedger()
        scheduler = AsyncDAGScheduler(ledger=ledger)
        dag = ExecutableDAG(dag_id="d", nodes=[{"step_id": "s1"}], budget_nano_usd=0)
        task_id = await scheduler.submit(
            dag, context={"store": store})
        assert await _drain(scheduler, task_id) == TaskStatus.FAILED
        rows = store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert rows >= 2  # SUBMITTED + STARTED + BREACHED
        types = [r[0] for r in store.conn.execute("SELECT type FROM events").fetchall()]
        assert "BUDGET_BREACHED" in types
    finally:
        store.close()


@pytest.mark.asyncio
async def test_scheduler_node_error_is_attributed():
    # An unexpected node exception names the step and the exception type
    # instead of landing as a bare reason string.
    from verifyci.contracts.scheduler import ExecutableDAG
    scheduler = AsyncDAGScheduler()
    dag = ExecutableDAG(dag_id="d", nodes=[
        {"step_id": "boom", "type": "verify", "config": {"__raise__": True},
         "depends_on": [], "pre_commit_hook_id": "h"},
    ])
    from verifyci.orchestration import executor as _ex

    async def _raise(self, node, context):
        raise RuntimeError("kaput")

    _real = _ex.Executor.execute_node
    _ex.Executor.execute_node = _raise
    try:
        task_id = await scheduler.submit(dag)
        assert await _drain(scheduler, task_id) == TaskStatus.FAILED
        assert scheduler._tasks[task_id]["error"] == "boom: RuntimeError: kaput"
    finally:
        _ex.Executor.execute_node = _real
