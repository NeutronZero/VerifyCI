import pytest

from src.orchestration.intent import build_intent_package
from src.orchestration.planner import Planner
from src.orchestration.scheduler import AsyncDAGScheduler
from src.contracts.scheduler import TERMINAL_STATUSES, TaskStatus


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
    assert all(s.pre_commit_hook_id for s in task.steps)


@pytest.mark.asyncio
async def test_gated_dag_without_evidence_ends_inconclusive():
    # Planner steps carry pre-commit hooks; with no graph and no diff the
    # semi-formal checker RUNS but establishes nothing (ungrounded) and no
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
    from src.contracts.scheduler import ExecutableDAG
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
    from src.contracts.scheduler import ExecutableDAG
    scheduler = AsyncDAGScheduler()
    dag = ExecutableDAG(dag_id="d", nodes=[{"step_id": "s1"}, {"step_id": "s2"}], budget_nano_usd=1)
    task_id = await scheduler.submit(dag)
    assert await _drain(scheduler, task_id) == TaskStatus.FAILED
