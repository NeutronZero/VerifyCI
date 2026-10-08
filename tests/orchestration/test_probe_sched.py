"""PROBES item 6: block/review precedence over cancelled noise; thread limit note."""
import asyncio

import pytest


@pytest.mark.asyncio
async def test_probe_block_beats_cancelled_noise():
    from types import SimpleNamespace
    from verifyci.contracts.scheduler import ExecutableDAG, TaskStatus
    from verifyci.orchestration import executor as exmod
    from verifyci.orchestration.scheduler import AsyncDAGScheduler

    block_dec = SimpleNamespace(status="FAIL", rationale="blocked")

    async def fake_execute(self, node, ctx):
        from verifyci.orchestration.executor import VerificationBlocker
        if node.step_id == "s_block":
            raise VerificationBlocker(None, block_dec)
        # Slow noise: the block lands first, the sibling is cancelled
        # after, so both outcomes exist and node order decides.
        await asyncio.sleep(0.3)
        raise RuntimeError("cancelled")

    real = exmod.Executor.execute_node
    exmod.Executor.execute_node = fake_execute  # ty: ignore[invalid-assignment] — timing double with intentionally loose signature
    try:
        sched = AsyncDAGScheduler()
        dag = ExecutableDAG(dag_id="d", nodes=[
            {"step_id": "s_noise", "type": "x", "config": {}, "depends_on": []},
            {"step_id": "s_block", "type": "x", "config": {}, "depends_on": []},
        ])
        tid = await sched.submit(dag)
        for _ in range(100):
            st = await sched.status(tid)
            if st == TaskStatus.FAILED:
                break
            await asyncio.sleep(0.05)
        assert await sched.status(tid) == TaskStatus.FAILED
        assert sched.decision(tid) is block_dec
    finally:
        exmod.Executor.execute_node = real


def test_probe_thread_limitation_documented():
    import inspect
    from verifyci.orchestration import scheduler as sch
    src = inspect.getsource(sch.AsyncDAGScheduler._run_node)
    assert "kill" in src.lower() and "linger" in src.lower()
