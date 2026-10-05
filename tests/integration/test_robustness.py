import asyncio
import pytest
from verifyci.memory.ledger import EventLedger


def test_subchain_two_tasks_valid():
    ledger = EventLedger()
    ledger.append(type='A', payload={}, provenance={}, task_id='t1')
    ledger.append(type='B', payload={}, provenance={}, task_id='t1')
    ledger.append(type='C', payload={}, provenance={}, task_id='t2')
    ledger.append(type='D', payload={}, provenance={}, task_id='t2')
    from verifyci.interface.commands.anchor import _subchain
    events = ledger.get_events()
    for tid in ('t1', 't2'):
        scoped = EventLedger()
        scoped._events = _subchain(events, tid)
        assert scoped.verify_subchain() is True
    assert ledger.verify_chain() is True


def test_subchain_tampered_invalid():
    import dataclasses
    ledger = EventLedger()
    ledger.append(type='A', payload={}, provenance={}, task_id='t1')
    ledger.append(type='B', payload={}, provenance={}, task_id='t1')
    ledger.append(type='C', payload={}, provenance={}, task_id='t2')
    from verifyci.interface.commands.anchor import _subchain
    scoped = EventLedger()
    scoped._events = _subchain(ledger.get_events(), 't1')
    assert scoped.verify_subchain() is True
    scoped._events[1] = dataclasses.replace(scoped._events[1], prev_event_hash='forged')
    assert scoped.verify_subchain() is False


def test_read_anchors_absent_returns_empty(tmp_path):
    from verifyci.memory.ledger import read_anchors
    assert read_anchors(str(tmp_path / 'absent.jsonl')) == ([], 0)


def test_read_anchors_other_oserror_surfaces(tmp_path):
    from verifyci.memory.ledger import read_anchors
    with pytest.raises(OSError):
        read_anchors(str(tmp_path))


@pytest.mark.asyncio
async def test_review_decision_not_clobbered():
    from types import SimpleNamespace
    from verifyci.contracts.scheduler import ExecutableDAG, TaskStatus
    from verifyci.orchestration.scheduler import AsyncDAGScheduler
    from verifyci.orchestration import executor as exmod
    review_dec = SimpleNamespace(status='HUMAN_REVIEW', rationale='needs human')
    ok_dec = SimpleNamespace(status='PASS', rationale='all good')
    async def fake_execute(self, node, ctx):
        from verifyci.orchestration.executor import HumanReviewRequired
        if node.step_id == 's1':
            raise HumanReviewRequired(None, review_dec)
        from verifyci.contracts.task_ir import NodeResult
        return NodeResult(step_id='s2', status='COMPLETED', output=None, decision=ok_dec)
    real = exmod.Executor.execute_node
    exmod.Executor.execute_node = fake_execute
    try:
        sched = AsyncDAGScheduler()
        dag = ExecutableDAG(dag_id='d', nodes=[
            {'step_id': 's1', 'type': 'verify', 'config': {}, 'depends_on': []},
            {'step_id': 's2', 'type': 'verify', 'config': {}, 'depends_on': []},
        ])
        tid = await sched.submit(dag)
        for _ in range(100):
            st = await sched.status(tid)
            if st in (TaskStatus.HUMAN_REVIEW, TaskStatus.COMPLETED, TaskStatus.FAILED):
                break
            await asyncio.sleep(0.05)
        assert await sched.status(tid) == TaskStatus.HUMAN_REVIEW
        assert sched.decision(tid) is review_dec
    finally:
        exmod.Executor.execute_node = real


def test_hookless_taskir_fails_validation():
    from verifyci.contracts.task_ir import TaskIR, Step, Budget
    from verifyci.orchestration.compiler.validation import validate_task_ir
    steps = [Step(step_id='s1', type='verify', config={}, pre_commit_hook_id='', depends_on=[])]
    task = TaskIR(goal='g', intent_package_id='i', steps=steps, constraints=[], budget=Budget(budget_id='b', nano_usd=1000), policy_id='p')
    assert validate_task_ir(task) is False


@pytest.mark.asyncio
async def test_executor_empty_invariants_still_scans_secrets():
    from types import SimpleNamespace
    from verifyci.orchestration.executor import Executor, VerificationBlocker
    node = SimpleNamespace(step_id='s1', type='verify', config={}, pre_commit_hook_id='h', depends_on=[])
    diff = 'diff --git a/s.py b/s.py\n--- a/s.py\n+++ b/s.py\n@@ -1,0 +1,1 @@\n+DB_PASSWORD=s3cr3tPr0dValue\n'
    ctx = SimpleNamespace(task_id='t', conversation_id='', graph=None, node_map={}, entities=[], diff=diff, changed_entities=[], test_entities=[], invariants=[], vuln_cache=None, dependency_graph=None)
    with pytest.raises(VerificationBlocker):
        await Executor().execute_node(node, ctx)


def test_mcp_diff_caps():
    import asyncio
    from verifyci.interface.mcp_server import create_mcp_server, MAX_DIFF_CHARS, MAX_TASK_DIFF_CHARS
    srv = create_mcp_server(graph=None, store=None, node_map={}, entities=[])
    big = 'x' * (MAX_DIFF_CHARS + 1)
    out = asyncio.run(srv.call_tool('verify.diff', diff=big))
    assert out['error'] == 'diff_too_large'
    bigt = 'y' * (MAX_TASK_DIFF_CHARS + 1)
    out2 = asyncio.run(srv.call_tool('task.run', task='t', diff=bigt))
    assert out2['error'] == 'diff_too_large'
    out3 = asyncio.run(srv.call_tool('task.run', task=bigt, diff=''))
    assert out3['error'] == 'task_too_large'


def test_fastmcp_diff_caps_present():
    import inspect
    from verifyci.interface import fastmcp_server as fm
    from verifyci.interface import mcp_server as ms
    assert fm.MAX_DIFF_CHARS == 1000000
    assert fm.MAX_TASK_DIFF_CHARS == 100000
    assert ms.MAX_DIFF_CHARS == 1000000
    src = inspect.getsource(fm.create_fastmcp_server)
    assert 'diff_too_large' in src


def test_topo_unknown_dependency_raises():
    from verifyci.orchestration.scheduler import _topo_order
    with pytest.raises(ValueError, match='unknown_dependency'):
        _topo_order([{'step_id': 'a', 'depends_on': ['missing']}])


@pytest.mark.asyncio
async def test_cancel_terminal_guard():
    from verifyci.contracts.scheduler import ExecutableDAG, TERMINAL_STATUSES
    from verifyci.orchestration.scheduler import AsyncDAGScheduler
    sched = AsyncDAGScheduler()
    dag = ExecutableDAG(dag_id='d', nodes=[{'step_id': 's1', 'type': 'noop', 'config': {}, 'depends_on': []}])
    tid = await sched.submit(dag)
    for _ in range(100):
        if await sched.status(tid) in TERMINAL_STATUSES:
            break
        await asyncio.sleep(0.05)
    term = await sched.status(tid)
    assert term in TERMINAL_STATUSES
    await sched.cancel(tid)
    assert await sched.status(tid) == term


@pytest.mark.asyncio
async def test_node_timeout_marks_error():
    from verifyci.contracts.scheduler import ExecutableDAG, TaskStatus
    from verifyci.orchestration.scheduler import AsyncDAGScheduler
    from verifyci.orchestration import executor as exmod
    async def slow(self, node, ctx):
        await asyncio.sleep(0.5)
        from verifyci.contracts.task_ir import NodeResult
        return NodeResult(step_id='s1', status='COMPLETED', output=None)
    real = exmod.Executor.execute_node
    exmod.Executor.execute_node = slow
    try:
        sched = AsyncDAGScheduler()
        dag = ExecutableDAG(dag_id='d', nodes=[{'step_id': 's1', 'type': 'x', 'config': {'timeout': 0.05}, 'depends_on': []}])
        tid = await sched.submit(dag)
        for _ in range(100):
            st = await sched.status(tid)
            if st in (TaskStatus.FAILED, TaskStatus.TIMEOUT):
                break
            await asyncio.sleep(0.05)
        assert await sched.status(tid) == TaskStatus.TIMEOUT
        assert 'Timeout' in sched._tasks[tid]['error']
    finally:
        exmod.Executor.execute_node = real


def test_event_attestation_roundtrip(tmp_path):
    from verifyci.storage.graph_store import GraphStore
    from verifyci.contracts.event import Event, AttestationMetadata
    db = str(tmp_path / 'v.db')
    store = GraphStore(db)
    try:
        att_dict = {'key_id': 'k1', 'signature_algorithm': 'ed', 'public_key_id': 'p1', 'signed_at': 1.0, 'signature': 's', 'signed_hash': 'h'}
        ev = Event(id='e1', type='T', timestamp=1.0, task_id='t', conversation_id='c', payload={}, provenance={}, prev_event_hash=None, attestation=att_dict)
        store.insert_event(ev)
        got = store.get_events()[0]
        assert isinstance(got.attestation, AttestationMetadata)
        assert got.attestation.key_id == 'k1'
    finally:
        store.close()


def test_mcp_task_run_has_no_anchor_file_param():
    import inspect
    from verifyci.interface import mcp_server as ms
    src = inspect.getsource(ms.create_mcp_server)
    assert 'anchor_file' not in src


def test_run_node_uses_to_thread():
    import inspect
    from verifyci.orchestration import scheduler as sch
    src = inspect.getsource(sch.AsyncDAGScheduler._run_node)
    assert 'to_thread' in src
    assert 'wait_for' in src


@pytest.mark.asyncio
async def test_persist_only_new_events():
    import tempfile
    import os
    from verifyci.contracts.scheduler import ExecutableDAG, TERMINAL_STATUSES
    from verifyci.memory.ledger import EventLedger
    from verifyci.storage.graph_store import GraphStore
    from verifyci.orchestration.scheduler import AsyncDAGScheduler
    db = os.path.join(tempfile.mkdtemp(prefix='vci_'), 'v.db')
    store = GraphStore(db)
    try:
        ledger = EventLedger()
        sched = AsyncDAGScheduler(ledger=ledger)
        dag = ExecutableDAG(dag_id='d', nodes=[{'step_id': 's1', 'type': 'noop', 'config': {}, 'depends_on': []}])
        tid = await sched.submit(dag, context={'store': store})
        for _ in range(100):
            if await sched.status(tid) in TERMINAL_STATUSES:
                break
            await asyncio.sleep(0.05)
        task = sched._tasks[tid]
        assert task['persisted_count'] == len(ledger.get_events())
        rows = store.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        assert rows == len(ledger.get_events())
        await sched._persist(tid)
        rows2 = store.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        assert rows2 == rows
    finally:
        store.close()
