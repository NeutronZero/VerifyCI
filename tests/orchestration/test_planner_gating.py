"""Planner gates exactly one step: verify_change.

retrieve_context and propose_change are ungated placeholders (their
nodes complete without running verification); the full
reasoner+blast+removal+invariants pipeline runs once per task, on
verify_change. Validation requires at least one gated step — an
all-ungated plan is invalid, and (by construction) so is the old
every-step-gated shape.
"""
from verifyci.contracts.task_ir import Budget, Step, TaskIR
from verifyci.orchestration.compiler.validation import validate_task_ir
from verifyci.orchestration.planner import Planner


def _valid_ir(hooks):
    steps = [Step(step_id=f"s{i}", type=f"t{i}", config={},
                  pre_commit_hook_id=h, depends_on=[])
             for i, h in enumerate(hooks)]
    return TaskIR(goal="g", intent_package_id="i", steps=steps,
                  constraints=[],
                  budget=Budget(budget_id="b", nano_usd=1, spent=0),
                  policy_id="p")


def test_planner_gates_only_verify_change():
    task = Planner().plan("goal", "intent1", "pol1")
    by_type = {s.type: s.pre_commit_hook_id for s in task.steps}
    assert by_type["verify_change"] == "default"
    assert by_type["retrieve_context"] is None
    assert by_type["propose_change"] is None


def test_validation_rejects_zero_gated_steps():
    assert validate_task_ir(_valid_ir([None, None])) is False


def test_validation_accepts_planner_output():
    assert validate_task_ir(Planner().plan("goal", "intent1", "pol1")) is True


def test_hookless_step_runs_no_verification():
    import asyncio
    from verifyci.orchestration.executor import Executor
    from verifyci.verification import semi_formal_reason as sfr
    calls = []
    orig = sfr.SemiFormalReasoner.verify

    def counting(self, *a, **k):
        calls.append(1)
        return orig(self, *a, **k)

    sfr.SemiFormalReasoner.verify = counting
    try:
        node = {"step_id": "s1", "type": "retrieve_context", "config": {},
                "pre_commit_hook_id": None, "depends_on": []}
        result = asyncio.run(Executor().execute_node(node, {}))
    finally:
        sfr.SemiFormalReasoner.verify = orig
    assert result.status == "COMPLETED"
    assert calls == []


DIFF = ("diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n"
        "+++ b/src/app.py\n@@ -1,2 +1,2 @@\n ctx\n+added\n ctx\n")


def _run_counted(monkeypatch, tmp_path, diff):
    import shutil
    from verifyci.interface.commands.init import run_init
    from verifyci.interface.commands.ingest import run_ingest
    from verifyci.interface.commands.run import run_task
    from verifyci.verification import semi_formal_reason as sfr
    repo = tmp_path / "repo"
    shutil.copytree("samples/test-repo", repo)
    run_init(str(repo))
    run_ingest(str(repo))
    db = str(repo / ".verifyci" / "verifyci.db")
    calls = []
    orig = sfr.SemiFormalReasoner.verify

    def counting(self, *a, **k):
        calls.append(1)
        return orig(self, *a, **k)

    monkeypatch.setattr(sfr.SemiFormalReasoner, "verify", counting)
    result = run_task("ship it", timeout=60.0, diff=diff, db_path=db)
    return result, len(calls)


def test_run_task_verifies_exactly_once(monkeypatch, tmp_path):
    result, count = _run_counted(monkeypatch, tmp_path, DIFF)
    assert count == 1
    assert result["decision"] is not None


def test_run_task_secret_still_fails_once(monkeypatch, tmp_path):
    secret = DIFF.replace("+added\n", '+password = "hunter2hunter2"\n')
    result, count = _run_counted(monkeypatch, tmp_path, secret)
    assert count == 1
    assert result["decision"] == "FAIL"


def test_run_task_empty_diff_inconclusive_once(monkeypatch, tmp_path):
    result, count = _run_counted(monkeypatch, tmp_path, "")
    assert count == 1
    assert result["decision"] == "INCONCLUSIVE"
