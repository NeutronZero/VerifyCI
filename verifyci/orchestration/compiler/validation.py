from verifyci.contracts.task_ir import TaskIR


def _hook(step) -> object:
    return step.get('pre_commit_hook_id') if isinstance(step, dict) else getattr(step, 'pre_commit_hook_id', None)


def _validate_dag_transitions(steps: list) -> bool:
    step_ids: set[str] = set()
    for s in steps:
        sid = s.get('step_id') if isinstance(s, dict) else getattr(s, 'step_id', None)
        if not sid or sid in step_ids:
            return False
        step_ids.add(sid)

    by_id = {
        (s.get('step_id') if isinstance(s, dict) else getattr(s, 'step_id', None)): s
        for s in steps
    }
    visited: dict[str, str] = {}

    def has_cycle(sid: str) -> bool:
        visited[sid] = "visiting"
        step = by_id[sid]
        deps = step.get('depends_on', []) if isinstance(step, dict) else getattr(step, 'depends_on', [])
        for dep in deps or []:
            if dep not in by_id:
                return True  # Dangling dependency
            if visited.get(dep) == "visiting":
                return True  # Cycle detected
            if dep not in visited and has_cycle(dep):
                return True
        visited[sid] = "done"
        return False

    for sid in step_ids:
        if sid not in visited:
            if has_cycle(sid):
                return False
    return True


def validate_task_ir(task: TaskIR) -> bool:
    if not task.goal:
        return False
    if not getattr(task, "intent_package_id", None):
        return False
    if not getattr(task, "policy_id", None):
        return False
    if not task.steps:
        return False
    if task.budget is None or not hasattr(task.budget, "remaining"):
        return False
    if task.budget.remaining() <= 0:
        return False
    if not _validate_dag_transitions(task.steps):
        return False
    # At least one gated step: an all-ungated plan would complete with
    # zero checks and no decision, indistinguishable from a verified run.
    # Individual ungated steps (retrieval/proposal placeholders) are fine.
    return any(_hook(s) for s in task.steps)
