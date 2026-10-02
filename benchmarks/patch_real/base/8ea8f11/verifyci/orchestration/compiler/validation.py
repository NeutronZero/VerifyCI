from verifyci.contracts.task_ir import TaskIR


def _hook(step) -> object:
    return step.get('pre_commit_hook_id') if isinstance(step, dict) else getattr(step, 'pre_commit_hook_id', None)


def validate_task_ir(task: TaskIR) -> bool:
    if not task.goal:
        return False
    if not task.steps:
        return False
    if task.budget.remaining() <= 0:
        return False
    # At least one gated step: an all-ungated plan would complete with
    # zero checks and no decision, indistinguishable from a verified run.
    # Individual ungated steps (retrieval/proposal placeholders) are fine.
    return any(_hook(s) for s in task.steps)
