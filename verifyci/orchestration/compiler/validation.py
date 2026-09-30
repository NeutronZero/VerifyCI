from verifyci.contracts.task_ir import TaskIR


def validate_task_ir(task: TaskIR) -> bool:
    if not task.goal:
        return False
    if not task.steps:
        return False
    if task.budget.remaining() <= 0:
        return False
    for s in task.steps:
        hid = s.get('pre_commit_hook_id') if isinstance(s, dict) else getattr(s, 'pre_commit_hook_id', None)
        if not hid:
            return False
    return True
