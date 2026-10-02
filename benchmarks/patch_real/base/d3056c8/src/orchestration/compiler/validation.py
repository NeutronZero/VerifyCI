from src.contracts.task_ir import TaskIR


def validate_task_ir(task: TaskIR) -> bool:
    if not task.goal:
        return False
    if not task.steps:
        return False
    if task.budget.remaining() <= 0:
        return False
    return True
