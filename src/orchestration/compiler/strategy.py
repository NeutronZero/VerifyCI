from src.contracts.task_ir import TaskIR


def lower_to_dag(task: TaskIR) -> dict:
    return {
        "task_id": task.goal,
        "nodes": [{"step_id": s.step_id, "type": s.type, "config": dict(s.config),
                   "pre_commit_hook_id": s.pre_commit_hook_id,
                   "depends_on": list(s.depends_on)} for s in task.steps],
    }
