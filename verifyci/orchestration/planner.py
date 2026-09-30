import uuid

from verifyci.contracts.task_ir import TaskIR, Step, Budget


class Planner:
    STEPS = (
        ("retrieve_context", {"retrieval": "dense_bm25_graph_rrf"}),
        ("propose_change", {"verification": "pre_commit"}),
        ("verify_change", {"verification": "semi_formal"}),
    )

    def plan(self, goal: str, intent_package_id: str, policy_id: str) -> TaskIR:
        steps = []
        prev_id: str | None = None
        for step_type, config in self.STEPS:
            step_id = str(uuid.uuid4())
            steps.append(Step(
                step_id=step_id,
                type=step_type,
                config={**config, "goal": goal},
                # Only the verification step is gated: retrieve/propose
                # are placeholders that complete without running checks.
                # Gating every step ran the full pipeline 3x per task.
                pre_commit_hook_id="default" if step_type == "verify_change" else None,
                depends_on=[prev_id] if prev_id else [],
            ))
            prev_id = step_id
        return TaskIR(
            goal=goal,
            intent_package_id=intent_package_id,
            steps=steps,
            constraints=[],
            budget=Budget(budget_id=str(uuid.uuid4()), nano_usd=1_000_000_000),
            policy_id=policy_id,
        )
