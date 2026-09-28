import asyncio
import time
import uuid
from types import SimpleNamespace
from typing import Any

from src.contracts.scheduler import ExecutableDAG, Scheduler, TaskStatus


def _as_dag_dict(dag: Any) -> dict[str, Any]:
    if isinstance(dag, ExecutableDAG):
        return {
            "task_id": dag.task_id or dag.dag_id,
            "nodes": list(dag.nodes),
            "conversation_id": dag.conversation_id,
            "budget_nano_usd": dag.budget_nano_usd,
        }
    if hasattr(dag, "steps"):  # TaskIR
        return {
            "task_id": getattr(dag, "goal", ""),
            "nodes": [
                {"step_id": s.step_id, "type": s.type, "config": s.config,
                 "pre_commit_hook_id": s.pre_commit_hook_id, "depends_on": s.depends_on}
                for s in dag.steps
            ],
            "conversation_id": "",
            "budget_nano_usd": dag.budget.nano_usd if hasattr(dag, "budget") else 0,
        }
    if isinstance(dag, dict):
        return {
            "task_id": dag.get("task_id", ""),
            "nodes": dag.get("nodes", []),
            "conversation_id": dag.get("conversation_id", ""),
            "budget_nano_usd": dag.get("budget_nano_usd", 0),
        }
    return {"task_id": "", "nodes": [], "conversation_id": "", "budget_nano_usd": 0}


def _topo_order(nodes: list[dict]) -> list[dict]:
    by_id = {n.get("step_id"): n for n in nodes}
    visited: dict[str, str] = {}
    order: list[dict] = []

    def visit(n: dict) -> None:
        sid = n.get("step_id")
        state = visited.get(sid, "")
        if state == "done":
            return
        if state == "visiting":
            raise ValueError(f"cycle_detected:{sid}")
        visited[sid] = "visiting"
        for dep in n.get("depends_on", []) or []:
            if dep in by_id:
                visit(by_id[dep])
        visited[sid] = "done"
        order.append(n)

    for n in nodes:
        visit(n)
    return order


def _levels(nodes: list[dict]) -> list[list[dict]]:
    """Topological levels: nodes in one level are independent and may run
    concurrently. Raises ValueError on cycles."""
    ordered = _topo_order(nodes)
    depth: dict[str, int] = {}
    by_id = {n.get("step_id"): n for n in ordered}
    for n in ordered:
        deps = [d for d in (n.get("depends_on", []) or []) if d in by_id]
        depth[n.get("step_id")] = (max((depth[d] for d in deps), default=-1) + 1)
    buckets: dict[int, list[dict]] = {}
    for n in ordered:
        buckets.setdefault(depth[n.get("step_id")], []).append(n)
    return [buckets[k] for k in sorted(buckets)]


class AsyncDAGScheduler(Scheduler):
    NODE_COST_NANO_USD = 1_000_000  # 0.1 cent per node

    def __init__(self, ledger: Any = None) -> None:
        self._tasks: dict[str, dict[str, Any]] = {}
        self._ledger = ledger

    async def submit(self, dag: Any, conversation_id: str = "",
                     context: dict | None = None) -> str:
        """Submit a DAG. `context` carries shared verification inputs
        (graph, node_map, entities, invariants, diff, vuln_cache, store)
        forwarded to every node execution."""
        dag_dict = _as_dag_dict(dag)
        if not conversation_id:
            conversation_id = dag_dict.get("conversation_id", "") or str(uuid.uuid4())
        task_id = str(uuid.uuid4())
        self._tasks[task_id] = {
            "dag": dag_dict, "status": TaskStatus.PENDING,
            "conversation_id": conversation_id,
            "context": dict(context or {}),
            "decision": None, "error": None, "needs_review": False,
        }
        self._emit("TASK_SUBMITTED", task_id, conversation_id, {"nodes": len(dag_dict["nodes"])})
        asyncio.create_task(self._execute(task_id))
        return task_id

    async def status(self, task_id: str) -> TaskStatus:
        task = self._tasks.get(task_id)
        return task["status"] if task else TaskStatus.FAILED

    def decision(self, task_id: str) -> Any:
        task = self._tasks.get(task_id)
        return task.get("decision") if task else None

    async def cancel(self, task_id: str) -> None:
        if task_id in self._tasks:
            self._tasks[task_id]["status"] = TaskStatus.CANCELLED
            self._emit("TASK_CANCELLED", task_id, self._tasks[task_id]["conversation_id"], {})

    async def resume(self, task_id: str) -> None:
        if task_id in self._tasks and self._tasks[task_id]["status"] in (TaskStatus.CANCELLED, TaskStatus.FAILED):
            self._tasks[task_id]["status"] = TaskStatus.PENDING
            asyncio.create_task(self._execute(task_id))

    async def _execute(self, task_id: str) -> None:
        from src.observability.tracing import start_agent_span

        task = self._tasks[task_id]
        conversation_id = task["conversation_id"]
        with start_agent_span(f"task.{task_id}", conversation_id, "task.run"):
            task["status"] = TaskStatus.RUNNING
            self._emit("TASK_STARTED", task_id, conversation_id, {})
            try:
                nodes = _topo_order(task["dag"]["nodes"])
                budget = task["dag"].get("budget_nano_usd", 0)
                if budget and len(nodes) * self.NODE_COST_NANO_USD > budget:
                    task["status"] = TaskStatus.FAILED
                    task["error"] = "BUDGET_BREACHED"
                    self._emit("BUDGET_BREACHED", task_id, conversation_id,
                               {"nodes": len(nodes), "budget_nano_usd": budget})
                    return
                from src.orchestration.executor import Executor, HumanReviewRequired, VerificationBlocker
                executor = Executor()
                shared = task.get("context", {}) or {}
                review_status: str | None = None
                for level in _levels(task["dag"]["nodes"]):
                    outcomes = await asyncio.gather(*[
                        self._run_node(executor, node, task_id, conversation_id, shared)
                        for node in level
                    ])
                    for outcome in outcomes:
                        kind, decision = outcome
                        if kind == "block":
                            task["decision"] = decision
                            task["status"] = TaskStatus.FAILED
                            self._emit("TASK_FAILED", task_id, conversation_id,
                                       {"reason": "verification_failed"})
                            self._persist(task_id)
                            return
                        if kind == "review":
                            task["decision"] = decision
                            task["needs_review"] = True
                            status = getattr(decision, "status", "HUMAN_REVIEW")
                            if status == "INCONCLUSIVE":
                                review_status = "INCONCLUSIVE"
                            elif review_status is None:
                                review_status = "HUMAN_REVIEW"
                if review_status == "INCONCLUSIVE":
                    task["status"] = TaskStatus.INCONCLUSIVE
                elif review_status == "HUMAN_REVIEW":
                    task["status"] = TaskStatus.HUMAN_REVIEW
                else:
                    task["status"] = TaskStatus.COMPLETED
                self._emit("TASK_COMPLETED", task_id, conversation_id,
                           {"needs_review": task["needs_review"],
                            "status": task["status"].value})
                self._persist(task_id)
            except Exception as e:  # noqa: BLE001
                task["status"] = TaskStatus.FAILED
                task["error"] = str(e)
                self._emit("TASK_FAILED", task_id, conversation_id, {"reason": str(e)})

    async def _run_node(self, executor, node: dict, task_id: str,
                        conversation_id: str, shared: dict) -> tuple[str, Any]:
        from src.orchestration.executor import HumanReviewRequired, VerificationBlocker
        node_obj = SimpleNamespace(
            step_id=node.get("step_id"), type=node.get("type"),
            config=node.get("config", {}),
            pre_commit_hook_id=node.get("pre_commit_hook_id"),
            depends_on=node.get("depends_on", []),
        )
        config = node.get("config", {}) or {}
        ctx = SimpleNamespace(
            task_id=task_id, conversation_id=conversation_id,
            graph=shared.get("graph"),
            node_map=shared.get("node_map"),
            entities=shared.get("entities", []),
            diff=config.get("diff", shared.get("diff", "")),
            changed_entities=config.get("changed_entities", shared.get("changed_entities", [])),
            test_entities=shared.get("test_entities", []),
            invariants=config.get("invariants", shared.get("invariants", [])),
            vuln_cache=shared.get("vuln_cache"),
            dependency_graph=shared.get("dependency_graph"),
        )
        try:
            await executor.execute_node(node_obj, ctx)
            return ("ok", None)
        except HumanReviewRequired as e:
            return ("review", e.decision)
        except VerificationBlocker as e:
            return ("block", e.decision)

    def _persist(self, task_id: str) -> None:
        """Persist the task ledger to the shared store (events table)."""
        task = self._tasks.get(task_id)
        if not task:
            return
        store = (task.get("context", {}) or {}).get("store")
        if store is None or self._ledger is None or not hasattr(self._ledger, "save_to_store"):
            return
        try:
            self._ledger.save_to_store(store)
        except Exception:  # noqa: BLE001, S110
            pass

    def _emit(self, type: str, task_id: str, conversation_id: str, payload: dict) -> None:
        if self._ledger is None:
            return
        try:
            self._ledger.append(
                type=type, payload={"task_id": task_id, **payload},
                provenance={"source": "scheduler"},
                task_id=task_id, conversation_id=conversation_id,
            )
        except Exception:  # noqa: BLE001, S110
            pass
