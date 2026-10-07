import asyncio
import logging
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any

from verifyci.contracts.scheduler import (
    ExecutableDAG, Scheduler, TERMINAL_STATUSES, TaskStatus,
)

logger = logging.getLogger(__name__)

# Node execution offload: `AsyncDAGScheduler._run_node` uses
# `asyncio.to_thread` (the loop's default executor, unbounded for our
# purposes and shared with unrelated work) under `asyncio.wait_for` for
# the deadline. `_NODE_POOL` below is reserved for future bounding of
# linger pileup when nodes block past their deadline; it is intentionally
# unused while the `to_thread` contract is locked by
# `tests/integration/test_robustness.py::test_run_node_uses_to_thread`.
# See `_run_node` for the timeout/linger semantics.
_NODE_POOL = ThreadPoolExecutor(
    max_workers=min(32, (os.cpu_count() or 1) + 4),
    thread_name_prefix="verifyci-node",
)


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
            "budget_nano_usd": dag.budget.nano_usd if hasattr(dag, "budget") else None,
        }
    if isinstance(dag, dict):
        return {
            "task_id": dag.get("task_id", ""),
            "nodes": dag.get("nodes", []),
            "conversation_id": dag.get("conversation_id", ""),
            "budget_nano_usd": dag.get("budget_nano_usd"),
        }
    return {"task_id": "", "nodes": [], "conversation_id": "", "budget_nano_usd": None}


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
            if dep not in by_id:
                raise ValueError(f"unknown_dependency:{dep}")
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
        # Aggregate mirror only: every submitted task gets its own
        # ledger (see submit). A single ledger shared across tasks
        # interleaves chains, so per-task heads and persisted offsets
        # would index the global list.
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
        from verifyci.memory.ledger import EventLedger
        self._tasks[task_id] = {
            "dag": dag_dict, "status": TaskStatus.PENDING,
            "conversation_id": conversation_id,
            "context": dict(context or {}),
            "decision": None, "error": None, "needs_review": False,
            "executing": False, "handle": None, "ledger_head": None, "persisted_count": 0,
            "ledger": EventLedger(),
        }
        self._emit("TASK_SUBMITTED", task_id, conversation_id, {"nodes": len(dag_dict["nodes"])})
        self._tasks[task_id]["handle"] = asyncio.create_task(self._execute(task_id))
        return task_id

    async def status(self, task_id: str) -> TaskStatus:
        task = self._tasks.get(task_id)
        # An unknown id is UNKNOWN, never FAILED: FAILED claims a run
        # happened and rejected the work, which would exit a CI gate as
        # a verdict on nothing. Callers map UNKNOWN to the infra channel.
        return task["status"] if task else TaskStatus.UNKNOWN

    def decision(self, task_id: str) -> Any:
        task = self._tasks.get(task_id)
        return task.get("decision") if task else None

    def ledger_head(self, task_id: str) -> Any:
        """Head hash of the task's own ledger (L1 tamper-evidence
        surfacing). Live-read from the per-task ledger so a mid-run
        head is meaningful; falls back to the terminal pin. None when
        the task is unknown or its ledger is empty."""
        task = self._tasks.get(task_id)
        if not task:
            return None
        ledger = task.get("ledger")
        if ledger is not None:
            try:
                head = ledger.head_hash()
                if head is not None:
                    return head
            except Exception as exc:  # noqa: BLE001
                logger.debug("Failed to read ledger head for task %s: %s", task_id, exc)
        return task.get("ledger_head")

    def _pin_head(self, task_id: str) -> None:
        """Pin the task ledger's head once the run is terminal, whatever
        path got it there (completed, failed, cancelled, review)."""
        task = self._tasks.get(task_id)
        if not task:
            return
        try:
            ledger = task.get("ledger")
            task["ledger_head"] = ledger.head_hash() if ledger is not None else None
        except Exception as exc:  # noqa: BLE001
            logger.debug("Failed to pin ledger head for task %s: %s", task_id, exc)
            task["ledger_head"] = None

    async def cancel(self, task_id: str) -> None:
        task = self._tasks.get(task_id)
        if task is None:
            return
        if task["status"] in TERMINAL_STATUSES:
            return
        task["status"] = TaskStatus.CANCELLED
        handle = task.get("handle")
        if handle is not None and not handle.done():
            handle.cancel()
            await asyncio.gather(handle, return_exceptions=True)
        # Emit-then-persist-then-pin: a TASK_CANCELLED recorded only in
        # memory never reaches the audit trail or the pinned head. The
        # _execute CancelledError path persists what ran before this;
        # this persists the cancellation itself, then pins over it.
        self._emit("TASK_CANCELLED", task_id, task["conversation_id"], {})
        await self._persist(task_id)
        self._pin_head(task_id)

    async def resume(self, task_id: str) -> None:
        task = self._tasks.get(task_id)
        if task is None:
            return
        # Never fork a second _execute against the same task record: a
        # still-running _execute owns the status writes.
        if task["status"] in (TaskStatus.CANCELLED, TaskStatus.FAILED) and not task.get("executing"):
            task["status"] = TaskStatus.PENDING
            task["handle"] = asyncio.create_task(self._execute(task_id))

    async def _execute(self, task_id: str) -> None:
        from verifyci.observability.tracing import start_agent_span

        task = self._tasks[task_id]
        if task.get("executing") or task["status"] != TaskStatus.PENDING:
            # Cancelled before start, or a duplicate _execute: the owner of
            # the record keeps it. Never clobber another run's status.
            return
        task["executing"] = True
        conversation_id = task["conversation_id"]
        try:
            with start_agent_span(f"task.{task_id}", conversation_id, "task.run"):
                task["status"] = TaskStatus.RUNNING
                self._emit("TASK_STARTED", task_id, conversation_id, {})
                try:
                    nodes = _topo_order(task["dag"]["nodes"])
                    budget = task["dag"].get("budget_nano_usd")
                    if budget is not None and len(nodes) * self.NODE_COST_NANO_USD > budget:
                        # Taxonomy: budget breach is a FAILED run with
                        # error "BUDGET_BREACHED" plus a BUDGET_BREACHED
                        # ledger event (persisted below) — not a separate
                        # TaskStatus, so exit mapping stays on the
                        # FAILED channel (CLI exit 1) and the head is
                        # still pinned in the finally.
                        task["status"] = TaskStatus.FAILED
                        task["error"] = "BUDGET_BREACHED"
                        self._emit("BUDGET_BREACHED", task_id, conversation_id,
                                   {"nodes": len(nodes), "budget_nano_usd": budget})
                        await self._persist(task_id)
                        return
                    from verifyci.orchestration.executor import Executor
                    executor = Executor()
                    shared = task.get("context", {}) or {}
                    review_status: str | None = None
                    for level in _levels(task["dag"]["nodes"]):
                        if task["status"] == TaskStatus.CANCELLED:
                            await self._persist(task_id)
                            return
                        outcomes = await self._run_level(
                            executor, level, task_id, conversation_id, shared)
                        # Precedence within a level: block > review > timeout >
                        # error > ok. A verification block or review decision
                        # must win over timeout/error/cancelled noise from
                        # siblings. Outcomes arrive in node order, so a
                        # cancelled sibling sorted first used to fail the
                        # task as "node_error: cancelled" and drop the
                        # verification decision entirely. Matches the
                        # ordering below (block, review, timeout, error,
                        # ok) and _run_level, which preempts siblings only
                        # on block/timeout/error — review is ordered but
                        # non-preempting by design.
                        ordered = [o for o in outcomes if o[0] == "block"]
                        ordered += [o for o in outcomes if o[0] == "review"]
                        ordered += [o for o in outcomes if o[0] == "timeout"]
                        ordered += [o for o in outcomes if o[0] == "error"]
                        ordered += [o for o in outcomes if o[0] == "ok"]
                        for outcome in ordered:
                            kind, decision = outcome
                            if kind == "ok":
                                # Passing gates still produce decisions; the last
                                # one labels the run so the ledger carries the
                                # rationale even when nothing failed.
                                if decision is not None and not task.get('needs_review'):
                                    task["decision"] = decision
                                continue
                            if kind == "block":
                                task["decision"] = decision
                                task["status"] = TaskStatus.FAILED
                                self._emit("TASK_FAILED", task_id, conversation_id,
                                           {"reason": "verification_failed",
                                            "decision": getattr(decision, "status", None),
                                            "rationale": getattr(decision, "rationale", None)})
                                await self._persist(task_id)
                                return
                            if kind == "review":
                                task["decision"] = decision
                                task["needs_review"] = True
                                status = getattr(decision, "status", "HUMAN_REVIEW")
                                if status == "INCONCLUSIVE":
                                    review_status = "INCONCLUSIVE"
                                elif review_status is None:
                                    review_status = "HUMAN_REVIEW"
                            if kind == "timeout":
                                # A node that outran its deadline is TIMEOUT
                                # (exit 3 infrastructure), never FAILED: the
                                # gate did not reject the work, it never got
                                # to conclude. The lingered worker may still
                                # finish past the deadline, so node effects
                                # are at-most-once — surfaced on the result
                                # dict by run_task / task.run, not cancelled.
                                step_id, error = decision
                                task["status"] = TaskStatus.TIMEOUT
                                task["error"] = f"{step_id}: {error}"
                                self._emit("TASK_TIMEOUT", task_id, conversation_id,
                                           {"reason": "node_timeout", "step_id": step_id,
                                            "error": error})
                                await self._persist(task_id)
                                return
                            if kind == "error":
                                step_id, error = decision
                                task["status"] = TaskStatus.FAILED
                                task["error"] = f"{step_id}: {error}"
                                self._emit("TASK_FAILED", task_id, conversation_id,
                                           {"reason": "node_error", "step_id": step_id,
                                            "error": error})
                                await self._persist(task_id)
                                return
                    if review_status == "INCONCLUSIVE":
                        task["status"] = TaskStatus.INCONCLUSIVE
                    elif review_status == "HUMAN_REVIEW":
                        task["status"] = TaskStatus.HUMAN_REVIEW
                    else:
                        task["status"] = TaskStatus.COMPLETED
                    self._emit("TASK_COMPLETED", task_id, conversation_id,
                               {"needs_review": task["needs_review"],
                                "status": task["status"].value,
                                "decision": getattr(task.get("decision"), "status", None),
                                "rationale": getattr(task.get("decision"), "rationale", None)})
                    await self._persist(task_id)
                except asyncio.CancelledError:
                    # Loop shutdown or cancel(): leave CANCELLED alone, and
                    # never report a half-run as anything else.
                    if task["status"] != TaskStatus.CANCELLED:
                        task["status"] = TaskStatus.CANCELLED
                        task["error"] = "cancelled"
                        self._emit("TASK_CANCELLED", task_id, conversation_id, {})
                    await self._persist(task_id)
                    raise
                except Exception as e:  # noqa: BLE001
                    task["status"] = TaskStatus.FAILED
                    task["error"] = f"{type(e).__name__}: {e}"
                    self._emit("TASK_FAILED", task_id, conversation_id,
                               {"reason": f"{type(e).__name__}: {e}"})
                    await self._persist(task_id)
        finally:
            task["executing"] = False
            # L1: pin the ledger head once the run is terminal, whatever
            # path got it there (completed, failed, cancelled, review).
            # A second _execute can never run concurrently (resume is
            # guarded), so the head cannot be clobbered mid-flight.
            if task["status"] in TERMINAL_STATUSES:
                self._pin_head(task_id)

    async def _run_level(self, executor, level: list[dict], task_id: str,
                         conversation_id: str, shared: dict) -> list:
        """Run one level; on an unexpected node error or verification block,
        cancel the still-running siblings instead of leaving them to run."""
        tasks = [asyncio.create_task(
            self._run_node(executor, node, task_id, conversation_id, shared))
            for node in level]
        results = [None] * len(tasks)
        pending = set(tasks)
        task_to_idx = {t: i for i, t in enumerate(tasks)}

        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                idx = task_to_idx[t]
                if t.cancelled():
                    results[idx] = ("error", (level[idx].get("step_id", "unknown"), "cancelled"))
                    continue
                exc = t.exception()
                if exc is not None:
                    results[idx] = ("error", (level[idx].get("step_id", "unknown"), f"{type(exc).__name__}: {exc}"))
                else:
                    results[idx] = t.result()

            has_terminating = any(results[task_to_idx[t]][0] in ("block", "timeout", "error")
                                  for t in done if results[task_to_idx[t]] is not None)
            if has_terminating:
                for other in pending:
                    other.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                for other in pending:
                    oidx = task_to_idx[other]
                    if results[oidx] is None:
                        results[oidx] = ("error", (level[oidx].get("step_id", "unknown"), "cancelled"))
                return results
        return results

    async def _run_node(self, executor, node: dict, task_id: str,
                        conversation_id: str, shared: dict) -> tuple[str, Any]:
        from verifyci.orchestration.executor import HumanReviewRequired, VerificationBlocker
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
            waivers=config.get("waivers", shared.get("waivers", [])),
            vuln_cache=shared.get("vuln_cache"),
            dependency_graph=shared.get("dependency_graph"),
        )
        timeout = config.get("timeout", None)
        if timeout is None:
            timeout = shared.get("node_timeout", 300)
        # Timeout bounds the wait, not the work: asyncio cannot kill a
        # thread once started, so after a timeout the to_thread worker may
        # linger until _invoke returns. to_thread uses the loop's default
        # executor (unbounded, shared); the timeout is configurable per
        # node (config "timeout", else shared "node_timeout", default
        # 300s); the loop never blocks on the lingerer, so a slow node
        # cannot deadlock the scheduler — but treat node side effects
        # past the deadline as at-most-once, not cancelled (surfaced as
        # "at_most_once": True on TIMEOUT result dicts).
        try:
            def _invoke():
                return asyncio.run(executor.execute_node(node_obj, ctx))
            result = await asyncio.wait_for(asyncio.to_thread(_invoke), timeout=timeout)
            return ("ok", getattr(result, "decision", None))
        except HumanReviewRequired as e:
            return ("review", e.decision)
        except VerificationBlocker as e:
            return ("block", e.decision)
        except (asyncio.TimeoutError, TimeoutError):
            step = node.get("step_id") or "unknown"
            return ("timeout", (step, f"TimeoutError: node_timeout after {timeout}s"))
        except Exception as e:  # noqa: BLE001
            # Unexpected node failure, attributed: which step, what type,
            # what message. The generic _execute handler can no longer tell.
            step = node.get("step_id") or "unknown"
            return ("error", (step, f"{type(e).__name__}: {e}"))

    async def _persist(self, task_id: str) -> None:
        """Persist the task ledger to the shared store (events table).

        Runs synchronously in the loop thread: the store is same-thread
        sqlite, and cross-thread use corrupts it. A persist failure is
        reported on stderr and recorded on the task — never swallowed,
        since a verification product that silently drops its audit trail
        is worse than one that errors loudly. Surfaced outward via
        `audit_degraded`/`persist_error` (see `run_task._audit_notes`):
        the run status/exit is unchanged — a degraded audit trail is
        not a verification verdict.
        """
        task = self._tasks.get(task_id)
        if not task:
            return
        store = (task.get("context", {}) or {}).get("store")
        ledger = task.get("ledger")
        if store is None or ledger is None or not hasattr(ledger, "save_to_store"):
            return
        try:
            persisted = task.get("persisted_count", 0)
            events = ledger.get_events()[persisted:]
            if not events:
                return
            if hasattr(store, "insert_events"):
                store.insert_events(events)
            elif hasattr(store, "batch"):
                with store.batch():
                    for e in events:
                        store.insert_event(e)
            else:
                for e in events:
                    store.insert_event(e)
            task["persisted_count"] = persisted + len(events)
        except Exception as e:  # noqa: BLE001
            import sys
            task["audit_degraded"] = True
            task["persist_error"] = f"{type(e).__name__}: {e}"
            sys.stderr.write(f"[WARNING] scheduler persist degraded for task {task_id}: {type(e).__name__}: {e}\n")

    def _emit(self, event_type: str, task_id: str, conversation_id: str, payload: dict) -> None:
        # Append to the task's own ledger; mirror into the shared
        # ledger when one was provided. The mirror receives the same
        # Event objects (never re-created), so ids and hashes match for
        # operators and back-compat readers.
        # NOTE: the first parameter is deliberately NOT named `type`:
        # it would shadow the builtin inside the except handlers below,
        # turning every emit failure into an uncaught TypeError instead
        # of a recorded emit_error.
        task = self._tasks.get(task_id)
        ledger = task.get("ledger") if task is not None else None
        if ledger is None:
            ledger = self._ledger
            if ledger is None:
                return
        try:
            event = ledger.append(
                type=event_type, payload={"task_id": task_id, **payload},
                provenance={"source": "scheduler"},
                task_id=task_id, conversation_id=conversation_id,
            )
        except Exception as e:  # noqa: BLE001
            import traceback
            if task is not None:
                task["emit_error"] = f"{type(e).__name__}: {e}"
            traceback.print_exc()
            return
        if self._ledger is not None and self._ledger is not ledger:
            try:
                self._ledger.adopt(event)
            except Exception as e:  # noqa: BLE001
                import traceback
                if task is not None:
                    task["emit_error"] = f"{type(e).__name__}: {e}"
                traceback.print_exc()
