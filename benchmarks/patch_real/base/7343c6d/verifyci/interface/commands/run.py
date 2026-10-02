import asyncio

from verifyci.contracts.scheduler import TERMINAL_STATUSES
from verifyci.interface.commands import resolve_db
from verifyci.interface.commands.graph_loader import load_graph
from verifyci.verification.config import load_repo_invariants
from verifyci.memory.ledger import EventLedger
from verifyci.orchestration.compiler.validation import validate_task_ir
from verifyci.orchestration.intent import build_intent_package
from verifyci.orchestration.planner import Planner
from verifyci.orchestration.scheduler import AsyncDAGScheduler
from verifyci.storage.graph_store import GraphStore


def _dedupe_invariants(invariants: list) -> list:
    seen: set[tuple] = set()
    out = []
    for inv in invariants:
        key = (inv.compiled_query, inv.blocking)
        if key not in seen:
            seen.add(key)
            out.append(inv)
    return out


def _latest_revision_id(store, db_path: str = "") -> str:
    try:
        from verifyci.interface.commands import resolve_repository
        from verifyci.storage.graph_store import latest_revision_id
        return latest_revision_id(store.conn, resolve_repository(db_path))
    except Exception:  # noqa: BLE001
        return ""


def run_task(task: str, timeout: float = 30.0, diff: str = "",
             db_path: str | None = None,
             anchor_file: str | None = None) -> dict:
    """Run a task to a terminal state. The returned dict always carries
    ``ledger_head`` (L1 tamper-evidence surfacing; None when no ledger
    ran). With ``anchor_file``, the (task, revision, head) tuple is
    appended to a JSONL anchor log (L2) for later ``verify-chain``."""
    async def _run() -> dict:
        planner = Planner()
        intent = build_intent_package(task)
        task_ir = planner.plan(task, intent.intent_package_id, "default")
        if not validate_task_ir(task_ir):
            return {"task": task, "status": "FAILED", "error": "invalid_task_ir",
                    "ledger_head": None}
        db = resolve_db(db_path)
        # A missing or unreadable DB is infrastructure, not a task that
        # failed verification: FAILED would exit 1 as if the gate rejected
        # the work. Report INFRA_ERROR (exit 3) with the same honest key.
        from verifyci.interface.commands import InfraError, open_for_read
        try:
            probe = open_for_read(db)
        except InfraError as e:
            return {"task": task, "status": "INFRA_ERROR", "error": e.kind,
                    "ledger_head": None}
        probe.close()
        try:
            graph, node_map, entities = load_graph(db)
        except InfraError as e:
            return {"task": task, "status": "INFRA_ERROR", "error": e.kind,
                    "ledger_head": None}
        ledger = EventLedger()
        store = GraphStore(db)
        try:
            scheduler = AsyncDAGScheduler(ledger=ledger)
            context = {
                "graph": graph, "node_map": node_map, "entities": entities,
                # intent.invariants are the project defaults; repo rules
                # extend them. Dedupe by query so the defaults are not
                # evaluated twice with conflicting blocking flags.
                "invariants": _dedupe_invariants(
                    intent.invariants + load_repo_invariants(db)),
                "diff": diff, "store": store,
            }
            task_id = await scheduler.submit(task_ir, context=context)
            for _ in range(int(timeout * 10)):
                status = await scheduler.status(task_id)
                if status in TERMINAL_STATUSES:
                    decision = scheduler.decision(task_id)
                    head = scheduler.ledger_head(task_id)
                    result = {"task": task, "task_id": task_id, "status": status.value,
                              "steps": len(task_ir.steps),
                              "decision": decision.status if decision else None,
                              "rationale": decision.rationale if decision else None,
                              "ledger_head": head}
                    if anchor_file and head:
                        from verifyci.memory.ledger import append_anchor
                        append_anchor(anchor_file, task_id,
                                      _latest_revision_id(store, db), head)
                    return result
                await asyncio.sleep(0.1)
            return {"task": task, "task_id": task_id, "status": "TIMEOUT",
                    "steps": len(task_ir.steps), "ledger_head": None}
        finally:
            store.close()

    return asyncio.run(_run())
