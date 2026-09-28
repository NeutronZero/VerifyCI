import asyncio

from src.contracts.scheduler import TERMINAL_STATUSES
from src.interface.commands import resolve_db
from src.interface.commands.graph_loader import load_graph
from src.interface.commands.verify import _default_invariants
from src.memory.ledger import EventLedger
from src.orchestration.compiler.validation import validate_task_ir
from src.orchestration.intent import build_intent_package
from src.orchestration.planner import Planner
from src.orchestration.scheduler import AsyncDAGScheduler
from src.storage.graph_store import GraphStore


def run_task(task: str, timeout: float = 30.0, diff: str = "",
             db_path: str | None = None) -> dict:
    async def _run() -> dict:
        planner = Planner()
        intent = build_intent_package(task)
        task_ir = planner.plan(task, intent.intent_package_id, "default")
        if not validate_task_ir(task_ir):
            return {"task": task, "status": "FAILED", "error": "invalid_task_ir"}
        db = resolve_db(db_path)
        graph, node_map, entities = load_graph(db)
        ledger = EventLedger()
        store = GraphStore(db)
        try:
            scheduler = AsyncDAGScheduler(ledger=ledger)
            context = {
                "graph": graph, "node_map": node_map, "entities": entities,
                "invariants": intent.invariants + _default_invariants(),
                "diff": diff, "store": store,
            }
            task_id = await scheduler.submit(task_ir, context=context)
            for _ in range(int(timeout * 10)):
                status = await scheduler.status(task_id)
                if status in TERMINAL_STATUSES:
                    decision = scheduler.decision(task_id)
                    return {"task": task, "task_id": task_id, "status": status.value,
                            "steps": len(task_ir.steps),
                            "decision": decision.status if decision else None,
                            "rationale": decision.rationale if decision else None}
                await asyncio.sleep(0.1)
            return {"task": task, "task_id": task_id, "status": "TIMEOUT", "steps": len(task_ir.steps)}
        finally:
            store.close()

    return asyncio.run(_run())
