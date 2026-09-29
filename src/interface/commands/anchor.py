"""L2 tamper-evidence verification: `aci verify-chain`.

The events table is a global interleaved log — every run appends with a
fresh ledger, so cross-task links are broken by construction. Chain
verification therefore always scopes to one task's subchain (events with
matching `task_id`, in stored order), never the whole table. Without
`--task-id` and without an anchor file, every task group is checked and
the worst verdict wins.

Verdicts:
- CHAIN_VALID — links hold (and the pinned head matches, when anchored).
- CHAIN_BROKEN — an internal `prev_event_hash` link fails.
- HEAD_MISMATCH — links hold but the head differs from the pinned
  anchor (e.g. last-event payload rewritten), no anchor exists for
  the target task, or the anchor file itself has malformed lines.
  Fail closed: an unconfirmable chain is not a valid one, and a
  truncated log must never verify against its surviving prefix.
- NO_EVENTS — nothing recorded (empty DB, missing DB, or no events for
  the task). A wrong `--db` must not read as a clean chain.
"""
import os

from src.interface.commands import resolve_db
from src.memory.ledger import EventLedger, read_anchors
from src.storage.graph_store import GraphStore


def _subchain(events: list, task_id: str) -> list:
    return [e for e in events if (e.task_id or "") == task_id]


def run_verify_chain(db_path: str | None = None, anchor_path: str | None = None,
                     task_id: str | None = None) -> dict:
    db = resolve_db(db_path)
    if not os.path.exists(db):
        return {"db_path": db, "status": "NO_EVENTS", "events": 0,
                "task_id": task_id or "", "error": "db_not_found"}
    store = GraphStore(db)
    try:
        ledger = EventLedger.load_from_store(store)
    finally:
        store.close()
    events = ledger.get_events()
    if not events:
        return {"db_path": db, "status": "NO_EVENTS", "events": 0,
                "task_id": task_id or "", "error": "no_events_recorded"}

    anchor_records: list[dict] = []
    if anchor_path:
        anchor_records, malformed = read_anchors(anchor_path)
        if malformed:
            return {"db_path": db, "status": "HEAD_MISMATCH",
                    "events": len(events), "task_id": task_id or "",
                    "error": "anchor_file_corrupt", "malformed_lines": malformed}
        if not task_id and anchor_records:
            # No target given: the latest anchor line names the target.
            task_id = anchor_records[-1].get("task_id") or ""

    if task_id:
        scoped = EventLedger()
        scoped._events = _subchain(events, task_id)
        if not scoped._events:
            return {"db_path": db, "status": "NO_EVENTS", "events": len(events),
                    "task_id": task_id, "error": "no_events_for_task"}
        if not scoped.verify_chain():
            return {"db_path": db, "status": "CHAIN_BROKEN", "events": len(events),
                    "task_id": task_id}
        if anchor_path:
            records = [r for r in anchor_records if r.get("task_id") == task_id]
            if not records:
                return {"db_path": db, "status": "HEAD_MISMATCH",
                        "events": len(events), "task_id": task_id,
                        "error": "no_anchor_for_task"}
            if not scoped.verify_chain(records[-1]["head_hash"]):
                return {"db_path": db, "status": "HEAD_MISMATCH",
                        "events": len(events), "task_id": task_id,
                        "anchor_timestamp": records[-1].get("timestamp")}
        return {"db_path": db, "status": "CHAIN_VALID", "events": len(events),
                "task_id": task_id, "head_hash": scoped.head_hash()}

    # Unanchored, untargeted: every task group must hold.
    groups: dict[str, list] = {}
    for event in events:
        groups.setdefault(event.task_id or "", []).append(event)
    for group_task, group_events in groups.items():
        scoped = EventLedger()
        scoped._events = list(group_events)
        if not scoped.verify_chain():
            return {"db_path": db, "status": "CHAIN_BROKEN", "events": len(events),
                    "task_id": group_task}
    return {"db_path": db, "status": "CHAIN_VALID", "events": len(events),
            "task_id": ""}
