"""L2 tamper-evidence verification: `verifyci verify-chain`.

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
- INFRA_ERROR — the database itself cannot be read (missing path,
  locked, corrupt). Infrastructure, not a chain verdict: exits 3, the
  same channel as every other read command.
"""
import os
import sqlite3

from verifyci.interface.commands import resolve_db
from verifyci.contracts.canonical import event_hash
from verifyci.memory.ledger import EventLedger, read_anchors, verify_task_subchain
from verifyci.storage.graph_store import GraphStore


def _subchain(events: list, task_id: str) -> list:
    return [e for e in events if (e.task_id or "") == task_id]


def run_verify_chain(db_path: str | None = None, anchor_path: str | None = None,
                     task_id: str | None = None) -> dict:
    db = resolve_db(db_path)
    if not os.path.exists(db):
        return {"db_path": db, "status": "INFRA_ERROR", "events": 0,
                "task_id": task_id or "", "error": "db_not_found"}
    try:
        store = GraphStore(db, read_only=True)
    except (sqlite3.Error, OSError) as e:
        return {"db_path": db, "status": "INFRA_ERROR", "events": 0,
                "task_id": task_id or "",
                "error": f"db_unreadable: {type(e).__name__}: {e}"}
    try:
        ledger = EventLedger.load_from_store(store)
    except sqlite3.Error as e:
        # Openable but schema-less file (0-byte, hand-made): sqlite
        # accepts it as an empty database — nothing was ever recorded.
        if "no such table" not in str(e):
            raise
        return {"db_path": db, "status": "NO_EVENTS", "events": 0,
                "task_id": task_id or "", "error": "no_events_recorded"}
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
        if anchor_path and not task_id:
            # Anchored verification was requested but no task can be
            # targeted (missing/empty log, or a latest record naming no
            # task). Fail closed: validating links alone here would
            # report CHAIN_VALID for a log that vouches for nothing.
            if not os.path.exists(anchor_path):
                error = "anchor_file_missing"
            elif not anchor_records:
                error = "anchor_file_empty"
            else:
                error = "anchor_task_unknown"
            return {"db_path": db, "status": "HEAD_MISMATCH",
                    "events": len(events), "task_id": "",
                    "error": error}

    if task_id:
        task_events = _subchain(events, task_id)
        if not task_events:
            return {"db_path": db, "status": "NO_EVENTS", "events": len(events),
                    "task_id": task_id, "error": "no_events_for_task"}
        if not verify_task_subchain(events, task_id):
            return {"db_path": db, "status": "CHAIN_BROKEN", "events": len(events),
                    "task_id": task_id}
        if anchor_path:
            records = [r for r in anchor_records if r.get("task_id") == task_id]
            if not records:
                return {"db_path": db, "status": "HEAD_MISMATCH",
                        "events": len(events), "task_id": task_id,
                        "error": "no_anchor_for_task"}
            if not verify_task_subchain(events, task_id, records[-1]["head_hash"]):
                return {"db_path": db, "status": "HEAD_MISMATCH",
                        "events": len(events), "task_id": task_id,
                        "anchor_timestamp": records[-1].get("timestamp")}
        return {"db_path": db, "status": "CHAIN_VALID", "events": len(events),
                "task_id": task_id, "head_hash": event_hash(task_events[-1])}

    # Unanchored, untargeted: every task group must hold.
    groups: dict[str, list] = {}
    for event in events:
        groups.setdefault(event.task_id or "", []).append(event)
    for group_task, group_events in groups.items():
        if not verify_task_subchain(events, group_task):
            return {"db_path": db, "status": "CHAIN_BROKEN", "events": len(events),
                    "task_id": group_task}
    return {"db_path": db, "status": "CHAIN_VALID", "events": len(events),
            "task_id": ""}
