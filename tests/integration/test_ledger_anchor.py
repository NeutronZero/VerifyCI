"""L1 head surfacing + L2 anchor-file verification, end to end.

The pinned scenario: run a task, anchor its head, rewrite the last
event's payload directly in SQLite. Links-only verification still
passes (the known last-event flaw); the anchored check fails closed.
"""
import json
import os
import sqlite3

from verifyci.interface.commands.anchor import run_verify_chain
from verifyci.interface.commands.run import run_task
from verifyci.memory.ledger import EventLedger, append_anchor, read_anchors


def _run(db, anchor=None):
    from verifyci.storage.graph_store import GraphStore
    if not os.path.exists(db):
        # run_task fails closed on a missing DB; a fresh schema-only
        # file is exactly what auto-creation used to provide.
        GraphStore(db).close()
    return run_task("probe task", diff="", db_path=db,
                    anchor_file=anchor)


def test_run_task_surfaces_ledger_head(tmp_path):
    db = str(tmp_path / "v.db")
    out = _run(db)
    assert out["status"] in ("COMPLETED", "FAILED", "INCONCLUSIVE",
                             "HUMAN_REVIEW", "TIMEOUT")
    if out["status"] != "TIMEOUT":
        assert out["ledger_head"]
    else:
        assert out["ledger_head"] is None


def test_anchor_round_trip_and_tamper_detection(tmp_path):
    db = str(tmp_path / "v.db")
    anchor = str(tmp_path / "heads.jsonl")
    out = _run(db, anchor)
    task_id, head = out["task_id"], out["ledger_head"]
    assert head

    records, malformed = read_anchors(anchor)
    assert malformed == 0
    assert len(records) == 1
    assert records[0]["task_id"] == task_id
    assert records[0]["head_hash"] == head

    # Baseline: anchored chain validates.
    assert run_verify_chain(db, anchor, task_id)["status"] == "CHAIN_VALID"

    # Tamper: rewrite the last event's payload directly in SQLite.
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT id, payload_json FROM events WHERE task_id = ? "
            "ORDER BY rowid DESC LIMIT 1", (task_id,)).fetchone()
        assert row is not None
        payload = json.loads(row[1])
        payload["tampered"] = True
        conn.execute("UPDATE events SET payload_json = ? WHERE id = ?",
                     (json.dumps(payload), row[0]))
        conn.commit()
    finally:
        conn.close()

    # Links-only still passes: the last event is anchored by nothing.
    from verifyci.storage.graph_store import GraphStore
    store = GraphStore(db)
    try:
        ledger = EventLedger.load_from_store(store)
    finally:
        store.close()
    assert ledger.verify_chain() is True

    # The anchored check fails closed.
    result = run_verify_chain(db, anchor, task_id)
    assert result["status"] == "HEAD_MISMATCH"


def test_broken_link_reports_chain_broken(tmp_path):
    db = str(tmp_path / "v.db")
    out = _run(db)
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT id FROM events WHERE task_id = ? ORDER BY rowid DESC LIMIT 1",
            (out["task_id"],)).fetchone()
        conn.execute("UPDATE events SET prev_event_hash = 'forged' WHERE id = ?",
                     (row[0],))
        conn.commit()
    finally:
        conn.close()
    assert run_verify_chain(db, None, out["task_id"])["status"] == "CHAIN_BROKEN"


def test_empty_db_is_no_events_not_valid(tmp_path):
    db = str(tmp_path / "missing.db")
    result = run_verify_chain(db, None, None)
    assert result["status"] == "NO_EVENTS"
    assert result["error"] == "db_not_found"

    conn = sqlite3.connect(str(tmp_path / "empty.db"))
    conn.close()
    result = run_verify_chain(str(tmp_path / "empty.db"), None, None)
    assert result["status"] == "NO_EVENTS"


def test_unanchored_valid_chain_reports_valid(tmp_path):
    db = str(tmp_path / "v.db")
    out = _run(db)
    result = run_verify_chain(db, None, out["task_id"])
    assert result["status"] == "CHAIN_VALID"
    assert result["head_hash"] == out["ledger_head"]


def test_anchor_for_unknown_task_mismatches(tmp_path):
    db = str(tmp_path / "v.db")
    out = _run(db)
    anchor = str(tmp_path / "heads.jsonl")
    append_anchor(anchor, "someone-else", "", "deadbeef")
    result = run_verify_chain(db, anchor, out["task_id"])
    assert result["status"] == "HEAD_MISMATCH"
    assert result["error"] == "no_anchor_for_task"


def test_read_anchors_counts_corrupt_lines(tmp_path):
    # Blank lines are benign; everything else without a head_hash is
    # damage, counted — never silently skipped.
    anchor = str(tmp_path / "heads.jsonl")
    with open(anchor, "w", encoding="utf-8") as fh:
        fh.write("\n")
        fh.write("not json\n")
        fh.write(json.dumps({"task_id": "t", "head_hash": "h"}) + "\n")
        fh.write(json.dumps({"task_id": "nohead"}) + "\n")
    records, malformed = read_anchors(anchor)
    assert records == [{"task_id": "t", "head_hash": "h"}]
    assert malformed == 2
    assert read_anchors(str(tmp_path / "absent.jsonl")) == ([], 0)


def test_corrupt_anchor_fails_closed(tmp_path):
    # A truncated log must never verify against its surviving prefix:
    # damage anywhere in the file is HEAD_MISMATCH, even when the
    # remaining records would confirm the chain.
    db = str(tmp_path / "v.db")
    anchor = str(tmp_path / "heads.jsonl")
    out = _run(db, anchor)
    assert run_verify_chain(db, anchor, out["task_id"])["status"] == "CHAIN_VALID"
    with open(anchor, "a", encoding="utf-8") as fh:
        fh.write("{truncated\n")
    result = run_verify_chain(db, anchor, out["task_id"])
    assert result["status"] == "HEAD_MISMATCH"
    assert result["error"] == "anchor_file_corrupt"
    assert result["malformed_lines"] == 1


def test_verify_chain_cli_exit_codes(tmp_path):
    from typer.testing import CliRunner
    from verifyci.interface.cli import app
    runner = CliRunner()
    missing = str(tmp_path / "missing.db")
    result = runner.invoke(app, ["verify-chain", "--db", missing])
    assert result.exit_code == 1
    assert "NO_EVENTS" in result.output
