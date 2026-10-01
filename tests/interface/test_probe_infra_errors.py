"""A5: infrastructure errors must not masquerade as verdicts.

Reproduced against the pre-fix tree: a MISSING database and a LOCKED
database both produced `INCONCLUSIVE` from run_verify (rationale
"checks_ran_but_nothing_established") — an ordinary verification verdict
for a gate that never ran. stats reported the error only in a dict
field while the CLI still exited 0. Contract after the fix:

    PASS -> 0, FAIL -> 1, HUMAN_REVIEW -> 2, INCONCLUSIVE -> 2,
    INFRA_ERROR -> 3.

The four V1 verdict states are untouched; INFRA_ERROR is a separate
channel the commands take when storage cannot answer at all.
"""
import os
import sqlite3

from typer.testing import CliRunner

from verifyci.interface.cli import app
from verifyci.storage.graph_store import GraphStore


DIFF = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n"
        "@@ -1,1 +1,1 @@\n-x\n+y\n")


def _valid_empty_db(tmp_path, name="v.db"):
    db = str(tmp_path / name)
    GraphStore(db).close()
    return db


def _locked(conn: sqlite3.Connection):
    conn.execute("BEGIN EXCLUSIVE")
    conn.execute("CREATE TABLE IF NOT EXISTS _hold (x)")
    conn.execute("INSERT INTO _hold VALUES (1)")


# ----------------------------------------------------- missing database ---

def test_verify_missing_db_is_infra_error(tmp_path):
    from verifyci.interface.commands.verify import run_verify
    r = run_verify(DIFF, db_path=str(tmp_path / "ghost.db"))
    assert r["status"] == "INFRA_ERROR", r
    assert r["error"] == "db_not_found"


def test_verify_missing_db_cli_exit_3(tmp_path):
    runner = CliRunner()
    r = runner.invoke(app, ["verify-diff", DIFF, "--db",
                            str(tmp_path / "ghost.db")])
    assert r.exit_code == 3, r.output
    assert "INFRA_ERROR" in r.output


def test_run_missing_db_is_infra_error(tmp_path):
    from verifyci.interface.commands.run import run_task
    db = str(tmp_path / "ghost.db")
    r = run_task("t", db_path=db)
    assert r.get("error") == "db_not_found", r
    assert r["status"] == "INFRA_ERROR", r
    assert not os.path.exists(db), "a read command must not create the DB"


def test_run_missing_db_cli_exit_3(tmp_path):
    runner = CliRunner()
    r = runner.invoke(app, ["run", "t", "--db", str(tmp_path / "ghost.db")])
    assert r.exit_code == 3, r.output


def test_stats_missing_db_cli_exit_3(tmp_path):
    runner = CliRunner()
    r = runner.invoke(app, ["stats", "--db", str(tmp_path / "ghost.db")])
    assert r.exit_code == 3, r.output
    assert "error" in r.output.lower()


def test_query_missing_db_cli_exit_3(tmp_path):
    runner = CliRunner()
    r = runner.invoke(app, ["query", "where?", "--db", str(tmp_path / "ghost.db")])
    assert r.exit_code == 3, r.output


def test_vuln_error_cli_exit_3(tmp_path):
    runner = CliRunner()
    r = runner.invoke(app, ["vuln", "--db", str(tmp_path / "ghost.db")])
    # run_vuln already reports the error honestly in its dict; the CLI
    # must not then exit 0 as if a clean report were produced.
    assert r.exit_code == 3, r.output


# ------------------------------------------------------- locked database --

def _legacy_db(tmp_path, name="legacy.db"):
    """A database forced back to journal_mode=DELETE, like every store
    written before the WAL fix: an exclusive writer genuinely blocks
    readers, so a reader must report db_locked rather than a verdict."""
    db = str(tmp_path / name)
    store = GraphStore(db)
    store.conn.execute("PRAGMA journal_mode=DELETE")
    store.close()
    return db


def test_verify_legacy_locked_db_is_infra_error(tmp_path):
    from verifyci.interface.commands.verify import run_verify
    db = _legacy_db(tmp_path)
    holder = sqlite3.connect(db, isolation_level=None)
    holder.execute("BEGIN EXCLUSIVE")
    holder.execute("CREATE TABLE IF NOT EXISTS _hold (x)")
    holder.execute("INSERT INTO _hold VALUES (1)")
    try:
        r = run_verify(DIFF, db_path=db)
        assert r["status"] == "INFRA_ERROR", r
        assert r["error"] == "db_locked"
    finally:
        holder.rollback()
        holder.close()


def test_verify_legacy_locked_db_cli_exit_3(tmp_path):
    db = _legacy_db(tmp_path)
    holder = sqlite3.connect(db, isolation_level=None)
    holder.execute("BEGIN EXCLUSIVE")
    holder.execute("CREATE TABLE _h (x)")
    holder.execute("INSERT INTO _h VALUES (1)")
    try:
        r = CliRunner().invoke(app, ["verify-diff", DIFF, "--db", db])
        assert r.exit_code == 3, r.output
    finally:
        holder.rollback()
        holder.close()


def test_corrupt_db_is_infra_error(tmp_path):
    from verifyci.interface.commands.verify import run_verify
    db = str(tmp_path / "corrupt.db")
    with open(db, "wb") as fh:
        fh.write(b"x" * 4096)  # valid path, not a database
    r = run_verify(DIFF, db_path=db)
    assert r["status"] == "INFRA_ERROR", r
    assert r["error"] == "db_unreadable"


# ------------------------------------------------------- invalid revision -

def test_verify_unknown_revision_is_infra_error(tmp_path):
    from verifyci.interface.commands.verify import run_verify
    db = _valid_empty_db(tmp_path)
    r = run_verify(DIFF, revision_id="deadbeef-not-a-rev", db_path=db)
    assert r["status"] == "INFRA_ERROR", r
    assert r["error"] == "revision_not_found"


# -------------------------------------------- NOT infrastructure (guards) --

def test_valid_empty_db_stays_a_verdict(tmp_path):
    # A real database that simply has no revisions yet is a state the
    # gate CAN judge: INCONCLUSIVE (nothing to ground on), exit 2 —
    # explicitly not INFRA_ERROR. This guard keeps the fix from
    # collapsing "empty" into "broken".
    from verifyci.interface.commands.verify import run_verify
    db = _valid_empty_db(tmp_path)
    r = run_verify(DIFF, db_path=db)
    assert r["status"] == "INCONCLUSIVE", r


def test_secret_diff_fails_even_on_valid_empty_db(tmp_path):
    from verifyci.interface.commands.verify import run_verify
    db = _valid_empty_db(tmp_path)
    secret = ('diff --git a/s.py b/s.py\n--- a/s.py\n+++ b/s.py\n'
              '@@ -1,0 +1,1 @@\n+password = "hunter2hunter2"\n')
    r = run_verify(secret, db_path=db)
    assert r["status"] == "FAIL", r


def test_malformed_diff_is_a_verdict_not_infra(tmp_path):
    # A gibberish "diff" against a VALID db: the gate ran and could not
    # ground it -> INCONCLUSIVE (verdict), not INFRA_ERROR.
    from verifyci.interface.commands.verify import run_verify
    db = _valid_empty_db(tmp_path)
    r = run_verify("def f(): pass  # not a diff at all", db_path=db)
    assert r["status"] == "INCONCLUSIVE", r


# ------------------------------------------------- verify-chain separation -

def test_chain_missing_db_stays_fail_closed_no_events():
    # verify-chain already refuses to masquerade: NO_EVENTS + explicit
    # db_not_found + exit 1 (closure-pinned). Not migrated to the new
    # channel; this guard pins that it STAYS fail-closed either way.
    from verifyci.interface.commands.anchor import run_verify_chain
    r = run_verify_chain(str(tmp_path := __import__("pathlib").Path() / "ghost-test.db"),
                         None, None)
    assert r["status"] == "NO_EVENTS", r
    assert r["error"] == "db_not_found"
    rr = CliRunner().invoke(app, ["verify-chain", "--db",
                                  str(tmp_path / "ghost.db")])
    assert rr.exit_code == 1, rr.output


def test_chain_empty_db_is_no_events(tmp_path):
    # Presence without events is a data state, not an infrastructure
    # failure: stays NO_EVENTS (fail-closed) with exit 1.
    from verifyci.interface.commands.anchor import run_verify_chain
    db = _valid_empty_db(tmp_path, "e.db")
    r = run_verify_chain(db, None, None)
    assert r["status"] == "NO_EVENTS", r
    rr = CliRunner().invoke(app, ["verify-chain", "--db", db])
    assert rr.exit_code == 1, rr.output


# ------------------------------------------------------------ WAL ---------

def test_store_enables_wal(tmp_path):
    db = _valid_empty_db(tmp_path, "w.db")
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    finally:
        conn.close()


def test_concurrent_read_during_ingest_transaction(tmp_path):
    """The WAL's actual job here: while a long ingest transaction is
    open, readers (verify/stats/query surfaces) still see the last
    committed state instead of hitting 'database is locked'."""
    from verifyci.interface.commands import open_for_read
    db = _valid_empty_db(tmp_path, "c.db")
    writer = GraphStore(db)
    try:
        with writer.batch():
            from verifyci.storage.revision import create_revision
            writer.insert_revision(create_revision(repository_id="r",
                                                   files=[("a.py", "h1")]))
            # mid-transaction read: must not raise
            ro = open_for_read(db)
            try:
                n = ro.execute("SELECT count(*) FROM revisions").fetchone()[0]
            finally:
                ro.close()
            assert n == 0, "uncommitted revision leaked into the reader"
        ro = open_for_read(db)
        try:
            n = ro.execute("SELECT count(*) FROM revisions").fetchone()[0]
        finally:
            ro.close()
        assert n == 1, "commit invisible to a later reader"
    finally:
        writer.close()
