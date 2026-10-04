from pathlib import Path


class InfraError(RuntimeError):
    """Storage could not be opened for reading — NOT a verification
    verdict. `load_graph` raises it for every open failure on an
    existing path (a missing path stays an empty graph, which callers
    report through the same channel). The four V1 verdict states
    (PASS/FAIL/HUMAN_REVIEW/INCONCLUSIVE) describe what the gate
    concluded *about a diff*; this describes the gate itself failing
    to run. The distinction is the whole point of a fail-closed
    product: infrastructure must never wear a verdict's clothes."""

    def __init__(self, kind: str, detail: str = ""):
        self.kind = kind
        super().__init__(detail or kind)


def open_for_read(db: str, timeout: float = 0.5):
    """Open a store read-only for a query/verify/stats command.

    Raises InfraError('db_not_found') when no database exists at the
    path and InfraError('db_locked'/'db_unreadable') when one exists
    but sqlite cannot answer (held by a writer on a legacy
    rollback-journal DB, or the file is damaged). Never creates, never
    changes the journal mode (a reader cannot promote or checkpoint
    WAL); mode=ro reads a WAL-mode DB whenever its -shm/-wal sidecars
    exist or the directory is writable — on a sealed read-only mount
    the DB must have been checkpointed/closed cleanly. Never returns
    an empty-but-successful store: an unreadable database is an error,
    not zero facts. The connection is returned open; callers close it."""
    import os
    import sqlite3
    from pathlib import Path
    if not os.path.exists(db):
        raise InfraError("db_not_found", db)
    try:
        # Resolved URI form: raw paths with "#", spaces, or non-ASCII
        # characters must survive the URI parser (same discipline as
        # run_stats' special-char handling).
        uri = Path(db).resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=timeout)
        try:
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        except BaseException:
            # A failed probe must not leak its connection: locked/corrupt
            # stores raised here on every infra-error path and warned at GC.
            conn.close()
            raise
    except sqlite3.Error as e:
        msg = str(e)
        if "locked" in msg or "busy" in msg:
            kind = "db_locked"
        elif ("not a database" in msg or "malformed" in msg
              or "unable to open" in msg or "disk" in msg):
            kind = "db_unreadable"
        else:
            kind = "db_unreadable"
        raise InfraError(kind, f"{db}: {msg}")
    return conn


def resolve_db(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    local = Path(".verifyci") / "verifyci.db"
    if local.exists():
        return str(local)
    return str(Path("storage") / "verifyci.db")


def resolve_repository(db_path: str | None) -> str | None:
    """Repository id implied by a DB path, or None.

    Ingest writes `<repo>/.verifyci/verifyci.db` with
    `repository_id=repo.name`, so a DB under `.verifyci` names its own
    repo (innermost `.verifyci` wins for nested checkouts). Anything
    else — custom `--db` paths, shared files — implies nothing, and
    callers fall back to the unscoped global lookup.
    """
    if not db_path:
        return None
    parts = Path(db_path).resolve().as_posix().split("/")
    if ".verifyci" not in parts:
        return None
    idx = len(parts) - 1 - parts[::-1].index(".verifyci")
    return parts[idx - 1] if idx > 0 else None
