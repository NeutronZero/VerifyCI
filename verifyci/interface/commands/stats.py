import os
import sqlite3

from verifyci.interface.commands import resolve_db


TABLES = ("revisions", "entities", "edges", "events", "anchors", "deltas")


def count_table(conn, table: str) -> int:
    """Count rows. Table names are never interpolated from untrusted input —
    anything outside the schema allowlist raises instead of executing."""
    if table not in TABLES:
        raise ValueError(f"unknown table: {table}")
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def _open_readonly(db: str):
    """Open without creating anything: a stats command must not mkdir,
    schema-write, or materialize a database at a client-chosen path."""
    if not os.path.exists(db):
        raise sqlite3.OperationalError(f"no database at {db}")
    return sqlite3.connect(f"file:{db}?mode=ro", uri=True)


def run_stats(db_path: str | None = None) -> dict:
    db = resolve_db(db_path)
    try:
        conn = _open_readonly(db)
    except sqlite3.Error:
        return {"db_path": db, **{t: 0 for t in TABLES},
                "resolution": {"resolved": 0, "ambiguous": 0, "missing": 0}}
    try:
        stats = {}
        for table in TABLES:
            try:
                stats[table] = count_table(conn, table)
            except sqlite3.Error:
                stats[table] = 0
        return {"db_path": db, **stats, **_resolution_stats(conn, db)}
    finally:
        conn.close()


def _resolution_stats(conn, db_path: str) -> dict:
    """How much of the cross-file reference load the deferred resolver
    actually linked: resolved / ambiguous / missing, plus stored
    unresolved edges awaiting a unique target. Same shape as
    `established=False` — a resolver that ran but established little
    must say so, or operators read edge counts as coverage. Build
    failures surface as an `error` note, never a zero-mask. Read-only:
    shares the stats connection, creates nothing."""
    from verifyci.graph.builder import GraphBuilder, UNRESOLVED_TYPES
    from verifyci.interface.commands import resolve_repository
    from verifyci.storage.graph_store import GraphStore, latest_revision_id
    try:
        try:
            revision_id = latest_revision_id(conn, resolve_repository(db_path))
        except sqlite3.Error:
            # No revisions table yet (fresh/foreign file): nothing
            # ingested, nothing to resolve. Normal state, not an error.
            return {"resolution": {"resolved": 0, "ambiguous": 0, "missing": 0}}
        if not revision_id:
            return {"resolution": {"resolved": 0, "ambiguous": 0, "missing": 0}}
        entities = [GraphStore._row_to_entity(r) for r in conn.execute(
            "SELECT * FROM entities WHERE revision_id = ?", (revision_id,)).fetchall()]
        edges = [GraphStore._row_to_edge(r) for r in conn.execute(
            "SELECT * FROM edges WHERE revision_id = ?", (revision_id,)).fetchall()]
        builder = GraphBuilder()
        builder.build(entities, edges)
        unresolved = sum(1 for e in edges if e.type in UNRESOLVED_TYPES)
        return {"resolution": {**builder.resolution_stats,
                               "unresolved_edges": unresolved}}
    except Exception as e:  # noqa: BLE001
        return {"resolution": {"resolved": 0, "ambiguous": 0, "missing": 0,
                               "error": f"{type(e).__name__}: {e}"}}
