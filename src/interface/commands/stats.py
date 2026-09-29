import sqlite3

from src.interface.commands import resolve_db


TABLES = ("revisions", "entities", "edges", "events", "anchors", "deltas")


def count_table(conn, table: str) -> int:
    """Count rows. Table names are never interpolated from untrusted input —
    anything outside the schema allowlist raises instead of executing."""
    if table not in TABLES:
        raise ValueError(f"unknown table: {table}")
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def run_stats(db_path: str | None = None) -> dict:
    db = resolve_db(db_path)
    conn = sqlite3.connect(db)
    try:
        stats = {}
        for table in TABLES:
            try:
                stats[table] = count_table(conn, table)
            except sqlite3.OperationalError:
                stats[table] = 0
        return {"db_path": db, **stats, **_resolution_stats(db)}
    finally:
        conn.close()


def _resolution_stats(db: str) -> dict:
    """How much of the cross-file reference load the deferred resolver
    actually linked: resolved / ambiguous / missing, plus stored
    unresolved edges awaiting a unique target. Same shape as
    `established=False` — a resolver that ran but established little
    must say so, or operators read edge counts as coverage. Build
    failures surface as an `error` note, never a zero-mask."""
    from src.graph.builder import GraphBuilder, UNRESOLVED_TYPES
    from src.storage.graph_store import GraphStore
    try:
        store = GraphStore(db)
        try:
            rows = store.conn.execute(
                "SELECT revision_id FROM revisions ORDER BY timestamp DESC LIMIT 1"
            ).fetchall()
            if not rows:
                return {"resolution": {"resolved": 0, "ambiguous": 0, "missing": 0}}
            revision_id = rows[0][0]
            entities = store.get_entities_by_revision(revision_id)
            edges = store.get_edges_by_revision(revision_id)
        finally:
            store.close()
        builder = GraphBuilder()
        builder.build(entities, edges)
        unresolved = sum(1 for e in edges if e.type in UNRESOLVED_TYPES)
        return {"resolution": {**builder.resolution_stats,
                               "unresolved_edges": unresolved}}
    except Exception as e:  # noqa: BLE001
        return {"resolution": {"resolved": 0, "ambiguous": 0, "missing": 0,
                               "error": f"{type(e).__name__}: {e}"}}
