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
        return {"db_path": db, **stats}
    finally:
        conn.close()
