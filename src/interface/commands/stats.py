import sqlite3

from src.interface.commands import resolve_db


def run_stats(db_path: str | None = None) -> dict:
    db = resolve_db(db_path)
    conn = sqlite3.connect(db)
    try:
        stats = {}
        for table in ("revisions", "entities", "edges", "events", "anchors", "deltas"):
            try:
                stats[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.OperationalError:
                stats[table] = 0
        return {"db_path": db, **stats}
    finally:
        conn.close()
