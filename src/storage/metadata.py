import sqlite3
from pathlib import Path


class MetadataStore:
    def __init__(self, db_path: str, conn=None):
        self.db_path = db_path
        self._owns_conn = conn is None
        if conn is None:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(db_path)
        self.conn = conn
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS file_metadata (
                file_path TEXT PRIMARY KEY,
                source_hash TEXT NOT NULL,
                language TEXT,
                last_ingested REAL,
                revision_id TEXT
            )
        """)
        self.conn.commit()

    def upsert_file(self, file_path: str, source_hash: str, language: str, revision_id: str):
        # No commit here: the sole caller runs inside GraphStore.batch(),
        # and a per-file commit defeated both the batch and its rollback.
        self.conn.execute(
            "INSERT OR REPLACE INTO file_metadata VALUES (?,?,?,?,?)",
            (file_path, source_hash, language, __import__('time').time(), revision_id),
        )

    def get_file(self, file_path: str):
        return self.conn.execute(
            "SELECT * FROM file_metadata WHERE file_path = ?", (file_path,)
        ).fetchone()

    def close(self):
        if self._owns_conn:
            self.conn.close()
