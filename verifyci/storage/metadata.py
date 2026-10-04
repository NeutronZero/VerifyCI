import sqlite3
from pathlib import Path


class MetadataStore:
    def __init__(self, db_path: str, conn=None):
        self.db_path = db_path
        self._owns_conn = conn is None
        if conn is None:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(db_path, timeout=30.0)
        self.conn = conn
        try:
            if self._owns_conn:
                self.conn.execute("PRAGMA journal_mode=WAL")
                self.conn.execute("PRAGMA busy_timeout=5000")
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
        except BaseException:
            # Same half-open guarantee as GraphStore/open_for_read: a
            # failed schema setup must not leak an owned connection the
            # caller never receives.
            if self._owns_conn:
                self.conn.close()
            raise

    def upsert_file(self, file_path: str, source_hash: str, language: str, revision_id: str):
        # The ingest caller runs inside GraphStore.batch() with a shared
        # connection (_owns_conn False): no per-file commit there, or the
        # batch and its rollback are defeated. Standalone owners commit.
        self.conn.execute(
            "INSERT OR REPLACE INTO file_metadata VALUES (?,?,?,?,?)",
            (file_path, source_hash, language, __import__('time').time(), revision_id),
        )
        if self._owns_conn:
            self.conn.commit()

    def get_file(self, file_path: str):
        return self.conn.execute(
            "SELECT * FROM file_metadata WHERE file_path = ?", (file_path,)
        ).fetchone()

    def close(self):
        if self._owns_conn:
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
