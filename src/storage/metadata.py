import json
import sqlite3
from pathlib import Path


class MetadataStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
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
        self.conn.execute(
            "INSERT OR REPLACE INTO file_metadata VALUES (?,?,?,?,?)",
            (file_path, source_hash, language, __import__('time').time(), revision_id),
        )
        self.conn.commit()

    def get_file(self, file_path: str):
        return self.conn.execute(
            "SELECT * FROM file_metadata WHERE file_path = ?", (file_path,)
        ).fetchone()

    def close(self):
        self.conn.close()
