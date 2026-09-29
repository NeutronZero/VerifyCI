"""Bulk-ingest atomicity: a failed batch rolls back, never half-commits."""
import pytest

from src.storage.graph_store import GraphStore
from src.storage.revision import create_revision


def test_batch_rolls_back_on_exception(tmp_path):
    store = GraphStore(str(tmp_path / "v.db"))
    try:
        rev = create_revision(repository_id="r", files=[])
        with pytest.raises(RuntimeError):
            with store.batch():
                store.insert_revision(rev)
                raise RuntimeError("boom mid-ingest")
        assert store.conn.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 0
    finally:
        store.close()


def test_batch_commits_on_success(tmp_path):
    store = GraphStore(str(tmp_path / "v.db"))
    try:
        rev = create_revision(repository_id="r", files=[])
        with store.batch():
            store.insert_revision(rev)
        assert store.conn.execute("SELECT COUNT(*) FROM revisions").fetchone()[0] == 1
    finally:
        store.close()
