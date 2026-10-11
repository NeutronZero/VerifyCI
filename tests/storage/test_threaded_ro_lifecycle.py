import concurrent.futures
import os
from pathlib import Path
import time

from verifyci.contracts.revision import Revision
from verifyci.storage.graph_store import GraphStore


def _init_test_db(db_path: str, rev_id: str = "rev_1") -> None:
    store = GraphStore(db_path)
    rev = Revision(
        revision_id=rev_id,
        repository_id="repo_concurrent",
        commit_id="commit_initial",
        parent_revision_id=None,
        source_hash="hash_initial",
        timestamp=time.time(),
        ingestion_config_hash="cfg_hash",
    )
    store.insert_revision(rev)
    store.close()


def test_nested_store_lifetimes_in_same_thread(tmp_path: Path):
    """Closing one store instance must not invalidate or close another store instance."""
    db_file = tmp_path / "nested.db"
    _init_test_db(str(db_file), "rev_nested")

    store1 = GraphStore(str(db_file), read_only=True)
    store2 = GraphStore(str(db_file), read_only=True)

    assert store1.latest_revision_id("repo_concurrent") == "rev_nested"
    assert store2.latest_revision_id("repo_concurrent") == "rev_nested"

    # Close store1
    store1.close()

    # store2 must remain completely valid and readable
    assert store2.latest_revision_id("repo_concurrent") == "rev_nested"
    store2.close()

    # After both close, file must be immediately deletable on Windows
    os.remove(str(db_file))
    assert not db_file.exists()


def test_concurrent_reader_threads_and_cleanup(tmp_path: Path):
    """Multiple threads reading concurrently must not collide on SQLite thread affinity."""
    db_file = tmp_path / "concurrent.db"
    _init_test_db(str(db_file), "rev_concurrent")

    def _worker_read(worker_id: int) -> str:
        store = GraphStore(str(db_file), read_only=True)
        try:
            rev = store.latest_revision_id("repo_concurrent")
            time.sleep(0.01)
            return rev
        finally:
            store.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(_worker_read, i) for i in range(16)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(results) == 16
    assert all(r == "rev_concurrent" for r in results)

    # All connections closed -> file deletable immediately
    os.remove(str(db_file))
    assert not db_file.exists()
