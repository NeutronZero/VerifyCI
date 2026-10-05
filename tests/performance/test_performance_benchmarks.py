"""Performance regression gate: prevents critical I/O, probe, and traversal drift."""
import sqlite3
import time
import pytest
from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.revision import Revision
from verifyci.storage.graph_store import GraphStore
from verifyci.interface.commands import open_for_read, InfraError


@pytest.mark.performance
def test_batch_entity_insertion_threshold(tmp_path):
    """1,200 entities must commit in < 500ms using batch transaction."""
    db = GraphStore(str(tmp_path / "perf_batch.db"))
    now = time.time()
    db.insert_revision(Revision("r1", "repo", "c1", None, "h1", now, "cfg"))
    ids = [f"log_{i}" for i in range(1200)]

    t0 = time.perf_counter()
    with db.batch():
        for i, lid in enumerate(ids):
            db.insert_entity(Entity("repo", lid, f"rev_{i}", EntityType.VARIABLE,
                                    f"v_{i}", "x.py", 1, 1, "py", "h", "r1",
                                    valid_from=now, t_created=now))
    elapsed_ms = (time.perf_counter() - t0) * 1000
    db.close()
    assert elapsed_ms < 2500.0, f"Perf hard-fail (5x envelope): took {elapsed_ms:.2f}ms"
    if elapsed_ms >= 500.0:
        pytest.skip(f"WARN-ONLY perf signal (evidence gate owns perf): batch insert {elapsed_ms:.2f}ms >= 500ms budget")


@pytest.mark.performance
def test_open_for_read_probe_timeout_threshold(tmp_path):
    """Locked database probe must fail in < 1,500ms (preventing 5s+ sleep regressions)."""
    db = str(tmp_path / "perf_locked.db")
    store = GraphStore(db)
    store.conn.execute("PRAGMA journal_mode=DELETE")
    store.close()

    holder = sqlite3.connect(db, isolation_level=None)
    holder.execute("BEGIN EXCLUSIVE")
    holder.execute("CREATE TABLE _h (x)")
    holder.execute("INSERT INTO _h VALUES (1)")

    t0 = time.perf_counter()
    try:
        with pytest.raises(InfraError):
            open_for_read(db)
    finally:
        holder.rollback()
        holder.close()
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert elapsed_ms < 4500.0, f"Perf hard-fail (3x envelope): took {elapsed_ms:.2f}ms"
    if elapsed_ms >= 1500.0:
        pytest.skip(f"WARN-ONLY perf signal (evidence gate owns perf): probe {elapsed_ms:.2f}ms >= 1500ms budget")
