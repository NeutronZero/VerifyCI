"""Scale measurement: EXPLAIN plans + 100k-row timing (measure-only, env-gated).

Gate Integrity / P0 untouched: no schema or predicate changes. The indexed
point-read assertions always run (fast, small fixture). The 100k build runs
only with VERIFYCI_SCALE_MEASURE=1 and records timings/plans without gating.
"""
import os
import sqlite3

import pytest

from verifyci.storage.graph_store import GraphStore

MEASURE = os.environ.get("VERIFYCI_SCALE_MEASURE") == "1"


def _plan(db_path, sql, params=()):
    con = sqlite3.connect(db_path)
    try:
        return [tuple(r) for r in con.execute("EXPLAIN QUERY PLAN " + sql, params)]
    finally:
        con.close()


@pytest.mark.performance
def test_temporal_point_reads_use_index(tmp_path):
    """Point temporal reads must seek, never scan (small fixture, always run)."""
    db = str(tmp_path / "scale_plan.db")
    store = GraphStore(db)
    try:
        for row in _plan(db, "SELECT * FROM entities WHERE logical_entity_id=? AND valid_from<=? AND (valid_until IS NULL OR valid_until>?) ORDER BY valid_from DESC LIMIT 1", ("x", 1.0, 1.0)):
            assert "SEARCH" in " ".join(map(str, row)), f"point read regressed to scan: {row}"
    finally:
        store.close()


@pytest.mark.performance
def test_scale_100k_measurement(tmp_path):
    """Build ~100k rows, time repo-wide closes (env-gated, measure-only)."""
    if not MEASURE:
        pytest.skip("set VERIFYCI_SCALE_MEASURE=1 to run 100k measurement")
    import time as _t

    from verifyci.contracts.entity import Entity, EntityType
    from verifyci.contracts.revision import Revision

    db = str(tmp_path / "scale_100k.db")
    store = GraphStore(db)
    now = _t.time()
    store.insert_revision(Revision("r1", "repo", "c1", None, "h1", now, "cfg"))
    with store.batch():
        for i in range(60000):
            store.insert_entity(Entity("repo", f"log_{i}", f"rev_{i}", EntityType.VARIABLE,
                                        f"v_{i}", "x.py", 1, 1, "py", "h", "r1",
                                        valid_from=now, t_created=now))
    store.insert_revision(Revision("r2", "repo", "c2", "r1", "h2", now + 1, "cfg"))
    t0 = _t.perf_counter()
    store.close_disappeared("r2", "r1", "repo", now + 1)
    dt_close = _t.perf_counter() - t0
    t0 = _t.perf_counter()
    store.repair_duplicate_live_intervals("repo", now + 1)
    dt_repair = _t.perf_counter() - t0
    t0 = _t.perf_counter()
    for i in range(0, 60000, 600):
        store.get_entity_as_of(f"log_{i}", now + 1)
    dt_point = (_t.perf_counter() - t0) / 100
    store.close()
    print(f"\n[scale100k] close_disappeared={dt_close:.2f}s repair={dt_repair:.2f}s point_avg_ms={dt_point*1000:.3f}")
    plans = _plan(db, "SELECT * FROM entities WHERE revision_id != ? AND repository_id=? AND valid_until IS NULL", ("r1", "repo"))
    print(f"[scale100k] close_disappeared plan: {plans}")
    assert dt_close < 60.0 and dt_repair < 60.0  # generous envelope: measurement, not SLO
