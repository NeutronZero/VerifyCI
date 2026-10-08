"""PHASE 3: determinism and state-integrity regression tests.

Ordering is by insertion (rowid), never wall-clock; ids are full-length;
labels name the state actually used; snapshots and replays cannot alias
caller-owned objects; corrupt rows fail closed as lineage errors.
"""
import copy
import os

import pytest


def test_replay_fallback_labels_actual_anchor():
    from verifyci.memory.replay import ReplayEngine
    engine = ReplayEngine()
    engine.add_anchor("rev1", {"a": 1})
    engine.add_delta("rev1", "rev2", {"b": 2})
    # Exact anchor missing: documented fallback replays from rev1, but the
    # projection must say so — never masquerade as replay_missing_rev2.
    out = engine.replay("missing", "rev2")
    assert out.state == {"a": 1, "b": 2}
    assert "missing" in out.projection_id and "rev1" in out.projection_id
    assert out.projection_id != "replay_missing_rev2"
    # Exact path keeps the plain label.
    out2 = engine.replay("rev1", "rev2")
    assert out2.projection_id == "replay_rev1_rev2"


def test_replay_state_isolated_from_caller_mutation():
    from verifyci.memory.replay import ReplayEngine
    engine = ReplayEngine()
    seed = {"nested": {"x": [1]}}
    engine.add_anchor("r1", seed)
    seed["nested"]["x"].append(999)
    stored = engine._anchors["r1"].state
    assert stored == {"nested": {"x": [1]}}


def test_snapshot_deepcopy_isolation():
    from verifyci.memory.snapshot import SnapshotStore
    store = SnapshotStore(snapshot_threshold=1)
    state = {"nested": {"x": [1]}}
    snap = store.maybe_snapshot("r1", state)
    state["nested"]["x"].append(999)
    assert snap.state == {"nested": {"x": [1]}}


def test_replay_events_orders_by_timestamp_then_id():
    from verifyci.memory.replay import ReplayEngine
    from types import SimpleNamespace
    evts = [
        SimpleNamespace(id="e2", timestamp=2.0, payload={"v": 2}),
        SimpleNamespace(id="e1", timestamp=1.0, payload={"v": 1}),
    ]
    out = ReplayEngine().replay_events(evts)
    assert out.state == {"v": 2}


def test_manifest_dedupes_and_rejects_conflicts():
    from verifyci.storage.revision import canonical_manifest, create_revision
    a = create_revision("r", files=[("a.py", "h1"), ("a.py", "h1"), ("b.py", "h2")])
    b = create_revision("r", files=[("b.py", "h2"), ("a.py", "h1")])
    assert a.revision_id == b.revision_id
    with pytest.raises(ValueError):
        canonical_manifest("r", None, None, [("a.py", "h1"), ("a.py", "other")])


def test_identity_normalization_noop_for_canonical():
    from verifyci.contracts.identity import compute_logical_entity_id
    from verifyci.contracts.entity import EntityType
    a = compute_logical_entity_id("r", "src/app.py", "f", EntityType.FUNCTION)
    b = compute_logical_entity_id("r", "src\\app.py", "f", EntityType.FUNCTION)
    c = compute_logical_entity_id("r", "./src/app.py", "f", EntityType.FUNCTION)
    assert a == b == c


def test_anchor_and_delta_ids_use_full_revisions(tmp_path):
    from verifyci.storage.graph_store import GraphStore
    db = str(tmp_path / "v.db")
    store = GraphStore(db)
    try:
        rev = "r" * 64
        aid = store.insert_anchor(rev, {"files": []})
        assert aid == f"anchor_{rev}"
        did = store.insert_delta("a" * 64, "b" * 64, {"added": []})
        assert did == f"delta_{'a' * 64}_{'b' * 64}"
    finally:
        store.close()


def test_corrupt_row_raises_lineage_error():
    from verifyci.contracts.revision import LineageIntegrityError
    from verifyci.storage.graph_store import GraphStore
    row = ["e", "l" * 64, "r", "rev", "NOT_A_TYPE", "n", "f.py",
           1, 2, "python", "h", None, None, None, None, "{}", None]
    with pytest.raises(LineageIntegrityError):
        GraphStore._row_to_entity(row)
    erow = ["id", "rev", "s", "d", "NOT_AN_EDGE", None,
            None, None, None, None, None, None, "{}", None]
    with pytest.raises(LineageIntegrityError):
        GraphStore._row_to_edge(erow)


def test_get_entity_by_name_deterministic_order(tmp_path):
    from verifyci.contracts.entity import Entity, EntityType
    from verifyci.storage.graph_store import GraphStore
    from verifyci.storage.revision import create_revision
    db = str(tmp_path / "v.db")
    store = GraphStore(db)
    try:
        rev = create_revision(repository_id="r", files=[("b.py", "h"), ("a.py", "h")])
        store.insert_revision(rev)
        for path, line in (("b.py", 30), ("a.py", 5)):
            store.insert_entity(Entity(
                repository_id="r", logical_entity_id="a" * 64,
                revision_entity_id="k" * 63 + str(line),
                type=EntityType.FUNCTION, name="dup", file_path=path,
                line_start=line, line_end=line + 1, language="python",
                source_hash="h", revision_id=rev.revision_id))
        got = store.get_entity_by_name("dup", revision_id=rev.revision_id)
        assert (got.file_path, got.line_start) == ("a.py", 5)
    finally:
        store.close()


def test_atomic_preserves_mode_and_replaces_symlink(tmp_path):
    import os
    from verifyci.storage.atomic import write_bytes_atomic
    target = tmp_path / "f.bin"
    target.write_bytes(b"old")
    os.chmod(target, 0o640)
    write_bytes_atomic(target, b"new")
    assert target.read_bytes() == b"new"
    if os.name != "nt":
        assert oct(target.stat().st_mode & 0o777) == "0o640"
    real = tmp_path / "real.bin"
    real.write_bytes(b"real")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks unavailable")
    write_bytes_atomic(link, b"through-link-must-not-land-in-real", sync=False)
    # The link itself was replaced (absolute, not resolved): real untouched.
    assert real.read_bytes() == b"real"


def test_querylog_truncates_and_restricts_mode(tmp_path):
    from verifyci.observability import querylog as qm
    log = tmp_path / "q.jsonl"
    logger = qm.QueryLogger(log)
    logger.log_query("x" * 2000)
    import json
    entry = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert len(entry["query"]) == qm.MAX_LOGGED_QUERY_CHARS
    assert entry["query_truncated"] is True
    if os.name != "nt":
        assert oct(log.stat().st_mode & 0o777) == "0o600"


def test_snapshot_store_threshold_counts_calls(tmp_path=None):
    from verifyci.memory.snapshot import SnapshotStore
    store = SnapshotStore(snapshot_threshold=2)
    assert store.maybe_snapshot("r1", {"a": 1}) is None
    snap = store.maybe_snapshot("r1", {"a": 1})
    assert snap is not None and snap.revision_id == "r1"
    assert copy.deepcopy(snap.state) == {"a": 1}
