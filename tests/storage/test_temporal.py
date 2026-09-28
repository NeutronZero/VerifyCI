import time

from src.storage.graph_store import GraphStore
from src.storage.revision import create_revision


def _rev(store, repo="r", files=()):
    rev = create_revision(repository_id=repo, files=list(files))
    store.insert_revision(rev)
    return rev


def _ent(store, logical, rev, path="a.py", name="f"):
    from src.contracts.entity import Entity, EntityType
    from src.contracts.identity import compute_revision_entity_id
    e = Entity(
        repository_id="r", logical_entity_id=logical,
        revision_entity_id=compute_revision_entity_id(logical, rev.revision_id),
        type=EntityType.FUNCTION, name=name, file_path=path,
        line_start=1, line_end=2, language="python", source_hash="h",
        revision_id=rev.revision_id, valid_from=time.time(), t_created=time.time(),
    )
    store.insert_entity(e)
    return e


def test_deleted_entities_close_on_reingest(tmp_path):
    store = GraphStore(str(tmp_path / "t.db"))
    try:
        r1 = _rev(store, files=[("a.py", "h1")])
        _ent(store, "keep", r1)
        _ent(store, "gone", r1, name="gone")
        now = time.time()
        r2 = _rev(store, files=[("a.py", "h2")])
        _ent(store, "keep", r2)
        store.close_superseded_entities(["keep"], r2.revision_id, now)
        n_e, n_d = store.close_deleted_file_version("a.py", ["keep"], r2.revision_id, now)
        assert n_e == 1
        live = [r[0] for r in store.conn.execute(
            "SELECT logical_entity_id FROM entities WHERE valid_until IS NULL").fetchall()]
        assert live == ["keep"]
        # asOf the old revision still sees the deleted entity
        span = store.conn.execute(
            "SELECT valid_from, valid_until FROM entities WHERE logical_entity_id = ?",
            ("gone",)).fetchone()
        old = store.get_entity_by_logical("gone", asOf=(span[0] + span[1]) / 2)
        assert old is not None and old.name == "gone"
        assert store.get_entity_by_logical("gone", asOf=now + 3600) is None
    finally:
        store.close()


def test_batch_defers_commits(tmp_path):
    store = GraphStore(str(tmp_path / "b.db"))
    try:
        r1 = _rev(store)
        with store.batch():
            _ent(store, "a", r1, name="a")
            _ent(store, "b", r1, name="b")
        rows = store.conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
        assert rows == 2
    finally:
        store.close()


def _two_revs(store):
    r1 = _rev(store, files=[("a.py", "h1")])
    _ent(store, "keep", r1)
    _ent(store, "gone", r1, name="gone")
    now = time.time()
    r2 = _rev(store, files=[("a.py", "h2")])
    _ent(store, "keep", r2)
    store.close_superseded_entities(["keep"], r2.revision_id, now)
    store.close_deleted_file_version("a.py", ["keep"], r2.revision_id, now)
    return r1, r2, now


def test_asof_returns_retracted_fact_independently(tmp_path):
    """Valid-time travel ignores transaction-time expiry (own method)."""
    store = GraphStore(str(tmp_path / "t.db"))
    try:
        _two_revs(store)
        span = store.conn.execute(
            "SELECT valid_from, valid_until FROM entities WHERE logical_entity_id = ?",
            ("gone",)).fetchone()
        got = store.get_entity_as_of("gone", (span[0] + span[1]) / 2)
        assert got is not None and got.name == "gone"
    finally:
        store.close()


def test_latest_hides_retracted_fact_independently(tmp_path):
    """Latest-version lookup honors transaction-time expiry (own method)."""
    store = GraphStore(str(tmp_path / "t.db"))
    try:
        _two_revs(store)
        assert store.get_current_entity("gone") is None
        assert store.get_current_entity("keep") is not None
    finally:
        store.close()
