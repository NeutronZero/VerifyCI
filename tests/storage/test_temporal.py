import time

from verifyci.storage.graph_store import GraphStore
from verifyci.storage.revision import create_revision


def _rev(store, repo="r", files=()):
    rev = create_revision(repository_id=repo, files=list(files))
    store.insert_revision(rev)
    return rev


def _ent(store, logical, rev, path="a.py", name="f", repo="r"):
    from verifyci.contracts.entity import Entity, EntityType
    from verifyci.contracts.identity import compute_revision_entity_id
    e = Entity(
        repository_id=repo, logical_entity_id=logical,
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


def _edge(store, eid, rev, src, dst, type_="CALLS"):
    import time as _time
    from verifyci.contracts.edge import Edge, EdgeType
    now = _time.time()
    e = Edge(id=eid, revision_id=rev.revision_id, src_entity_id=src,
             dst_entity_id=dst, type=EdgeType(type_), metadata={},
             valid_from=now, observed_at=now, t_created=now)
    store.insert_edge(e)
    return e


def test_disappeared_file_entities_close_globally(tmp_path):
    # close_deleted_file_version only runs for files still present; a
    # wholly removed file's entities need the global pass or they haunt
    # name lookups forever.
    store = GraphStore(str(tmp_path / "t.db"))
    try:
        r1 = _rev(store, files=[("a.py", "h1"), ("dead.py", "h9")])
        _ent(store, "keep", r1)
        _ent(store, "doomed", r1, path="dead.py", name="doomed")
        r2 = _rev(store, files=[("a.py", "h1")])
        _ent(store, "keep", r2)
        n_e, n_d = store.close_disappeared(
            r2.revision_id, r1.revision_id, "r", time.time())
        assert n_e == 1
        assert store.get_current_entity("doomed") is None
        assert store.get_current_entity("keep") is not None
        assert store.get_entity_by_name("doomed") is None
    finally:
        store.close()


def test_removed_call_edge_expires(tmp_path):
    store = GraphStore(str(tmp_path / "t.db"))
    try:
        r1 = _rev(store, files=[("a.py", "h1")])
        keep = _ent(store, "keep", r1)
        callee = _ent(store, "callee", r1, name="callee")
        _edge(store, "e1", r1, keep.revision_entity_id, callee.revision_entity_id)
        r2 = _rev(store, files=[("a.py", "h2")])
        keep2 = _ent(store, "keep", r2)
        callee2 = _ent(store, "callee", r2, name="callee")
        n_e, n_d = store.close_disappeared(
            r2.revision_id, r1.revision_id, "r", time.time())
        assert (n_e, n_d) == (0, 1)
        live = store.conn.execute(
            "SELECT COUNT(*) FROM edges WHERE valid_until IS NULL").fetchone()[0]
        assert live == 0
        assert (keep2.revision_entity_id, callee2.revision_entity_id) is not None
    finally:
        store.close()


def test_asof_sees_deleted_edge_but_latest_does_not(tmp_path):
    store = GraphStore(str(tmp_path / "t.db"))
    try:
        r1 = _rev(store, files=[("a.py", "h1")])
        keep = _ent(store, "keep", r1)
        callee = _ent(store, "callee", r1, name="callee")
        _edge(store, "e1", r1, keep.revision_entity_id, callee.revision_entity_id)
        edge_row = store.conn.execute(
            "SELECT valid_from FROM edges WHERE id = 'e1'").fetchone()
        mid = time.time()
        r2 = _rev(store, files=[("a.py", "h2")])
        _ent(store, "keep", r2)
        _ent(store, "callee", r2, name="callee")
        closed_at = time.time()
        store.close_disappeared(r2.revision_id, r1.revision_id, "r", closed_at)
        # Latest view: no live edges at all.
        assert store.conn.execute(
            "SELECT COUNT(*) FROM edges WHERE valid_until IS NULL").fetchone()[0] == 0
        # As-of between versions: the old edge row still carries its span.
        span = store.conn.execute(
            "SELECT valid_from, valid_until FROM edges WHERE id = 'e1'").fetchone()
        assert span[0] is not None and span[1] is not None
        assert span[0] <= mid <= span[1]
        assert edge_row is not None
    finally:
        store.close()


def test_disappearance_is_repo_scoped_and_needs_parent(tmp_path):
    store = GraphStore(str(tmp_path / "t.db"))
    try:
        r1 = _rev(store, repo="other", files=[("b.py", "h1")])
        _ent(store, "foreign", r1, path="b.py", name="foreign", repo="other")
        assert store.close_disappeared("revX", "", "other", time.time()) == (0, 0)
        # A disappearance pass for repo "r" never touches "other" rows,
        # even when the other repo's entities are absent from r's tree.
        r1r = _rev(store, files=[("a.py", "h1")])
        _ent(store, "keep", r1r)
        r2r = _rev(store, files=[("a.py", "h1")])
        _ent(store, "keep", r2r)
        assert store.close_disappeared(
            r2r.revision_id, r1r.revision_id, "r", time.time()) == (0, 0)
        assert store.get_current_entity("foreign") is not None
    finally:
        store.close()


def test_carried_unresolved_refs_are_continuing_not_gone(tmp_path):
    # Incremental carry re-inserts unresolved refs into the new revision;
    # disappearance must read them as continuing edges, not expire them.
    from verifyci.contracts.edge import Edge, EdgeType
    store = GraphStore(str(tmp_path / "t.db"))
    try:
        r1 = _rev(store, files=[("a.py", "h1")])
        caller = _ent(store, "caller", r1, name="caller")
        store.insert_edge(Edge(
            id="u1", revision_id=r1.revision_id, src_entity_id=caller.revision_entity_id,
            dst_entity_id="", type=EdgeType.CALLS_UNRESOLVED,
            metadata={"callee": "faraway", "caller_scope": ""}))
        r2 = _rev(store, files=[("a.py", "h2")])
        caller2 = _ent(store, "caller", r2, name="caller")
        u2 = Edge(
            id="u2", revision_id=r2.revision_id, src_entity_id=caller2.revision_entity_id,
            dst_entity_id="", type=EdgeType.CALLS_UNRESOLVED,
            metadata={"callee": "faraway", "caller_scope": ""})
        store.insert_edge(u2)
        # Real ingest supersedes first: the old row version-closes,
        # leaving exactly the carried row live.
        store.close_superseded_edges([u2], r2.revision_id, time.time())
        n_e, n_d = store.close_disappeared(
            r2.revision_id, r1.revision_id, "r", time.time())
        assert (n_e, n_d) == (0, 0)
        live = store.conn.execute(
            "SELECT COUNT(*) FROM edges WHERE valid_until IS NULL").fetchone()[0]
        assert live == 1
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
