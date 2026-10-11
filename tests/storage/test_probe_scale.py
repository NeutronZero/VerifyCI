"""PROBES item 8: storage-side scale/scoping fixes."""
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


def _edge(store, eid, rev, src, dst, type_="CALLS", meta=None):
    from verifyci.contracts.edge import Edge, EdgeType
    now = time.time()
    e = Edge(id=eid, revision_id=rev.revision_id, src_entity_id=src,
             dst_entity_id=dst, type=EdgeType(type_), metadata=dict(meta or {}),
             valid_from=now, observed_at=now, t_created=now)
    store.insert_edge(e)
    return e


def test_probe_supersede_edges_scoped_queries(tmp_path):
    db = str(tmp_path / "t.db")
    store = GraphStore(db)
    try:
        r1 = _rev(store, files=[("a.py", "h1"), ("b.py", "h1")])
        ea = _ent(store, "ea", r1, path="a.py", name="fa")
        eb = _ent(store, "eb", r1, path="b.py", name="fb")
        _edge(store, "k1", r1, ea.revision_entity_id, eb.revision_entity_id)
        r2 = _rev(store, files=[("a.py", "h2"), ("b.py", "h1")])
        ea2 = _ent(store, "ea", r2, path="a.py", name="fa")
        eb2 = _ent(store, "eb", r2, path="b.py", name="fb")
        new = _edge(store, "k2", r2, ea2.revision_entity_id, eb2.revision_entity_id)

        seen = []
        store.conn.set_trace_callback(seen.append)
        try:
            closed = store.close_superseded_edges([new], r2.revision_id, time.time())
        finally:
            store.conn.set_trace_callback(None)
        assert closed == 1, closed
        full_scans = [s for s in seen if "FROM entities" in s and "WHERE" not in s.upper()]
        full_scans += [s for s in seen if "FROM edges" in s and "WHERE" not in s.upper()]
        assert full_scans == [], full_scans
    finally:
        store.close()


def test_probe_deleted_file_version_cross_repo_scoped(tmp_path):
    if hasattr(GraphStore, "close_deleted_file_version"):
        rB = None
        store = GraphStore(str(tmp_path / "t.db"))
        try:
            rA1 = _rev(store, repo="repoA", files=[("a.py", "h1")])
            _ent(store, "LA", rA1, path="a.py", name="fa", repo="repoA")
            rA2 = _rev(store, repo="repoA", files=[("a.py", "h2")])
            _ent(store, "LA", rA2, path="a.py", name="fa", repo="repoA")
            rB = _rev(store, repo="repoB", files=[("a.py", "h9")])
            _ent(store, "LB", rB, path="a.py", name="fb", repo="repoB")
            store.close_deleted_file_version("a.py", ["LA"], rA2.revision_id, time.time())
            assert store.get_current_entity("LB") is not None, \
                "cross-repo row for the same relative path was expired"
        finally:
            store.close()
    else:
        store = GraphStore(str(tmp_path / "t.db"))
        try:
            rA1 = _rev(store, repo="repoA", files=[("a.py", "h1"), ("gone.py", "h1")])
            _ent(store, "LA", rA1, path="a.py", name="fa", repo="repoA")
            _ent(store, "LG", rA1, path="gone.py", name="gg", repo="repoA")
            rB = _rev(store, repo="repoB", files=[("a.py", "h9")])
            _ent(store, "LB", rB, path="a.py", name="fb", repo="repoB")
            rA2 = _rev(store, repo="repoA", files=[("a.py", "h1")])
            _ent(store, "LA", rA2, path="a.py", name="fa", repo="repoA")
            n_e, _ = store.close_disappeared(
                rA2.revision_id, rA1.revision_id, "repoA", time.time())
            assert n_e == 1
            assert store.get_current_entity("LG") is None
            assert store.get_current_entity("LB") is not None
            assert store.get_current_entity("LA") is not None
        finally:
            store.close()


def test_probe_disappeared_keys_unresolved_callee(tmp_path):
    store = GraphStore(str(tmp_path / "t.db"))
    try:
        r1 = _rev(store, files=[("a.py", "h1")])
        caller = _ent(store, "caller", r1, name="caller")
        _edge(store, "u-far", r1, caller.revision_entity_id, "",
              type_="CALLS_UNRESOLVED", meta={"callee": "faraway", "caller_scope": ""})
        _edge(store, "u-near", r1, caller.revision_entity_id, "",
              type_="CALLS_UNRESOLVED", meta={"callee": "nearby", "caller_scope": ""})
        r2 = _rev(store, files=[("a.py", "h2")])
        caller2 = _ent(store, "caller", r2, name="caller")
        _edge(store, "u-near2", r2, caller2.revision_entity_id, "",
              type_="CALLS_UNRESOLVED", meta={"callee": "nearby", "caller_scope": ""})
        n_e, n_d = store.close_disappeared(
            r2.revision_id, r1.revision_id, "r", time.time())
        assert n_d == 1, (n_e, n_d)
        rows = {r[0]: r[1] for r in store.conn.execute(
            "SELECT id, valid_until FROM edges").fetchall()}
        assert rows["u-far"] is not None, rows
        assert rows["u-near"] is None, rows
        assert rows["u-near2"] is None, rows
        live = sorted(r[0] for r in store.conn.execute(
            "SELECT id FROM edges WHERE valid_until IS NULL").fetchall())
        assert live == ["u-near", "u-near2"], live
    finally:
        store.close()


def test_probe_no_asof_gap_on_reingest(tmp_path):
    from verifyci.interface.commands.ingest import run_ingest
    repo = tmp_path / "proj"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text("def f():\n    return 1\n")
    out1 = run_ingest(str(repo))
    (repo / "src" / "a.py").write_text("def f():\n    return 2\n")
    out2 = run_ingest(str(repo))
    assert out2["revision_id"] != out1["revision_id"]
    store = GraphStore(out2["db_path"])
    try:
        rows = store.conn.execute(
            "SELECT logical_entity_id, valid_from, valid_until FROM entities"
            " WHERE name = 'f'").fetchall()
        old = [r for r in rows if r[2] is not None]
        new = [r for r in rows if r[2] is None]
        assert old and new, rows
        assert old[0][0] == new[0][0]
        assert old[0][2] >= new[0][1], (old, new)
    finally:
        store.close()


def test_probe_superseded_edges_chunk_bound_under_sqlite_limit(tmp_path):
    """Regression for the chunk-bound mismatch cited in the audit.

    close_superseded_edges must never pass more than 999 bound
    parameters to any single SQLite statement (the documented
    _SQLITE_PARAM_CHUNK guard floor). Before the fix the candidate
    scan built [rev, *chunk, *chunk] with 500-element chunks, which
    could reach 1001 params; the corrected path slices by
    _SQLITE_PARAM_CHUNK and now asserts the bound explicitly.
    """
    from verifyci.storage.graph_store import GraphStore, _SQLITE_PARAM_CHUNK
    db = str(tmp_path / "t.db")
    store = GraphStore(db)
    try:
        # Build a candidate set at the chunk boundary: 400 + 100 == 500
        # distinct logical ids, so one chunk will be full-size and the
        # params list will be [rev, *chunk, *chunk] == 1 + 500 + 500.
        n = _SQLITE_PARAM_CHUNK + 100
        ents = []
        for i in range(n):
            ents.append(f"e{i:04d}")

        def _rev(store):
            from verifyci.storage.revision import create_revision
            rev = create_revision(repository_id="r", files=[])
            store.insert_revision(rev)
            return rev

        def _ent(store, logical):
            from verifyci.contracts.entity import Entity, EntityType
            from verifyci.contracts.identity import compute_revision_entity_id
            rev = _rev(store)
            e = Entity(
                repository_id="r", logical_entity_id=logical,
                revision_entity_id=compute_revision_entity_id(logical, rev.revision_id),
                type=EntityType.FUNCTION, name=logical, file_path="a.py",
                line_start=1, line_end=2, language="python", source_hash="h",
                revision_id=rev.revision_id, valid_from=time.time(),
                t_created=time.time(),
            )
            store.insert_entity(e)
            return e

        def _edge(store, eid, src, dst):
            from verifyci.contracts.edge import Edge, EdgeType
            now = time.time()
            e = Edge(
                id=eid, revision_id=_rev(store).revision_id,
                src_entity_id=src, dst_entity_id=dst,
                type=EdgeType.CALLS, metadata={},
                valid_from=now, observed_at=now, t_created=now,
            )
            store.insert_edge(e)
            return e

        _r1 = _rev(store)
        srcs = {i: _ent(store, f"s{i:04d}") for i in range(n)}
        dsts = {i: _ent(store, f"d{i:04d}") for i in range(n)}
        _edges = [_edge(store, f"e{i:04d}", srcs[i].revision_entity_id, dsts[i].revision_entity_id)
                  for i in range(n)]

        r2 = _rev(store)
        new = _edge(store, "new", srcs[0].revision_entity_id, dsts[0].revision_entity_id)

        try:
            store.close_superseded_edges([new], r2.revision_id, time.time())
        except RuntimeError as exc:
            msg = str(exc)
            assert "sql param bound overflow" in msg, msg
            raise AssertionError(
                "close_superseded_edges exceeded the 999 bound on a deliberately "
                "boundary-sized candidate set; the chunk constant guard is not "
                "enforced on the candidate-load query path."
            ) from exc
    finally:
        store.close()
