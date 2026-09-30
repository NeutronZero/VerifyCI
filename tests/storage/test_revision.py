from verifyci.storage.revision import canonical_manifest, create_revision


def _files():
    return [("b.py", "h2"), ("a.py", "h1")]


def test_same_state_same_id_despite_time_and_order():
    r1 = create_revision("repo", files=_files())
    r2 = create_revision("repo", files=list(reversed(_files())))
    assert r1.revision_id == r2.revision_id
    assert r1.source_hash == r2.source_hash
    assert len(r1.revision_id) == 64


def test_state_change_new_id():
    r1 = create_revision("repo", files=_files())
    r2 = create_revision("repo", files=[("a.py", "CHANGED"), ("b.py", "h2")])
    assert r1.revision_id != r2.revision_id


def test_commit_bound_to_identity():
    r1 = create_revision("repo", commit_id="abc", files=_files())
    r2 = create_revision("repo", commit_id="def", files=_files())
    assert r1.revision_id != r2.revision_id


def test_empty_manifest_deterministic():
    r1 = create_revision("repo")
    r2 = create_revision("repo")
    assert r1.revision_id == r2.revision_id


def test_manifest_canonical_bytes():
    raw = canonical_manifest("repo", None, None, _files())
    import json
    parsed = json.loads(raw)
    assert [f["path"] for f in parsed["files"]] == ["a.py", "b.py"]


def test_historical_entity_lookup(tmp_path):
    import time
    from verifyci.storage.graph_store import GraphStore
    from verifyci.contracts.entity import Entity, EntityType
    from verifyci.contracts.revision import Revision

    db = GraphStore(str(tmp_path / "test.db"))
    now = time.time()
    db.insert_revision(Revision("r1", "repo1", "c1", None, "h1", now, "cfg"))
    e1 = Entity("repo1", "log1", "rev1", EntityType.FUNCTION, "func_a", "a.py", 1, 10, "python", "h", "r1", valid_from=now, t_created=now)
    db.insert_entity(e1)

    # Ingest r2 superseding e1
    db.insert_revision(Revision("r2", "repo1", "c2", "r1", "h2", now + 10, "cfg"))
    e2 = Entity("repo1", "log1", "rev2", EntityType.FUNCTION, "func_a", "a.py", 1, 15, "python", "h", "r2", valid_from=now + 10, t_created=now + 10)
    db.insert_entity(e2)
    db.close_superseded_entities(["log1"], "r2", now + 10)

    # Lookup by revision_id='r1' must find e1 even though it was superseded by r2
    res_r1 = db.get_entity_by_name("func_a", revision_id="r1")
    assert res_r1 is not None
    assert res_r1.revision_id == "r1"
    assert res_r1.line_end == 10

    # Lookup without revision returns latest live entity
    latest = db.get_entity_by_name("func_a")
    assert latest is not None
    assert latest.revision_id == "r2"
    assert latest.line_end == 15
    db.close()


def test_chunked_superseded_entities_large_batch(tmp_path):
    import time
    from verifyci.storage.graph_store import GraphStore
    from verifyci.contracts.entity import Entity, EntityType
    from verifyci.contracts.revision import Revision

    db = GraphStore(str(tmp_path / "large.db"))
    now = time.time()
    db.insert_revision(Revision("r1", "repo", "c1", None, "h1", now, "cfg"))

    # Insert 1200 entities (exceeds default SQLite 999 parameter limit)
    ids = [f"log_{i}" for i in range(1200)]
    for i, lid in enumerate(ids):
        db.insert_entity(Entity("repo", lid, f"rev_{i}", EntityType.VARIABLE, f"v_{i}", "x.py", 1, 1, "py", "h", "r1", valid_from=now, t_created=now))

    db.insert_revision(Revision("r2", "repo", "c2", "r1", "h2", now + 5, "cfg"))
    closed = db.close_superseded_entities(ids, "r2", now + 5)
    assert closed == 1200
    db.close()
