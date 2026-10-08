"""Legacy database canonicalization adapter tests."""
import sqlite3


def _legacy_db(path):
    from verifyci.storage.graph_store import GraphStore
    from verifyci.storage.revision import create_revision
    from verifyci.contracts.entity import Entity, EntityType
    from verifyci.contracts.edge import Edge, EdgeType
    db = str(path)
    store = GraphStore(db)
    try:
        rev = create_revision(repository_id="r", files=[("a.py", "h")])
        store.insert_revision(rev)
        store.insert_entity(Entity(
            repository_id="r", logical_entity_id="legacy-logical",
            revision_entity_id="legacy-rev", type=EntityType.FUNCTION,
            name="f", file_path="a.py", line_start=1, line_end=2,
            language="python", source_hash="h", revision_id=rev.revision_id))
        store.insert_entity(Entity(
            repository_id="r", logical_entity_id="c" * 64,
            revision_entity_id="d" * 64, type=EntityType.FUNCTION,
            name="g", file_path="a.py", line_start=3, line_end=4,
            language="python", source_hash="h", revision_id=rev.revision_id))
        store.insert_edge(Edge(
            id="e1", revision_id=rev.revision_id,
            src_entity_id="legacy-rev", dst_entity_id="d" * 64,
            type=EdgeType.CALLS))
        store.insert_edge(Edge(
            id="dep1", revision_id=rev.revision_id,
            src_entity_id="a.py", dst_entity_id="pypi:requests",
            type=EdgeType.DEPENDS_ON,
            metadata={"external": True, "ecosystem": "pypi"}))
    finally:
        store.close()
    return db


def _is_hex64(v):
    import re
    return bool(re.fullmatch(r"[0-9a-f]{64}", v or ""))


def test_migrate_rekeys_and_remaps(tmp_path):
    from verifyci.storage.migrate import canonicalize_database
    db = _legacy_db(tmp_path / "legacy.db")
    rep = canonicalize_database(db)
    assert rep["remapped_entities"] == 1
    assert rep["remapped_edges"] == 1
    assert rep["unmigratable"] == []
    assert (tmp_path / "legacy.db.bak").exists()
    conn = sqlite3.connect(db)
    try:
        ids = conn.execute(
            "SELECT logical_entity_id, revision_entity_id, file_path FROM entities").fetchall()
        assert all(_is_hex64(a) and _is_hex64(b) for a, b, _ in ids)
        # Healthy hex row untouched.
        assert ("c" * 64, "d" * 64, "a.py") in ids
        edges = conn.execute(
            "SELECT src_entity_id, dst_entity_id FROM edges WHERE id = 'e1'").fetchone()
        assert edges[0] != "legacy-rev" and _is_hex64(edges[0])
        assert edges[1] == "d" * 64
        # Externals are canonical by design: untouched.
        dep = conn.execute(
            "SELECT src_entity_id, dst_entity_id FROM edges WHERE id = 'dep1'").fetchone()
        assert dep == ("a.py", "pypi:requests")
    finally:
        conn.close()


def test_migrate_is_deterministic(tmp_path):
    from verifyci.storage.migrate import canonicalize_database
    db1 = _legacy_db(tmp_path / "a.db")
    db2 = _legacy_db(tmp_path / "b.db")
    canonicalize_database(db1, backup=False)
    canonicalize_database(db2, backup=False)

    def dump(p):
        conn = sqlite3.connect(str(p))
        try:
            return (conn.execute("SELECT logical_entity_id, revision_entity_id, file_path FROM entities ORDER BY 1").fetchall(),
                    conn.execute("SELECT id, src_entity_id, dst_entity_id FROM edges ORDER BY 1").fetchall())
        finally:
            conn.close()
    assert dump(db1) == dump(db2)


def test_migrate_refuses_empty_path(tmp_path):
    import pytest
    from verifyci.storage.graph_store import GraphStore
    from verifyci.storage.revision import create_revision
    from verifyci.contracts.entity import Entity, EntityType
    from verifyci.storage.migrate import canonicalize_database
    db = str(tmp_path / "bad.db")
    store = GraphStore(db)
    try:
        rev = create_revision(repository_id="r", files=[("a.py", "h")])
        store.insert_revision(rev)
        store.insert_entity(Entity(
            repository_id="r", logical_entity_id="x", revision_entity_id="y",
            type=EntityType.FUNCTION, name="f", file_path="",
            line_start=1, line_end=2, language="python", source_hash="h",
            revision_id=rev.revision_id))
    finally:
        store.close()
    with pytest.raises(ValueError, match="unmigratable"):
        canonicalize_database(db, backup=False)


def test_migrated_db_loads_and_verifies(tmp_path):
    from verifyci.interface.commands.graph_loader import load_graph
    from verifyci.storage.migrate import canonicalize_database
    db = _legacy_db(tmp_path / "legacy.db")
    canonicalize_database(db, backup=False)
    graph, node_map, entities = load_graph(db)
    assert entities, "migrated rows must load"
    assert all(_is_hex64(e.logical_entity_id) for e in entities
               if not (e.metadata or {}).get("external"))
