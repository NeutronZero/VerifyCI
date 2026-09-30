"""PROBE item 3: graph_query(name, asOf=...) must time-filter named lookups."""
import asyncio
import time

from verifyci.storage.graph_store import GraphStore
from verifyci.storage.revision import create_revision


def _two_rev_db(db):
    from verifyci.contracts.entity import Entity, EntityType
    store = GraphStore(db)
    try:
        r1 = create_revision(repository_id="r", files=[("a.py", "h1")])
        store.insert_revision(r1)
        t0 = time.time()
        e_old = Entity(repository_id="r", logical_entity_id="L-old",
                       revision_entity_id="e-old", type=EntityType.FUNCTION,
                       name="alpha", file_path="a.py", line_start=1, line_end=5,
                       language="python", source_hash="h1", revision_id=r1.revision_id,
                       valid_from=t0, t_created=t0)
        store.insert_entity(e_old)
        t1 = time.time()
        r2 = create_revision(repository_id="r", files=[("a.py", "h2")])
        store.insert_revision(r2)
        t2 = time.time()
        e_new = Entity(repository_id="r", logical_entity_id="L-new",
                       revision_entity_id="e-new", type=EntityType.FUNCTION,
                       name="beta", file_path="a.py", line_start=1, line_end=5,
                       language="python", source_hash="h2", revision_id=r2.revision_id,
                       valid_from=t2, t_created=t2)
        store.insert_entity(e_new)
        store.close_superseded_entities(["L-old"], "other-rev-never", t1)
        row = store.conn.execute(
            "UPDATE entities SET valid_until = ?, t_expired = ?"
            " WHERE revision_entity_id = 'e-old'", (t1, t1))
        store.conn.commit()
        assert row.rowcount == 1
        return t0, t1, t2
    finally:
        store.close()


def test_probe_get_entity_by_name_asof(tmp_path):
    db = str(tmp_path / "v.db")
    t0, t1, t2 = _two_rev_db(db)
    store = GraphStore(db)
    try:
        got = store.get_entity_by_name("alpha", as_of=(t0 + t1) / 2)
        assert got is not None and got.name == "alpha", got
        assert got.revision_entity_id == "e-old"
        assert store.get_entity_by_name("alpha") is None
        got2 = store.get_entity_by_name("beta", as_of=t2 + 60)
        assert got2 is not None and got2.name == "beta"
    finally:
        store.close()


def test_probe_graph_query_name_respects_asof(tmp_path):
    from verifyci.interface.mcp_server import create_mcp_server
    db = str(tmp_path / "v.db")
    t0, t1, t2 = _two_rev_db(db)
    store = GraphStore(db)
    try:
        server = create_mcp_server(graph=None, store=store, node_map={}, entities=[])
        out = asyncio.run(server.call_tool("graph.query", query="alpha",
                                           asOf=(t0 + t1) / 2))
        assert [r["name"] for r in out["results"]] == ["alpha"], out
        out2 = asyncio.run(server.call_tool("graph.query", query="alpha",
                                            asOf=t2 + 60))
        assert out2["results"] == [], out2
        ents = store.get_entities_by_revision(store.latest_revision_id("r"))
        assert [e.revision_entity_id for e in ents] == ["e-new"]
        server2 = create_mcp_server(graph=None, store=store, node_map={},
                                    entities=ents)
        out3 = asyncio.run(server2.call_tool("graph.query", query="e-new"))
        assert [r["name"] for r in out3["results"]] == ["beta"], out3
        out4 = asyncio.run(server2.call_tool("graph.query", query="e-new",
                                             asOf=t2 + 60))
        assert out4["results"] == [], out4
    finally:
        store.close()
