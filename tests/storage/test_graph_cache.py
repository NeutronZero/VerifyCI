import concurrent.futures
import threading
import time
import pytest

from verifyci.storage.graph_cache import GraphSnapshotCache


def test_graph_cache_basic_and_immutability():
    cache = GraphSnapshotCache(max_cost=1000)
    key = ("db1", "repo1", "rev1", "v2", "cfg1", "src1")

    loader_calls = 0

    def _loader():
        nonlocal loader_calls
        loader_calls += 1
        fake_graph = {"type": "fake_graph"}
        node_map = {"e1": 0, "e2": 1}
        entities = ["ent1", "ent2"]
        edges = [("e1", "e2")]
        return fake_graph, node_map, entities, edges

    g1, map1, ents1 = cache.get_or_load(key, _loader)
    assert loader_calls == 1
    assert map1 == {"e1": 0, "e2": 1}
    assert ents1 == ["ent1", "ent2"]

    # Immutability test: mutating caller's copy does not corrupt cache
    map1["e3"] = 99
    ents1.append("ent3")

    g2, map2, ents2 = cache.get_or_load(key, _loader)
    assert loader_calls == 1  # Served from cache!
    assert "e3" not in map2
    assert "ent3" not in ents2
    assert map2 == {"e1": 0, "e2": 1}
    assert ents2 == ["ent1", "ent2"]


def test_graph_cache_single_flight_concurrent_misses():
    cache = GraphSnapshotCache(max_cost=1000)
    key = ("db2", "repo2", "rev2", "v2", "cfg2", "src2")

    loader_calls = 0
    barrier = threading.Barrier(4)

    def _slow_loader():
        nonlocal loader_calls
        loader_calls += 1
        time.sleep(0.05)
        return {"graph": "fast"}, {"e1": 0}, ["ent1"], []

    def _worker():
        barrier.wait()
        return cache.get_or_load(key, _slow_loader)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(_worker) for _ in range(4)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert len(results) == 4
    # Despite 4 concurrent worker misses, loader was called exactly once!
    assert loader_calls == 1


def test_graph_cache_cost_eviction_and_oversized_rejection():
    # Cache with budget of 10
    cache = GraphSnapshotCache(max_cost=10)

    # 1. Snapshot with cost = 4 (2 entities + 1 edge * 2 = 4)
    key1 = ("db", "repo", "rev1", "v2", "", "")
    cache.get_or_load(key1, lambda: (None, {}, ["a", "b"], [1]))
    assert cache.current_cost == 4

    # 2. Snapshot with cost = 4
    key2 = ("db", "repo", "rev2", "v2", "", "")
    cache.get_or_load(key2, lambda: (None, {}, ["c", "d"], [2]))
    assert cache.current_cost == 8

    # 3. Snapshot with cost = 4 (exceeds 10 -> evicts key1)
    key3 = ("db", "repo", "rev3", "v2", "", "")
    cache.get_or_load(key3, lambda: (None, {}, ["e", "f"], [3]))
    assert cache.current_cost == 8
    assert key1 not in cache._cache
    assert key2 in cache._cache
    assert key3 in cache._cache

    # 4. Oversized snapshot with cost = 20 > max_cost (10): returned but not cached
    key_oversized = ("db", "repo", "rev_huge", "v2", "", "")
    res = cache.get_or_load(key_oversized, lambda: (None, {}, ["x"] * 10, [1] * 5))
    assert res[2] == ["x"] * 10
    assert key_oversized not in cache._cache
    assert cache.current_cost == 8  # Did not blow cache cost


def test_graph_cache_failure_cleans_up_locks():
    cache = GraphSnapshotCache(max_cost=1000)
    key = ("db_fail", "repo", "rev", "v2", "", "")

    def _failing_loader():
        raise RuntimeError("simulated disk error")

    with pytest.raises(RuntimeError, match="simulated disk error"):
        cache.get_or_load(key, _failing_loader)

    # In-flight lock must be cleaned up
    assert key not in cache._key_locks

    # Subsequent attempt can succeed
    res = cache.get_or_load(key, lambda: ({"ok": True}, {}, [], []))
    assert res[0]["ok"] is True


def test_graph_cache_immutable_view_rejects_mutation():
    import rustworkx as rx
    cache = GraphSnapshotCache(max_cost=1000)
    key = ("db_rx", "repo", "rev", "v2", "", "")

    def _loader():
        g = rx.PyDiGraph()
        n1 = g.add_node({"name": "node1", "tags": ["tag1"]})
        n2 = g.add_node({"name": "node2", "tags": ["tag2"]})
        g.add_edge(n1, n2, {"type": "CALLS", "meta": {"weight": 1}})
        return g, {"node1": n1, "node2": n2}, ["node1", "node2"], [("node1", "node2")]

    g_view, _, _ = cache.get_or_load(key, _loader)
    # Read operations succeed
    assert len(g_view) == 2
    assert g_view.successors(0)[0]["name"] == "node2"
    assert g_view[0]["name"] == "node1"
    assert g_view.num_nodes() == 2
    assert g_view.num_edges() == 1

    # Mutating operations fail closed with TypeError
    with pytest.raises(TypeError, match="ImmutableGraphView cannot be modified"):
        g_view.add_node({"name": "node3"})

    with pytest.raises(TypeError, match="ImmutableGraphView cannot be modified"):
        g_view.add_edge(0, 1, {"type": "NEW"})

    with pytest.raises(TypeError, match="ImmutableGraphView cannot be modified"):
        g_view.remove_node(0)

    with pytest.raises(TypeError, match="ImmutableGraphView cannot be modified"):
        g_view.update_edge(0, 1, {"type": "TAMPERED"})

    with pytest.raises(TypeError, match="item assignment is forbidden"):
        g_view[0] = {"tampered": True}

    with pytest.raises(TypeError, match="attribute assignment"):
        g_view.custom_attr = 123

    # Direct access to private/internal attributes is blocked
    with pytest.raises(AttributeError, match="Direct access to private or internal attribute '_graph' is prohibited"):
        _ = g_view._graph

    with pytest.raises(AttributeError, match="Direct access to private or internal attribute '_get_inner' is prohibited"):
        _ = g_view._get_inner()

    assert hasattr(g_view, "_get_inner") is False

    # Arbitrary method forwarding is NOT supported -> raises AttributeError
    with pytest.raises(AttributeError, match="'ImmutableGraphView' object has no attribute 'arbitrary_method'"):
        g_view.arbitrary_method()

    # Payload immutability: attempting to mutate returned dictionaries or lists raises TypeError or AttributeError
    with pytest.raises(TypeError):
        g_view[0]["name"] = "mutated_node1"

    with pytest.raises((TypeError, AttributeError)):
        g_view.successors(0)[0]["tags"].append("mutated_tag")

    with pytest.raises(TypeError):
        g_view.in_edges(1)[0][2]["meta"]["weight"] = 999


def test_immutable_graph_view_blocks_mutation_through_entity_and_edge_metadata():
    """Verify that dataclass entities and edges (including nested metadata dicts) cannot mutate cached state."""
    import rustworkx as rx
    from verifyci.contracts.edge import CPGEdgeSubtype, Edge, EdgeType
    from verifyci.contracts.entity import Entity, EntityType

    cache = GraphSnapshotCache(max_cost=1000)
    key = ("db_dataclass", "repo", "rev", "v2", "", "")

    original_ent = Entity(
        repository_id="repo1",
        logical_entity_id="0" * 64,
        revision_entity_id="ent_1",
        type=EntityType.FUNCTION,
        name="compute_fee",
        file_path="src/fee.py",
        line_start=10,
        line_end=20,
        language="python",
        source_hash="h1",
        revision_id="rev1",
        metadata={"permission": "admin", "config": {"retry": 3}},
    )
    original_edge = Edge(
        id="edge_1",
        revision_id="rev1",
        src_entity_id="ent_1",
        dst_entity_id="ent_2",
        type=EdgeType.CALLS,
        subtype=CPGEdgeSubtype.CALLS_DIRECT,
        metadata={"security_boundary": "isolated", "labels": ["crypto"]},
    )

    def _loader():
        g = rx.PyDiGraph()
        n1 = g.add_node(original_ent)
        n2 = g.add_node({"name": "ent_2"})
        g.add_edge(n1, n2, original_edge)
        return g, {"ent_1": n1, "ent_2": n2}, [original_ent, "ent_2"], [original_edge]

    g_view, _, _ = cache.get_or_load(key, _loader)

    # 1. Retrieve entity from view
    ent_from_view = g_view[0]
    assert ent_from_view.name == "compute_fee"
    assert ent_from_view.metadata["permission"] == "admin"

    # Attempting to mutate entity attribute directly fails (dataclass frozen)
    with pytest.raises(Exception):
        ent_from_view.name = "tampered_fee"

    # Attempting to mutate entity.metadata dictionary directly fails (MappingProxyType)
    with pytest.raises(TypeError):
        ent_from_view.metadata["permission"] = "unauthorized"

    with pytest.raises(TypeError):
        ent_from_view.metadata["new_key"] = "hacked"

    with pytest.raises(AttributeError):
        ent_from_view.metadata.clear()

    with pytest.raises(AttributeError):
        ent_from_view.metadata.update({"permission": "root"})

    # Nested dictionary in entity.metadata is also frozen
    with pytest.raises(TypeError):
        ent_from_view.metadata["config"]["retry"] = 999

    # Verify that the underlying original entity's metadata was NOT mutated
    assert original_ent.metadata["permission"] == "admin"
    assert "new_key" not in original_ent.metadata
    assert original_ent.metadata["config"]["retry"] == 3

    # 2. Retrieve edge from view
    edge_from_view = g_view.get_edge_data(0, 1)
    assert edge_from_view.metadata["security_boundary"] == "isolated"

    # Attempting to mutate edge.metadata dictionary fails
    with pytest.raises(TypeError):
        edge_from_view.metadata["security_boundary"] = "permissive"

    with pytest.raises((TypeError, AttributeError)):
        edge_from_view.metadata["labels"].append("tampered")

    assert original_edge.metadata["security_boundary"] == "isolated"


def test_immutable_graph_view_all_exposed_read_methods():
    """Verify that all exposed read/query methods function correctly and return frozen payloads."""
    import rustworkx as rx
    from verifyci.contracts.edge import Edge, EdgeType
    from verifyci.contracts.entity import Entity, EntityType

    cache = GraphSnapshotCache(max_cost=1000)
    key = ("db_all_reads", "repo", "rev", "v2", "", "")

    ent1 = Entity("repo", "0" * 64, "e1", EntityType.FUNCTION, "f1", "f.py", 1, 5, "py", "h1", "rev", metadata={"m": 1})
    ent2 = Entity("repo", "1" * 64, "e2", EntityType.FUNCTION, "f2", "f.py", 6, 10, "py", "h2", "rev", metadata={"m": 2})
    edge1 = Edge("ed1", "rev", "e1", "e2", EdgeType.CALLS, metadata={"edge_m": 10})

    def _loader():
        g = rx.PyDiGraph()
        n1 = g.add_node(ent1)
        n2 = g.add_node(ent2)
        g.add_edge(n1, n2, edge1)
        return g, {"e1": n1, "e2": n2}, [ent1, ent2], [edge1]

    view, _, _ = cache.get_or_load(key, _loader)

    # 1. Size & containment
    assert len(view) == 2
    assert view.num_nodes() == 2
    assert view.num_edges() == 1
    assert 0 in view
    assert 1 in view
    assert 99 not in view

    # 2. Node access
    assert view.node_indices() == [0, 1]
    all_nodes = view.nodes()
    assert len(all_nodes) == 2
    assert all_nodes[0].name == "f1"
    assert all_nodes[1].name == "f2"
    iter_nodes = list(iter(view))
    assert len(iter_nodes) == 2
    assert iter_nodes[0].name == "f1"
    assert view[0].name == "f1"

    # 3. Adjacency
    succs = view.successors(0)
    assert len(succs) == 1
    assert succs[0].name == "f2"
    preds = view.predecessors(1)
    assert len(preds) == 1
    assert preds[0].name == "f1"
    neighbors = view.neighbors(0)
    assert neighbors == [1]

    # 4. Edges
    in_edges = view.in_edges(1)
    assert len(in_edges) == 1
    assert in_edges[0][0] == 0
    assert in_edges[0][1] == 1
    assert in_edges[0][2].id == "edge_1" or in_edges[0][2].id == "ed1"

    out_edges = view.out_edges(0)
    assert len(out_edges) == 1
    assert out_edges[0][0] == 0

    assert view.has_edge(0, 1) is True
    assert view.has_edge(1, 0) is False

    ed_data = view.get_edge_data(0, 1)
    assert ed_data.id == "ed1"
    all_ed = view.get_all_edge_data(0, 1)
    assert len(all_ed) == 1
    assert all_ed[0].id == "ed1"

    emap = view.edge_index_map()
    assert len(emap) == 1
    assert view.edge_indices() == [0]
    assert view.edge_list() == [(0, 1)]


