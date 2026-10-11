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
        n1 = g.add_node("node1")
        n2 = g.add_node("node2")
        g.add_edge(n1, n2, "edge")
        return g, {"node1": n1, "node2": n2}, ["node1", "node2"], [("node1", "node2")]

    g_view, _, _ = cache.get_or_load(key, _loader)
    # Read operations succeed
    assert len(g_view) == 2
    assert g_view.successors(0) == ["node2"]

    # Mutating operations fail closed with TypeError
    with pytest.raises(TypeError, match="ImmutableGraphView cannot be modified"):
        g_view.add_node("node3")

    with pytest.raises(TypeError, match="ImmutableGraphView cannot be modified"):
        g_view.add_edge(0, 1, "tampered")

    with pytest.raises(TypeError, match="ImmutableGraphView cannot be modified"):
        g_view.remove_node(0)

