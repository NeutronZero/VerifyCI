"""Contract tests validating SQLiteGraphStore and DuckDBGraphStore parity."""

from __future__ import annotations

from pathlib import Path
import pytest

from verifyci.extensions.protocols import GraphEdge, GraphNode, GraphStoreProtocol
from verifyci.extensions.storage.duckdb_store import DuckDBGraphStore
from verifyci.extensions.storage.sqlite_store import SQLiteGraphStore


@pytest.fixture(params=["sqlite", "duckdb"])
def graph_store(request: pytest.FixtureRequest, tmp_path: Path) -> GraphStoreProtocol:
    if request.param == "sqlite":
        return SQLiteGraphStore(":memory:")
    else:
        return DuckDBGraphStore(tmp_path / "test_duck.db")


def test_graph_store_snapshot_and_temporal_isolation(graph_store: GraphStoreProtocol) -> None:
    # Commit 1
    node_a = GraphNode("n_a", "FUNCTION", "src/a.py", "fn_a", 1, 10, {"complexity": 1})
    node_b = GraphNode("n_b", "FUNCTION", "src/b.py", "fn_b", 1, 5, {"complexity": 2})
    edge_ab = GraphEdge("e_ab", "n_a", "n_b", "CALLS", {"weight": 1})

    graph_store.record_commit_snapshot("commit_1", [node_a, node_b], [edge_ab])

    # Commit 2
    node_c = GraphNode("n_c", "FUNCTION", "src/c.py", "fn_c", 1, 8, {})
    edge_ac = GraphEdge("e_ac", "n_a", "n_c", "CALLS", {})
    graph_store.record_commit_snapshot("commit_2", [node_a, node_c], [edge_ac])

    # Query commit 1
    c1_nodes = graph_store.get_nodes_as_of("commit_1")
    c1_edges = graph_store.get_edges_as_of("commit_1")
    assert len(c1_nodes) == 2
    assert {n.node_uid for n in c1_nodes} == {"n_a", "n_b"}
    assert len(c1_edges) == 1
    assert c1_edges[0].dst_node_uid == "n_b"
    assert c1_nodes[0].properties.get("complexity") is not None

    # Query commit 2
    c2_nodes = graph_store.get_nodes_as_of("commit_2")
    c2_edges = graph_store.get_edges_as_of("commit_2")
    assert len(c2_nodes) == 2
    assert {n.node_uid for n in c2_nodes} == {"n_a", "n_c"}
    assert len(c2_edges) == 1
    assert c2_edges[0].dst_node_uid == "n_c"


def test_graph_store_overwrite_clears_stale_records(graph_store: GraphStoreProtocol) -> None:
    node_old = GraphNode("n_old", "MODULE", "src/old.py", "old", 1, 10)
    graph_store.record_commit_snapshot("commit_dup", [node_old], [])
    assert len(graph_store.get_nodes_as_of("commit_dup")) == 1

    # Overwrite same commit
    node_new = GraphNode("n_new", "MODULE", "src/new.py", "new", 1, 20)
    graph_store.record_commit_snapshot("commit_dup", [node_new], [])
    nodes = graph_store.get_nodes_as_of("commit_dup")
    assert len(nodes) == 1
    assert nodes[0].node_uid == "n_new"
