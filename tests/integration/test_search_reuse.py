"""code_search must not rebuild the search index on every call.

The long-lived MCP server loads the graph once, but the search path used
to re-describe the whole graph (rebuild the BM25 index + texts map) per
query (measured: 5 describe calls across 5 queries). The index is now
cached and keyed on a structural fingerprint of the graph; an unchanged
graph is reused across calls (identical, still-correct hits), and a
rebuilt graph busts the cache so no stale index is ever served.
"""
import asyncio

import verifyci.interface.mcp_server as mcp_mod
from verifyci.graph.builder import GraphBuilder
from verifyci.ingestion.extractor import extract_entities, extract_edges
from verifyci.ingestion.parser import TreeSitterParser


def _graph():
    parser = TreeSitterParser()
    ents, edges = [], []
    for i in range(8):
        p = parser.parse(f"m{i}.py", f"def handler_{i}():\n    value = {i}\n".encode(), "python")
        e = extract_entities(p, "r", "rev")
        ents += e
        edges += extract_edges(p, e, "rev")
    builder = GraphBuilder()
    return builder.build(ents, edges), builder.get_node_map()


def _spy_describe(monkeypatch):
    real = mcp_mod._describe_graph
    spy = {"n": 0}
    def counting(*a, **k):
        spy["n"] += 1
        return real(*a, **k)
    monkeypatch.setattr(mcp_mod, "_describe_graph", counting)
    return spy


def test_index_built_once_across_queries(monkeypatch):
    graph, nm = _graph()
    spy = _spy_describe(monkeypatch)
    server = mcp_mod.create_mcp_server(graph=graph, node_map=nm)
    loop = asyncio.new_event_loop()
    try:
        first = loop.run_until_complete(server.call_tool("code.search", query="handler", k=3))
        for _ in range(4):
            loop.run_until_complete(server.call_tool("code.search", query="handler", k=3))
    finally:
        loop.close()
    assert spy["n"] == 1, f"index rebuilt {spy['n']} times across 5 queries"
    assert first["results"]


def test_repeated_queries_are_deterministic(monkeypatch):
    graph, nm = _graph()
    _spy_describe(monkeypatch)
    server = mcp_mod.create_mcp_server(graph=graph, node_map=nm)
    loop = asyncio.new_event_loop()
    try:
        a = loop.run_until_complete(server.call_tool("code.search", query="handler_0", k=5))
        b = loop.run_until_complete(server.call_tool("code.search", query="handler_0", k=5))
    finally:
        loop.close()
    # Reuse must not change results: same hits, same order.
    assert [h["id"] for h in a["results"]] == [h["id"] for h in b["results"]]


def test_graph_change_busts_cache_no_stale_index(monkeypatch):
    graph, nm = _graph()
    spy = _spy_describe(monkeypatch)
    server = mcp_mod.create_mcp_server(graph=graph, node_map=nm)
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(server.call_tool("code.search", query="handler_0", k=5))
        assert spy["n"] == 1  # first query builds
        # Mutate the same graph object (a reload rebuilds nodes/edges):
        # the fingerprint changes, so the next search re-describes
        # instead of serving a stale cached index.
        graph.add_node(
            type("P", (), {"revision_entity_id": "new", "name": "brand",
                           "file_path": "new.py"})())
        loop.run_until_complete(server.call_tool("code.search", query="brand", k=5))
    finally:
        loop.close()
    assert spy["n"] == 2, f"expected re-describe after graph change, got {spy['n']}"

