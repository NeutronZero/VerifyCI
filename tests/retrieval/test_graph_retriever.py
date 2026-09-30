"""GraphRetriever must honor edge semantics.

The old traversal expanded successors()/predecessors() blindly: a seed
function reached its containing module via CONTAINS and its doc rows
via DOCUMENTS, so a two-hop expansion of any symbol pulled in whole
modules. Semantic relationships (calls, imports, inheritance,
references) still expand; containment and documentation do not.
"""
import time

from verifyci.contracts.edge import CPGEdgeSubtype, Edge, EdgeType
from verifyci.contracts.entity import Entity, EntityType
from verifyci.retrieval.graph_retriever import GraphRetriever


def _ent(eid, name, type_=EntityType.FUNCTION, path="a.py"):
    now = time.time()
    return Entity(repository_id="r", logical_entity_id=f"l_{eid}",
                  revision_entity_id=eid, type=type_, name=name,
                  file_path=path, line_start=1, line_end=2,
                  language="python", source_hash="h", revision_id="rev",
                  valid_from=now, t_created=now)


def _edge(eid, src, dst, etype):
    now = time.time()
    return Edge(id=eid, revision_id="rev", src_entity_id=src, dst_entity_id=dst,
                type=etype, subtype=CPGEdgeSubtype.CALLS_DIRECT,
                valid_from=now, observed_at=now, t_created=now)


class _FakeRxGraph:
    """Minimal rustworkx-shaped graph: entities + edges, with
    edge_index_map() returning {idx: (src, dst, payload)} as PyDiGraph
    does. successors/predecessors are absent on purpose: a
    type-filtering retriever must read the edge payloads."""

    def __init__(self, entities, edges):
        self._nodes = list(entities)
        by_id = {n.revision_entity_id: i for i, n in enumerate(self._nodes)}
        self._resolved = []
        for e in edges:
            s = by_id.get(e.src_entity_id)
            d = by_id.get(e.dst_entity_id)
            if s is not None and d is not None:
                self._resolved.append((s, d, e))

    def nodes(self):
        return list(self._nodes)

    def node_indices(self):
        return list(range(len(self._nodes)))

    def edge_index_map(self):
        return {i: tuple(entry) for i, entry in enumerate(self._resolved)}


def _module_graph():
    mod = _ent("mod_a", "a", EntityType.MODULE)
    user = _ent("user", "user")
    target = _ent("target", "target")
    helper = _ent("helper", "helper")
    doc = _ent("doc_a", "doc", EntityType.MODULE, path="docs/a.rst")
    edges = [
        _edge("e1", "mod_a", "user", EdgeType.CONTAINS),
        _edge("e2", "mod_a", "target", EdgeType.CONTAINS),
        _edge("e3", "user", "target", EdgeType.CALLS),
        _edge("e4", "target", "helper", EdgeType.CALLS),
        _edge("e5", "mod_a", "doc_a", EdgeType.DOCUMENTS),
    ]
    ents = [mod, user, target, helper, doc]
    nm = {e.revision_entity_id: i for i, e in enumerate(ents)}
    return _FakeRxGraph(ents, edges), nm


def test_contains_and_documents_do_not_expand():
    g, nm = _module_graph()
    hits = {h.id for h in GraphRetriever(g, nm).retrieve(["target"], max_hops=2)}
    assert hits == {"user", "helper"}  # CALLS neighbors only, both hops
    assert "mod_a" not in hits          # CONTAINS (up and down)
    assert "doc_a" not in hits          # DOCUMENTS (through the module)


def test_semantic_edges_expand_both_directions():
    g, nm = _module_graph()
    hits = {h.id for h in GraphRetriever(g, nm).retrieve(["helper"], max_hops=1)}
    assert hits == {"target"}  # inbound CALLS still traverses


def test_imports_are_semantic():
    g, nm = _module_graph()
    imp = _ent("imp_x", "x", EntityType.IMPORT, path="a.py")
    base_edges = [e for _, _, e in g._resolved]
    g2 = _FakeRxGraph(list(g._nodes) + [imp],
                      base_edges + [_edge("e9", "target", "imp_x", EdgeType.IMPORTS)])
    nm2 = dict(nm)
    nm2["imp_x"] = len(g2._nodes) - 1
    hits = {h.id for h in GraphRetriever(g2, nm2).retrieve(["target"], max_hops=1)}
    assert "imp_x" in hits
    assert "mod_a" not in hits


def test_hop_distance_scoring_and_determinism():
    # Chain target -> helper -> extra (all CALLS): helper is 1 hop,
    # extra is 2 hops from the seed. Closer beats farther.
    ents = [_ent("target", "target"), _ent("helper", "helper"),
            _ent("extra", "extra")]
    edges = [_edge("c1", "target", "helper", EdgeType.CALLS),
             _edge("c2", "helper", "extra", EdgeType.CALLS)]
    nm = {e.revision_entity_id: i for i, e in enumerate(ents)}
    g = _FakeRxGraph(ents, edges)
    r = GraphRetriever(g, nm)
    first = r.retrieve(["target"], max_hops=2)
    second = r.retrieve(["target"], max_hops=2)
    assert [(h.id, h.score) for h in first] == [(h.id, h.score) for h in second]
    by_id = {h.id: h.score for h in first}
    assert len(by_id) == len(first)      # no duplicate ids
    assert by_id["helper"] > by_id["extra"]  # 1-hop beats 2-hop
    assert by_id["helper"] == 1.0 and by_id["extra"] == 0.5


def test_graph_without_edge_index_map_falls_back_to_neighbors():
    """Old-shaped graphs (successors/predecessors over ids) still work:
    the retriever must not crash when edge payloads are unavailable."""
    class _OldGraph:
        def successors(self, node):
            return ["b"]
        def predecessors(self, node):
            return []
    hits = {h.id for h in GraphRetriever(_OldGraph(), {}).retrieve(["a"])}
    assert hits == {"b"}
