"""Retrieval blast radius: dependency/vulnerability impact helpers.

`compute_blast_radius` traversal is pinned by the frozen blast corpus;
these tests cover the advisory impact helpers (dict/object dependency
graphs, DEPENDS_ON edge packages, vuln-cache lookup) and the
unknown-seed / test-gap branches.
"""

from types import SimpleNamespace

from verifyci.retrieval.blast_radius import (
    _dependency_impact,
    _graph_dependency_packages,
    _vulnerability_impact,
    compute_blast_radius,
)


class FakeGraph:
    def __init__(self, preds=None, succs=None, edges=None):
        self._preds = preds or {}
        self._succs = succs or {}
        self._edges = edges or []

    def predecessors(self, idx):
        return self._preds.get(idx, [])

    def successors(self, idx):
        return self._succs.get(idx, [])

    def edge_index_map(self):
        return {i: (None, None, e) for i, e in enumerate(self._edges)}


def _edge(etype, package=None, src="c", dst="x"):
    return SimpleNamespace(
        type=etype,
        metadata={"package": package} if package else {},
        src_entity_id=src,
        dst_entity_id=dst,
    )


def test_unknown_seed_skipped():
    out = compute_blast_radius(FakeGraph(), ["ghost"], set(), node_map={"real": 1})
    assert out.affected_callers == [] and out.affected_callees == []
    assert out.risk_score == 0.0


def test_none_graph_with_empty_map():
    out = compute_blast_radius(None, ["e"], set(), node_map={})
    assert out.affected_callers == [] and out.risk_score == 0.0
    assert out.dependency_impact == [] and out.vulnerability_impact == []


def test_test_entities_gap_counts_untested_dependents():
    g = FakeGraph(preds={1: [101]})
    node_map = {"changed": 1, "caller": 101}
    full = compute_blast_radius(g, ["changed"], {"other"}, node_map=node_map)
    assert full.test_coverage_gap == ["caller"]
    assert full.risk_score == 0.1 + 0.2  # 1 caller + 1 gap
    covered = compute_blast_radius(g, ["changed"], {"caller"}, node_map=node_map)
    assert covered.test_coverage_gap == []
    assert covered.risk_score == 0.1


def test_dependency_dict_graph():
    out = _dependency_impact({"changed": ["flask", "requests"]}, {"changed"})
    assert out == ["flask", "requests"]


def test_dependency_object_graph():
    class Deps:
        def dependents(self, eid):
            return ["pkg-a"] if eid == "changed" else []

    assert _dependency_impact(Deps(), {"changed"}) == ["pkg-a"]
    assert _dependency_impact(Deps(), {"other"}) == []


def test_dependency_errors_swallowed():
    class Broken:
        def dependents(self, eid):
            raise RuntimeError("boom")

    assert _dependency_impact(Broken(), {"changed"}) == []


def test_graph_depends_on_packages():
    g = FakeGraph(
        edges=[
            _edge("DEPENDS_ON", package="flask", src="c"),
            _edge("DEPENDS_ON", package="flask", src="c"),  # deduped
            _edge("CALLS", package="not-a-dep", src="c"),  # wrong edge type
            _edge("DEPENDS_ON", src="c"),  # no package recorded
            _edge("DEPENDS_ON", package="far", src="zzz", dst="yyy"),  # untouched
        ]
    )
    assert _graph_dependency_packages(g, {"c"}) == {"flask"}
    assert _graph_dependency_packages(None, {"c"}) == set()
    assert _graph_dependency_packages(g, set()) == set()


def test_vuln_lookup_reports_ids():
    class Cache:
        def lookup(self, edge):
            assert edge.metadata["package"] in ("flask", "requests")
            return [{"id": "CVE-2"}, "CVE-1"]

    out = _vulnerability_impact(Cache(), {"flask", "requests"})
    assert out == ["CVE-1", "CVE-2"]  # sorted, deduped


def test_graph_edge_map_errors_swallowed():
    class BrokenMap(FakeGraph):
        def edge_index_map(self):
            raise RuntimeError("boom")

    assert _graph_dependency_packages(BrokenMap(), {"c"}) == set()


def test_vuln_absent_or_broken_cache_is_empty():
    assert _vulnerability_impact(None, {"flask"}) == []
    assert _vulnerability_impact(object(), {"flask"}) == []

    class NoLookup:
        pass

    assert _vulnerability_impact(NoLookup(), {"flask"}) == []

    class Broken:
        def lookup(self, edge):
            raise RuntimeError("boom")

    assert _vulnerability_impact(Broken(), {"flask"}) == []
    assert _vulnerability_impact(Broken(), set()) == []
