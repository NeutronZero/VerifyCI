from verifyci.contracts.verification_ir import Invariant
from verifyci.verification.intent_align import evaluate_invariants
from verifyci.graph.builder import GraphBuilder
from verifyci.ingestion.extractor import extract_edges
from verifyci.ingestion.extractor import extract_entities
from verifyci.ingestion.parser import TreeSitterParser
def _inv(iid, query):
    return Invariant(invariant_id=iid, rule=iid, compiled_query=query, blocking=True)
def _shop_graph():
    src = b"def order():\n    return checkout(\"cart\")\n\ndef checkout(cart):\n    return cart\n"
    parsed = TreeSitterParser().parse("shop.py", src, "python")
    ents = extract_entities(parsed, "repo", "rev1")
    edges = extract_edges(parsed, ents, "rev1")
    return GraphBuilder().build(ents, edges)
def test_has_error_unbalanced_is_inconclusive():
    diff = "diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n@@ -1,0 +1,1 @@\n+    eval(user_input\n"
    checks, _ = evaluate_invariants(diff, [_inv("f", "forbid_call:eval")], graph=_shop_graph(), evidence=[])
    assert checks[0].established is False
def test_exception_is_inconclusive(monkeypatch):
    import verifyci.verification.added_refs as ar
    def _boom(diff):
        raise RuntimeError("parse boom")
    monkeypatch.setattr(ar, "extract_added_refs_status", _boom)
    diff = "diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n@@ -1,0 +1,1 @@\n+    eval(user_input)\n"
    checks, _ = evaluate_invariants(diff, [_inv("f", "forbid_call:eval")], graph=None, evidence=[])
    assert checks[0].established is False
def test_cpp_qualified_system_caught():
    diff = "diff --git a/src/a.cpp b/src/a.cpp\n--- a/src/a.cpp\n+++ b/src/a.cpp\n@@ -1,0 +1,1 @@\n+    std::system(cmd);\n"
    checks, _ = evaluate_invariants(diff, [_inv("f", "forbid_call:system")], graph=None, evidence=[])
    assert checks[0].passed is False
def test_unresolved_graph_caught():
    from verifyci.contracts.edge import Edge
    from verifyci.contracts.edge import EdgeType
    class FakeUnresolvedGraph:
        def nodes(self):
            return []
        def edge_index_map(self):
            e = Edge(id="e1", revision_id="rev1", src_entity_id="src1", dst_entity_id="", type=EdgeType.CALLS_UNRESOLVED, subtype=None, valid_from=0.0, observed_at=0.0, t_created=0.0, metadata={"callee": "eval", "caller_scope": ""})
            return {0: (0, 0, e)}
    checks, _ = evaluate_invariants("x", [_inv("f", "forbid_call:eval")], graph=FakeUnresolvedGraph(), evidence=[])
    assert checks[0].passed is False
