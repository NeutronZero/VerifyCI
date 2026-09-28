from src.contracts.verification_ir import Invariant
from src.graph.builder import GraphBuilder
from src.ingestion.extractor import extract_edges, extract_entities
from src.ingestion.parser import TreeSitterParser
from src.verification.intent_align import evaluate_invariants

SOURCE = b"""def order():
    return checkout("cart")

def checkout(cart):
    return cart
"""


def _inv(iid, query, blocking=True):
    return Invariant(invariant_id=iid, rule=iid, compiled_query=query, blocking=blocking)


def _graph():
    parsed = TreeSitterParser().parse("shop.py", SOURCE, "python")
    entities = extract_entities(parsed, "repo", "rev1")
    edges = extract_edges(parsed, entities, "rev1")
    builder = GraphBuilder()
    return builder.build(entities, edges)


def test_secrets_in_diff_fail_blocking():
    diff = '+++ b/shop.py\n+password = "hunter2"\n'
    checks, _ = evaluate_invariants(diff, [_inv("s", "secrets_scan")], graph=None, evidence=[])
    assert checks[0].passed is False


def test_clean_diff_passes_secrets():
    diff = '+++ b/shop.py\n+x = 1\n'
    checks, _ = evaluate_invariants(diff, [_inv("s", "secrets_scan")], graph=None, evidence=[])
    assert checks[0].passed is True


def test_forbid_call_violation_fails():
    graph = _graph()
    checks, _ = evaluate_invariants("x", [_inv("f", "forbid_call:checkout")], graph=graph)
    assert checks[0].passed is False


def test_forbid_call_absent_passes():
    graph = _graph()
    checks, _ = evaluate_invariants("x", [_inv("f", "forbid_call:refund")], graph=graph)
    assert checks[0].passed is True


def test_unknown_query_fails_closed():
    checks, _ = evaluate_invariants("x", [_inv("u", "temporal_reasoning")], graph=None)
    assert checks[0].passed is False


def test_provenance_needs_evidence():
    from src.contracts.verification_ir import FileEvidence
    ev = [FileEvidence(file_path="a.py", line_start=1, line_end=2, snippet="x", source_hash="h")]
    (fail,) = evaluate_invariants("x", [_inv("p", "provenance_check")], graph=None, evidence=[])[0]
    (ok,) = evaluate_invariants("x", [_inv("p", "provenance_check")], graph=None, evidence=ev)[0]
    assert fail.passed is False
    assert ok.passed is True
