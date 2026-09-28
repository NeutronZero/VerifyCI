from src.contracts.verification_ir import Invariant
from src.graph.builder import GraphBuilder
from src.ingestion.extractor import extract_edges, extract_entities
from src.ingestion.parser import TreeSitterParser
from src.verification.intent_align import evaluate_invariants, score_labeled

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


def test_labeled_set_meets_plan_gates():
    # PLAN.md: detection recall >= 0.90, precision >= 0.85 on a labeled set.
    from src.contracts.verification_ir import FileEvidence
    graph = _graph()
    ev = [FileEvidence(file_path="shop.py", line_start=1, line_end=2,
                       snippet="order", source_hash="h")]
    evil = '+++ b/shop.py\n+password = "hunter2"\n'
    clean = '+++ b/shop.py\n+x = 1\n'
    cases = [
        (evil, _inv("s1", "secrets_scan"), None, [], True),
        (clean, _inv("s2", "secrets_scan"), None, [], False),
        ("x", _inv("f1", "forbid_call:checkout"), graph, [], True),
        ("x", _inv("f2", "forbid_call:refund"), graph, [], False),
        ("x", _inv("p1", "provenance_check"), None, [], True),
        ("x", _inv("p2", "provenance_check"), None, ev, False),
    ]
    metrics = score_labeled(cases)
    assert metrics.check_coverage == 1.0
    assert metrics.detection_recall >= 0.90
    assert metrics.detection_precision >= 0.85


def test_unlabeled_metrics_report_unmeasured():
    _, metrics = evaluate_invariants("x", [_inv("s", "secrets_scan")], graph=None)
    assert metrics.check_coverage == 1.0
    assert metrics.detection_recall == 0.0
    assert metrics.detection_precision == 0.0
