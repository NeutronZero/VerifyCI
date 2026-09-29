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


def test_unquoted_secrets_fail():
    # The quotes-only regex passed every one of these; all are real leaks.
    for added in (
        "DB_PASSWORD=s3cr3tPr0dValue",
        "AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMIK7MDENGbPxRfiCY",
        'aws_key = "AKIAIOSFODNN7EXAMPLE"',
        "token = -----BEGIN RSA PRIVATE KEY-----",
        'DSN = "postgres://u:sup3rs3cret@h/db"',
    ):
        diff = f"diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n@@ -1,0 +1,1 @@\n+{added}\n"
        checks, _ = evaluate_invariants(diff, [_inv("s", "secrets_scan")], graph=None, evidence=[])
        assert checks[0].passed is False, added


def test_env_lookups_do_not_match():
    # Unquoted matching must not flag code that reads secrets instead of
    # embedding them: the value has to run to end-of-line/comment.
    for added in (
        'api_key = os.environ.get("API_KEY")',
        "password = get_password()",
        'token = os.getenv("X", "default")',
    ):
        diff = f"diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n@@ -1,0 +1,1 @@\n+{added}\n"
        checks, _ = evaluate_invariants(diff, [_inv("s", "secrets_scan")], graph=None, evidence=[])
        assert checks[0].passed is True, added


def test_secrets_outside_hunks_still_fail():
    # Preamble lines and header-region lines (no @@) used to bypass the
    # scanner while still grounding the diff.
    preamble = '+password = "hunter2hunter2"\n' + (
        "diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n"
        "@@ -1 +1,2 @@\n x = 1\n+y = 2\n")
    checks, _ = evaluate_invariants(preamble, [_inv("s", "secrets_scan")], graph=None, evidence=[])
    assert checks[0].passed is False
    no_hunk = ("diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n"
               '+password = "hunter2hunter2"\n')
    checks, _ = evaluate_invariants(no_hunk, [_inv("s", "secrets_scan")], graph=None, evidence=[])
    assert checks[0].passed is False


def test_forbid_call_violation_fails():
    graph = _graph()
    checks, _ = evaluate_invariants("x", [_inv("f", "forbid_call:checkout")], graph=graph)
    assert checks[0].passed is False


def test_forbid_call_absent_passes():
    graph = _graph()
    checks, _ = evaluate_invariants("x", [_inv("f", "forbid_call:refund")], graph=graph)
    assert checks[0].passed is True


def test_forbid_fails_closed_on_broken_graph():
    # A graph whose traversal raises is unevaluable, not clean: the
    # check must reject (FAIL at policy), never pass vacuously.
    class _Broken:
        def nodes(self):
            raise RuntimeError("corrupt")

    checks, _ = evaluate_invariants("x", [_inv("f", "forbid_call:checkout")],
                                    graph=_Broken())
    assert checks[0].passed is False
    assert checks[0].established is True
    assert "fail-closed" in checks[0].explanation


def test_unknown_query_fails_closed():
    # Check-level verdict (failed) vs decision-level routing: a failed
    # blocking check with no certificate is a *rejection* at the policy
    # layer (FAIL), distinct from an ungrounded diff (no seeds), which is
    # inability (INCONCLUSIVE). See test_policy_*_is_* for the routing;
    # "unknown → INCONCLUSIVE" in the matrix refers to unknown *files*.
    checks, _ = evaluate_invariants("x", [_inv("u", "temporal_reasoning")], graph=None)
    assert checks[0].passed is False


def test_provenance_needs_evidence():
    from src.contracts.verification_ir import FileEvidence
    ev = [FileEvidence(file_path="a.py", line_start=1, line_end=2, snippet="x", source_hash="h")]
    (fail,) = evaluate_invariants("x", [_inv("p", "provenance_check")], graph=None, evidence=[])[0]
    (ok,) = evaluate_invariants("x", [_inv("p", "provenance_check")], graph=None, evidence=ev)[0]
    assert fail.passed is False
    assert ok.passed is True


def test_unlabeled_metrics_report_unmeasured():
    _, metrics = evaluate_invariants("x", [_inv("s", "secrets_scan")], graph=None)
    assert metrics.check_coverage == 1.0
    assert metrics.detection_recall is None
    assert metrics.detection_precision is None
