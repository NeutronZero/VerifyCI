from verifyci.contracts.verification_ir import Invariant
from verifyci.verification.intent_align import evaluate_invariants
def _inv(iid, query):
    return Invariant(invariant_id=iid, rule=iid, compiled_query=query, blocking=True)
def test_json_colon_form_fails():
    diff = "diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n@@ -1,0 +1,1 @@\n+{\"api_key\": \"12345678ABCDEFGH\"}\n"
    checks, _ = evaluate_invariants(diff, [_inv("s", "secrets_scan")], graph=None, evidence=[])
    assert checks[0].passed is False
def test_secret_line_numbers_are_real():
    diff = "diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n@@ -10,3 +20,3 @@\n context1\n+password = \"hunter2hunter\"\n context2\n"
    checks, _ = evaluate_invariants(diff, [_inv("s", "secrets_scan")], graph=None, evidence=[])
    assert checks[0].passed is False
    ev = checks[0].evidence[0]
    assert ev.startswith("src/app.py:21:")
def test_forbid_evidence_only_parser_lines():
    diff = "diff --git a/src/a.py b/src/a.py\n--- a/src/a.py\n+++ b/src/a.py\n@@ -1,0 +1,1 @@\n+    eval(user_input)\n"
    diff = diff + "diff --git a/src/b.py b/src/b.py\n--- a/src/b.py\n+++ b/src/b.py\n@@ -1,0 +1,1 @@\n+    evaluation = 1\n"
    checks, _ = evaluate_invariants(diff, [_inv("f", "forbid_call:eval")], graph=None, evidence=[])
    assert checks[0].passed is False
    evs = checks[0].evidence
    assert len(evs) > 0
    assert all(e.startswith("src/a.py:") for e in evs)
