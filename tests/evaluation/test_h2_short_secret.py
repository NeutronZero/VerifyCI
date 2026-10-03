"""H2-C failing-first: sub-12-char unquoted secrets are detected.

Residual `v2-gap-short-unquoted`: `AWS_SECRET_KEY=shortVal` (8 chars)
sits below the documented 12-char `UNQUOTED_SECRET_RE` floor and is
missed. These tests pin the intended OUTCOME: the residual line fails,
while short-but-legit shapes that pass today keep passing (precision
stays 1.00). They FAIL until detection reaches below the floor without
widening into wiring.
"""
from verifyci.contracts.verification_ir import Invariant
from verifyci.verification.intent_align import evaluate_invariants


def _inv(iid, query):
    return Invariant(invariant_id=iid, rule=iid, compiled_query=query, blocking=True)


def _diff(line: str) -> str:
    return ("diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n"
            "+++ b/src/app.py\n@@ -1,0 +1,1 @@\n+" + line + "\n")


def test_c_short_unquoted_secret_fails():
    # The residual itself, verbatim from the frozen label.
    checks, _ = evaluate_invariants(
        _diff("AWS_SECRET_KEY=shortVal"), [_inv("s", "secrets_scan")],
        graph=None, evidence=[])
    assert checks[0].passed is False


def test_c_short_quoted_value_stays_passing():
    # Below every quoted floor today; must not be swept up by a
    # widened unquoted rule (wrong shape entirely).
    checks, _ = evaluate_invariants(
        _diff('password = "x"'), [_inv("s", "secrets_scan")],
        graph=None, evidence=[])
    assert checks[0].passed is True


def test_c_env_lookup_stays_passing():
    # Wiring, not a literal — the documented negative that a louder
    # scanner is most likely to newly flag.
    checks, _ = evaluate_invariants(
        _diff('password = (os.environ.get("X"))'), [_inv("s", "secrets_scan")],
        graph=None, evidence=[])
    assert checks[0].passed is True
