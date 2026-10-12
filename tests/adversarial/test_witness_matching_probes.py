"""UNFROZEN witness-matching isolation probes (F2 follow-up).

Characterizes `deletion._has_associated_witness` — the rule behind the
F2t pipeline results (import-linked witnesses still INCONCLUSIVE).
Pins CURRENT behavior; flips fail loudly. Frozen oracles untouched.

Findings pinned here:
- W0: diff-extracted witnesses never carry execution receipts (hints
  only, per Contract 5) — no diff-only witness can satisfy Class 2.
- W1-W5: the matching conjunction (non-general + verified receipt +
  entity-scoped id equality). File-level witnesses do NOT corroborate
  per the code, though the docstring suggests otherwise (flagged, not
  changed).
"""
from types import SimpleNamespace

from verifyci.contracts.verification_ir import ExecutionWitness
from verifyci.verification.deletion import _has_associated_witness
from verifyci.verification.witness import extract_execution_witnesses

F2T_IMPORT = (
    "diff --git a/tests/test_login.py b/tests/test_login.py\n"
    "--- /dev/null\n+++ b/tests/test_login.py\n"
    "@@ -0,0 +1,4 @@\n"
    "+from src.auth import login\n"
    "+def test_login():\n"
    '+    assert login("u", "password123") is not None\n'
)


def _entity(eid="e_login"):
    return SimpleNamespace(revision_entity_id=eid, name="login")


def _witness(**kw):
    base = dict(witness_id="w1", test_file="tests/test_login.py",
                test_function="test_login", target_entity_id="e_login",
                target_file="src/auth.py", is_general_regression=False,
                association_method="direct_ast", execution_receipt_id=None,
                execution_verified=False)
    base.update(kw)
    return ExecutionWitness(**base)


def test_w0_diff_witnesses_carry_no_receipt():
    ws = extract_execution_witnesses(
        diff=F2T_IMPORT, code_files=["src/auth.py"],
        test_files=["tests/test_login.py"], entities=[_entity()])
    assert ws, "expected at least one extracted witness"
    assert all(not w.execution_verified for w in ws)
    assert all(w.execution_receipt_id is None for w in ws)
    # And therefore none satisfies the Class-2 rule, however linked.
    assert all(not _has_associated_witness("src/auth.py", _entity(), [w]) for w in ws)


def test_w1_unverified_entity_witness_rejected():
    assert _has_associated_witness("src/auth.py", _entity(), [_witness()]) is False


def test_w2_verified_receipt_entity_match_accepted():
    w = _witness(execution_verified=True, execution_receipt_id="run-1")
    assert _has_associated_witness("src/auth.py", _entity(), [w]) is True


def test_w3_verified_receipt_wrong_entity_rejected():
    w = _witness(execution_verified=True, execution_receipt_id="run-1")
    assert _has_associated_witness("src/auth.py", _entity("e_other"), [w]) is False


def test_w4_verified_general_regression_rejected():
    w = _witness(execution_verified=True, execution_receipt_id="run-1",
                 is_general_regression=True)
    assert _has_associated_witness("src/auth.py", _entity(), [w]) is False


def test_w5_verified_file_level_witness_rejected():
    # Code behavior (deletion.py): only target_entity_id equality
    # corroborates; file-level association does not — despite the
    # docstring's file-level clause. Pinned as-is; doc fix is separate.
    w = _witness(execution_verified=True, execution_receipt_id="run-1",
                 target_entity_id=None, target_file="src/auth.py")
    assert _has_associated_witness("src/auth.py", _entity(), [w]) is False
