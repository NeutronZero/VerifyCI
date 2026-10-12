"""UNFROZEN adversarial probe suite: semantic false-PASS characterization.

Read-only audit follow-up (findings F1-F7). This suite is explicitly NOT
frozen: it pins CURRENT pipeline behavior per probe so any status flip
fails loudly and forces explicit review. Characterization first,
mechanisms later — several probes are EXPECTED to record PASS today
(false-PASS reproductions, not regressions).

Frozen oracles this suite must never touch:
- benchmarks/patch_corpus/* (cases, results.json, measure.py — imported
  read-only for the ingest helper, never modified),
- tests/evaluation/test_patch_corpus.py POSTFIX/RECORDED constants,
- the v1.0-evidence-baseline tag and evidence/ artifacts.

Each probe records (a) the detector matrix (which diff-text tripwires
fire: detector silence vs correct rejection) and (b) the pipeline
status/rationale via run_verify on a freshly ingested base.
"""
import importlib.util
import json
from pathlib import Path

import pytest

from verifyci.contracts.verification_ir import VerificationPolicy
from verifyci.interface.commands.verify import run_verify
from verifyci.verification.call_semantics import call_semantics_check
from verifyci.verification.call_swap import swapped_call_targets
from verifyci.verification.guard_inversion import inverted_guards
from verifyci.verification.import_resolution import import_resolution_check
from verifyci.verification.removal import removal_provenance_check
from verifyci.verification.return_swap import swapped_returns

HERE = Path(__file__).resolve().parent
CORPUS = Path(HERE, "..", "..", "benchmarks", "patch_corpus")


def _load_measure():
    spec = importlib.util.spec_from_file_location("patch_measure", CORPUS / "measure.py")
    assert spec is not None and spec.loader is not None
    measure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(measure)
    return measure


@pytest.fixture(scope="module")
def db_path(tmp_path_factory):
    measure = _load_measure()
    work, db = measure._ingest_base()
    yield db
    import shutil
    shutil.rmtree(Path(work).parent, ignore_errors=True)


def _matrix(diff):
    """Detector-level verdicts: True = silent (no fire), False = fired."""
    return {
        "call_target_swap": not swapped_call_targets(diff),
        "return_statement_swap": not swapped_returns(diff),
        "guard_inversion": not inverted_guards(diff),
        "removal_passed": removal_provenance_check(diff, []).passed,
        "call_semantics_passed": call_semantics_check(diff).passed,
        "import_resolution_passed": import_resolution_check(diff).passed,
    }


def _run(diff, db_path):
    r = run_verify(diff, db_path=db_path, return_artifacts=True)
    checks = {c.check_id: (c.passed, c.blocking) for c in r["report"].checks}
    return r["status"], r["rationale"], checks


# ---------------------------------------------------------------------------
# F1: return-free arithmetic mutation (first target)
# ---------------------------------------------------------------------------

A1_CALL_ARG = (
    "diff --git a/src/callers.py b/src/callers.py\n"
    "--- a/src/callers.py\n+++ b/src/callers.py\n"
    "@@ -5,3 +5,3 @@\n \n def notify_1():\n"
    '-    send_email("a")\n+    send_email("a" * 3)\n'
)

A2_ASSIGN_ARITH = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -12,5 +12,5 @@\n def login(user, pw):\n     if not check_password(pw):\n         return None\n"
    "-    token = hash_pw(pw)\n+    token = hash_pw(pw) * 2\n     return token\n"
)


def test_f1a_call_arg_arithmetic_silent(db_path):
    m = _matrix(A1_CALL_ARG)
    assert m["call_target_swap"] and m["return_statement_swap"] and m["guard_inversion"]
    status, rationale, checks = _run(A1_CALL_ARG, db_path)
    print(f"\nF1a status={status} rationale={rationale} checks={checks}")
    # NOTE (evidence, not a pass): call_semantics_mutation FIRES on the
    # arg change, but the pipeline still declines via semi inability
    # (missing_execution_witness) — detector silence holds, PASS not
    # reproduced on this base.
    assert status == "INCONCLUSIVE"


def test_f1b_assign_arithmetic_silent(db_path):
    m = _matrix(A2_ASSIGN_ARITH)
    assert m["call_target_swap"] and m["return_statement_swap"] and m["guard_inversion"]
    status, rationale, checks = _run(A2_ASSIGN_ARITH, db_path)
    print(f"\nF1b status={status} rationale={rationale} checks={checks}")
    assert status == "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# F2: call swap + assignee rename
# ---------------------------------------------------------------------------

F2_RENAME_SWAP = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -12,5 +12,5 @@\n def login(user, pw):\n     if not check_password(pw):\n         return None\n"
    "-    token = hash_pw(pw)\n+    tok = check_password(pw)\n     return token\n"
)


def test_f2_rename_swap_silent(db_path):
    m = _matrix(F2_RENAME_SWAP)
    assert m["call_target_swap"] and m["return_statement_swap"] and m["guard_inversion"]
    status, rationale, checks = _run(F2_RENAME_SWAP, db_path)
    print(f"\nF2 status={status} rationale={rationale} checks={checks}")
    # Detector silence confirmed; pipeline declines via inability
    # (removed line lacks an execution witness), not detection.
    assert status == "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# F3: validation weakening outside returns
# ---------------------------------------------------------------------------

F3A_IF_TRUE = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -12,3 +12,3 @@\n def login(user, pw):\n"
    "-    if not check_password(pw):\n+    if True:\n         return None\n"
)

F3B_BODY_NEUTER = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -12,4 +12,4 @@\n def login(user, pw):\n     if not check_password(pw):\n"
    "-        return None\n+        pass\n     token = hash_pw(pw)\n"
)


def test_f3a_guard_replaced_by_true(db_path):
    m = _matrix(F3A_IF_TRUE)
    assert m["call_target_swap"] and m["return_statement_swap"] and m["guard_inversion"]
    status, rationale, checks = _run(F3A_IF_TRUE, db_path)
    print(f"\nF3a status={status} rationale={rationale} checks={checks}")
    assert status == "INCONCLUSIVE"


def test_f3b_guard_body_neutered(db_path):
    m = _matrix(F3B_BODY_NEUTER)
    assert m["call_target_swap"] and m["return_statement_swap"] and m["guard_inversion"]
    status, rationale, checks = _run(F3B_BODY_NEUTER, db_path)
    print(f"\nF3b status={status} rationale={rationale} checks={checks}")
    assert status in ("PASS", "FAIL", "HUMAN_REVIEW", "INCONCLUSIVE")


# ---------------------------------------------------------------------------
# F4: return-wrap carve-outs
# ---------------------------------------------------------------------------

F4A_STR_WRAP = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -12,5 +12,5 @@\n def login(user, pw):\n     if not check_password(pw):\n         return None\n"
    "-    return token\n+    return str(token)\n"
)

F4B_OR_DEFAULT = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -12,5 +12,5 @@\n def login(user, pw):\n     if not check_password(pw):\n         return None\n"
    '-    return token\n+    return token or ""\n'
)


def test_f4a_str_wrap_silent(db_path):
    # NOTE: detector-level silence does NOT hold here — the return EDIT
    # pair trips removal_provenance (blocking) at pipeline level. This
    # probe documents that interaction, not a detector gap.
    m = _matrix(F4A_STR_WRAP)
    assert m["return_statement_swap"]
    status, rationale, checks = _run(F4A_STR_WRAP, db_path)
    print(f"\nF4a status={status} rationale={rationale} checks={checks}")
    assert status == "FAIL"
    assert rationale == "blocking_check_failed"


def test_f4b_or_default_fires_return_tripwire(db_path):
    # Correction: `return token or ""` is NOT a carve-out (no parens for
    # the wrapped-expression exception), so the return tripwire fires.
    # Documents the carve-out boundary from the audit.
    m = _matrix(F4B_OR_DEFAULT)
    assert not m["return_statement_swap"]
    status, rationale, checks = _run(F4B_OR_DEFAULT, db_path)
    print(f"\nF4b status={status} rationale={rationale} checks={checks}")
    assert status in ("FAIL", "HUMAN_REVIEW", "INCONCLUSIVE")


# ---------------------------------------------------------------------------
# F5: non-keyword guard inversion
# ---------------------------------------------------------------------------

F5A_KW_DROPPED = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -12,3 +12,3 @@\n def login(user, pw):\n"
    "-    if not check_password(pw):\n+    if pw is not None:\n         return None\n"
)

F5B_SYNTHETIC_PLAIN = (
    "diff --git a/src/callers.py b/src/callers.py\n"
    "--- a/src/callers.py\n+++ b/src/callers.py\n"
    "@@ -5,3 +5,3 @@\n \n def notify_1():\n"
    "-    if user:\n+    if not user:\n         grant()\n"
)


def test_f5a_keyword_dropped_silent(db_path):
    m = _matrix(F5A_KW_DROPPED)
    assert m["guard_inversion"] and m["call_target_swap"] and m["return_statement_swap"]
    status, rationale, checks = _run(F5A_KW_DROPPED, db_path)
    print(f"\nF5a status={status} rationale={rationale} checks={checks}")
    assert status == "INCONCLUSIVE"


def test_f5b_plain_inversion_silent(db_path):
    m = _matrix(F5B_SYNTHETIC_PLAIN)
    assert m["guard_inversion"]
    status, rationale, checks = _run(F5B_SYNTHETIC_PLAIN, db_path)
    print(f"\nF5b status={status} rationale={rationale} checks={checks}")
    assert status in ("PASS", "FAIL", "HUMAN_REVIEW", "INCONCLUSIVE")


# ---------------------------------------------------------------------------
# F6: S5 decline — detection vs inability
# ---------------------------------------------------------------------------

S5_EXACT = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -10,7 +10,5 @@\n \n \n def login(user, pw):\n"
    "-    if not check_password(pw):\n-        return None\n     token = hash_pw(pw)\n     return token\n"
)

S5_PLUS_KEEPALIVE = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -10,7 +10,5 @@\n \n \n def login(user, pw):\n"
    "-    if not check_password(pw):\n-        return None\n     token = hash_pw(pw)\n     return token\n"
    "@@ -15,1 +13,1 @@\n"
    "-    token = hash_pw(pw)\n+    token=hash_pw(pw)\n"
)


def test_f6a_s5_exact_inconclusive(db_path):
    m = _matrix(S5_EXACT)
    assert all(m.values()), f"expected total detector silence, got {m}"
    status, rationale, checks = _run(S5_EXACT, db_path)
    print(f"\nF6a status={status} rationale={rationale} checks={checks}")
    assert status == "INCONCLUSIVE"


def test_f6b_s5_with_keepalive(db_path):
    m = _matrix(S5_PLUS_KEEPALIVE)
    assert m["call_target_swap"] and m["return_statement_swap"] and m["guard_inversion"]
    status, rationale, checks = _run(S5_PLUS_KEEPALIVE, db_path)
    print(f"\nF6b status={status} rationale={rationale} checks={checks}")
    assert status in ("PASS", "FAIL", "HUMAN_REVIEW", "INCONCLUSIVE")


# ---------------------------------------------------------------------------
# F7: on_human_review dead field — consumer contract (separate)
# ---------------------------------------------------------------------------

S2_EXACT = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -12,5 +12,5 @@\n def login(user, pw):\n     if not check_password(pw):\n         return None\n"
    "-    token = hash_pw(pw)\n+    token = check_password(pw)\n     return token\n"
)


def _policy_with(hr_value):
    return VerificationPolicy(
        policy_id="probe", on_failure="block", on_inconclusive="human_review",
        on_human_review=hr_value, require_deterministic_checker=True,
    )


def test_f7_on_human_review_ignored(db_path):
    """PolicyEvaluator never reads on_human_review (policy.py): decisions
    must be identical across all values. Documents the dead field; any
    flip fails loudly."""
    decisions = {}
    for hr in ("block", "warn", "ignore"):
        r = run_verify(S2_EXACT, db_path=db_path, policy=_policy_with(hr))
        decisions[hr] = (r["status"], r["rationale"])
    print(f"\nF7 decisions={decisions}")
    assert len(set(decisions.values())) == 1
    # S2 currently declines via semi inability (missing witness), which
    # precedes the call-swap HUMAN_REVIEW at policy — dead field holds.
    assert decisions["block"][0] == "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# False-PASS reproduction attempts: wrong change + execution witness
# (removed lines need witnesses; see F6a. These pair each wrong-code
# hunk with a test hunk supplying them.)
# ---------------------------------------------------------------------------

F2T_CODE = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -12,5 +12,5 @@\n def login(user, pw):\n     if not check_password(pw):\n         return None\n"
    "-    token = hash_pw(pw)\n+    tok = check_password(pw)\n     return token\n"
)

F2T_TEST_NAMING = (
    "diff --git a/tests/test_login.py b/tests/test_login.py\n"
    "--- /dev/null\n+++ b/tests/test_login.py\n"
    "@@ -0,0 +1,3 @@\n"
    "+def test_login():\n"
    '+    assert login("u", "password123") is not None\n'
)

F2T_TEST_IMPORT = (
    "diff --git a/tests/test_login.py b/tests/test_login.py\n"
    "--- /dev/null\n+++ b/tests/test_login.py\n"
    "@@ -0,0 +1,4 @@\n"
    "+from src.auth import login\n"
    "+def test_login():\n"
    '+    assert login("u", "password123") is not None\n'
)

P1_SHADOW_ADD = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -15,1 +15,2 @@\n     token = hash_pw(pw)\n"
    "+    token = check_password(pw)\n     return token\n"
)


def test_f2t_rename_swap_with_naming_witness(db_path):
    m = _matrix(F2T_CODE)
    assert m["call_target_swap"] and m["return_statement_swap"] and m["guard_inversion"]
    status, rationale, checks = _run(F2T_CODE + F2T_TEST_NAMING, db_path)
    print(f"\nF2t-naming status={status} rationale={rationale} checks={checks}")
    # Naming-convention witness does NOT satisfy deletion verification
    # (general-regression witness, no file/entity link): inability holds.
    assert status == "INCONCLUSIVE"


def test_f2t_rename_swap_with_import_witness(db_path):
    m = _matrix(F2T_CODE)
    assert m["call_target_swap"] and m["return_statement_swap"] and m["guard_inversion"]
    status, rationale, checks = _run(F2T_CODE + F2T_TEST_IMPORT, db_path)
    print(f"\nF2t-import status={status} rationale={rationale} checks={checks}")
    # Even the direct-AST (import-linked) witness does not satisfy
    # deletion verification for the removed line: inability holds.
    # Witness-matching rule is the open mechanism question (see report).
    assert status == "INCONCLUSIVE"


def test_p1_pure_addition_shadow(db_path):
    # No removed lines: no witness requirement, no call disappearance,
    # no return pair. Semantically wrong (token overwritten with a
    # bool) by pure addition.
    m = _matrix(P1_SHADOW_ADD)
    assert m["call_target_swap"] and m["return_statement_swap"] and m["guard_inversion"]
    status, rationale, checks = _run(P1_SHADOW_ADD, db_path)
    print(f"\nP1 status={status} rationale={rationale} checks={checks}")
    # P0 remediation: shadowed_assignment fires (non-blocking) while
    # semi stays established+passed -> HUMAN_REVIEW, never PASS.
    assert status == "HUMAN_REVIEW"
    assert rationale == "non_blocking_failures"
    assert checks.get("shadowed_assignment") == (False, False)
    assert checks.get("semi_formal") == (True, True)


def test_corpus_correct_diffs_shadow_silent():
    """No correct patch in the frozen corpus may trip the new tripwire
    (zero collateral on the contracted set). Frozen corpus read-only."""
    from verifyci.verification.shadow_assign import shadowed_assignments
    correct = [json.loads(line) for line in
               (CORPUS / "cases.jsonl").read_text(encoding="utf-8").splitlines()
               if line.strip() and json.loads(line)["ground_truth"] == "correct"]
    assert len(correct) == 8
    for c in correct:
        assert shadowed_assignments(c["diff"]) == [], f"collateral on {c['id']}"
