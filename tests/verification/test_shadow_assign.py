"""Unit tests for the shadowed-assignment tripwire (P0 remediation).

Narrow scope, pinned here: per-hunk detection over ADDED assignment
lines only. A fire needs an earlier (context or added) line in the SAME
hunk assigning the identical normalized LHS with a DIFFERING RHS callee
set. Replaced lines (removed+added pairs) are modifications owned by
the call/return tripwires, never shadows. Anything unsplittable or
ambiguous stays silent (fail closed).
"""
from verifyci.verification.shadow_assign import (
    shadow_assignment_check,
    shadowed_assignments,
)


def _diff(*bodies):
    head = ("diff --git a/src/auth.py b/src/auth.py\n--- a/src/auth.py\n+++ b/src/auth.py\n"
            "@@ -12,5 +12,6 @@\n")
    return head + "".join(bodies)


def test_p1_shadow_fires_with_new_side_lineno():
    d = _diff(" def login(user, pw):\n", "     token = hash_pw(pw)\n",
              "+    token = check_password(pw)\n", "     return token\n")
    assert shadowed_assignments(d) == ["src/auth.py:14"]


def test_identical_reassignment_silent():
    d = _diff(" def login(user, pw):\n", "     token = hash_pw(pw)\n",
              "+    token = hash_pw(pw)\n", "     return token\n")
    assert shadowed_assignments(d) == []


def test_same_callee_arithmetic_silent():
    d = _diff(" def double(x):\n", "     y = f(x)\n",
              "+    y = f(x * 2)\n", "     return y\n")
    assert shadowed_assignments(d) == []


def test_constant_overwrite_fires():
    d = _diff(" def login(user, pw):\n", "     token = hash_pw(pw)\n",
              "+    token = 0\n", "     return token\n")
    assert shadowed_assignments(d) == ["src/auth.py:14"]


def test_renamed_lhs_silent():
    d = _diff(" def login(user, pw):\n", "     token = hash_pw(pw)\n",
              "+    tok = check_password(pw)\n", "     return token\n")
    assert shadowed_assignments(d) == []


def test_multiple_shadows_all_sites():
    d = _diff(" def f():\n", "     a = f()\n", "     b = g()\n",
              "+    a = h()\n", "+    b = i()\n", "+    a = j()\n")
    assert shadowed_assignments(d) == ["src/auth.py:15", "src/auth.py:16", "src/auth.py:17"]


def test_unrelated_additions_silent():
    d = _diff(" def f():\n", "     x = 1\n",
              "+    audit_log(x)\n", "+    return x\n", "+    import os\n")
    assert shadowed_assignments(d) == []


def test_unsplittable_lines_silent():
    d = _diff(" def f():\n", "     if a == b:\n",
              "+    if a == c:\n", "         pass\n")
    assert shadowed_assignments(d) == []


def test_replaced_lines_excluded():
    # Modification (removed+added same LHS), owned by call-swap — never
    # a shadow even though RHS callees differ.
    d = ("diff --git a/src/auth.py b/src/auth.py\n--- a/src/auth.py\n+++ b/src/auth.py\n"
         "@@ -12,5 +12,5 @@\n def login(user, pw):\n     if not check_password(pw):\n         return None\n"
         "-    token = hash_pw(pw)\n+    token = check_password(pw)\n     return token\n")
    assert shadowed_assignments(d) == []


def test_cross_hunk_assignment_silent():
    # Prior assignment lives in a DIFFERENT hunk: per-hunk scope stays
    # silent (narrow by design; file-scope extension is out of scope).
    d = ("diff --git a/src/auth.py b/src/auth.py\n--- a/src/auth.py\n+++ b/src/auth.py\n"
         "@@ -4,2 +4,3 @@\n def check_password(pw):\n+    token = hash_pw(pw)\n     return len(pw) >= 8\n"
         "@@ -16,1 +16,2 @@\n     return token\n+    token = check_password(pw)\n")
    assert shadowed_assignments(d) == []


def test_check_result_shape():
    d = _diff(" def login(user, pw):\n", "     token = hash_pw(pw)\n",
              "+    token = check_password(pw)\n", "     return token\n")
    check = shadow_assignment_check(d)
    assert check.check_id == "shadowed_assignment"
    assert check.passed is False
    assert check.blocking is False
    assert check.evidence == ["src/auth.py:14"]
    clean = _diff(" def f():\n", "     x = 1\n", "+    y = 2\n")
    ok = shadow_assignment_check(clean)
    assert ok.passed is True and ok.evidence == []
