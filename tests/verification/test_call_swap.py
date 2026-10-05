"""Call-target swap tripwire: S2 shape declines, everything else passes."""
from verifyci.verification.call_swap import (
    call_target_check, swapped_call_targets,
)

S2 = ("diff --git a/src/auth.py b/src/auth.py\n"
      "--- a/src/auth.py\n+++ b/src/auth.py\n"
      "@@ -12,5 +12,5 @@\n"
      " def login(user, pw):\n"
      "     if not check_password(pw):\n"
      "         return None\n"
      "-    token = hash_pw(pw)\n"
      "+    token = check_password(pw)\n"
      "     return token\n")


def test_s2_shape_flags_with_location():
    assert swapped_call_targets(S2) == ["src/auth.py:15"]
    check = call_target_check(S2)
    assert check.check_id == "call_target_swap"
    assert check.passed is False
    assert check.blocking is False
    assert getattr(check, "established", True) is True
    assert check.evidence == ["src/auth.py:15"]


def test_added_call_alongside_kept_callee_passes():
    # `f(a)` -> `f(a) + g(b)`: nothing disappeared, silence.
    diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-    x = f(a)\n"
            "+    x = f(a) + g(b)\n")
    assert swapped_call_targets(diff) == []
    assert call_target_check(diff).passed is True


def test_argument_only_change_passes():
    diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-    x = f(a)\n"
            "+    x = f(b)\n")
    assert swapped_call_targets(diff) == []


def test_pure_call_addition_passes():
    # C1/C3/C4 shape: added call, no removed line at all.
    diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1,2 +1,3 @@\n"
            " def n():\n"
            "     send_email(\"a\")\n"
            "+    send_email(\"a2\")\n")
    assert swapped_call_targets(diff) == []


def test_lhs_rename_out_of_scope():
    # Assignee renamed too: no same-LHS pair, no guess.
    diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-    token = hash_pw(pw)\n"
            "+    result = check_password(pw)\n")
    assert swapped_call_targets(diff) == []


def test_comments_pass_but_embedded_comparison_fires():
    # Comment lines never fire; a call swap inside a comparison still
    # does — the `==`-aware splitter pairs on the real assignee `ok`.
    diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1,5 +1,5 @@\n"
            "-    # token = hash_pw(pw)\n"
            "+    # token = check_password(pw)\n"
            "-    ok = (a == f(x))\n"
            "+    ok = (a == g(x))\n")
    assert swapped_call_targets(diff) == ["a.py:2"]


def test_non_code_partitions_ignored():
    diff = ("diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n"
            "@@ -1,2 +1,2 @@\n"
            "-token = hash_pw(pw)\n"
            "+token = check_password(pw)\n")
    assert swapped_call_targets(diff) == []
    assert swapped_call_targets(None) == []
    assert swapped_call_targets("") == []


def test_check_never_blocks():
    flagged = call_target_check(S2)
    clean = call_target_check(None)
    assert flagged.blocking is False and clean.blocking is False
    assert clean.passed is True and clean.score == 1.0
