"""Return-swap tripwire: S3 shape declines, everything else passes."""
from verifyci.verification.return_swap import (
    return_statement_check, swapped_returns,
)

S3 = ("diff --git a/src/auth.py b/src/auth.py\n"
      "--- a/src/auth.py\n+++ b/src/auth.py\n"
      "@@ -13,4 +13,4 @@\n"
      "     if not check_password(pw):\n"
      "         return None\n"
      "     token = hash_pw(pw)\n"
      "-    return token\n"
      "+    return user\n")


def test_s3_shape_flags_with_location():
    assert swapped_returns(S3) == ["src/auth.py:16"]
    check = return_statement_check(S3)
    assert check.check_id == "return_statement_swap"
    assert check.passed is False
    assert check.blocking is False
    assert getattr(check, "established", True) is True
    assert check.evidence == ["src/auth.py:16"]


def test_identical_return_rewrite_passes():
    diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-    return   token\n"
            "+    return token\n")
    assert swapped_returns(diff) == []
    assert return_statement_check(diff).passed is True


def test_pure_return_addition_passes():
    # C2/C5/C8 shape: a second `return` after an early one, nothing
    # removed — unreachable-code additions are not swaps.
    diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -3,3 +3,4 @@\n"
            " def double(x):\n"
            "     return x * 2\n"
            "+    return (x * 2)\n")
    assert swapped_returns(diff) == []


def test_comments_strings_and_prefix_names_pass():
    diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1,4 +1,4 @@\n"
            "-    # return token\n"
            "+    # return user\n"
            "-    x = \"return token\"\n"
            "+    x = \"return user\"\n"
            "-    returned = token\n"
            "+    returned = user\n")
    assert swapped_returns(diff) == []


def test_non_code_partitions_ignored():
    diff = ("diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n"
            "@@ -1,2 +1,2 @@\n"
            "-return token\n"
            "+return user\n")
    assert swapped_returns(diff) == []
    assert swapped_returns(None) == []
    assert swapped_returns("") == []


def test_check_never_blocks():
    # Even flagging, the tripwire escalates (HUMAN_REVIEW), never FAILs.
    flagged = return_statement_check(S3)
    clean = return_statement_check(None)
    assert flagged.blocking is False and clean.blocking is False
    assert clean.passed is True and clean.score == 1.0
