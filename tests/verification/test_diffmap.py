"""Diff filename parsing, including hostile inputs.

The UTF-16 case is a frozen regression fixture: a real PowerShell-redirected
`git diff` decoded as UTF-8 yields NUL-interleaved garbage. The parser must
return no seeds (→ inconclusive downstream), never throw, never hallucinate.
"""
from src.verification.diffmap import normalize_path, parse_diff_files


def test_plusplus_lines_yield_files():
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1 +1 @@\n"
    )
    assert parse_diff_files(diff) == ["src/app.py"]


def test_gibberish_yields_no_files():
    assert parse_diff_files("def f(): pass  # not a diff") == []
    assert parse_diff_files("") == []
    assert parse_diff_files(None) == []


def test_utf16_misdecoded_diff_yields_no_files():
    # b"+++ b/x.py\n" misdecoded: every char NUL-interleaved, as produced
    # when a UTF-16 `git diff` redirect is read as UTF-8.
    raw = "++ b/retrieval/context_assembly.py\n".encode("utf-16-le")
    garbled = raw.decode("utf-8", errors="replace")
    assert "\x00" in garbled  # fixture really is NUL-interleaved
    assert parse_diff_files(garbled) == []


def test_dev_null_and_duplicates():
    diff = "+++ /dev/null\n+++ b/a.py\n+++ b/a.py\n"
    assert parse_diff_files(diff) == ["a.py"]


def test_normalize_path_separators():
    assert normalize_path("src\\app.py") == "src/app.py"
    assert normalize_path("./src/app.py") == "src/app.py"
