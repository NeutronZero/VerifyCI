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


def test_truncated_diff_still_grounds():
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1 +1 @@\n"
        "-x = 1\n"
        # hunk body cut off mid-diff
    )
    assert parse_diff_files(diff) == ["src/app.py"]


def test_deletion_only_diff_names_old_file():
    diff = (
        "diff --git a/src/old.py b/src/old.py\n"
        "deleted file mode 100644\n"
        "--- a/src/old.py\n"
        "+++ /dev/null\n"
    )
    assert parse_diff_files(diff) == ["src/old.py"]


def test_git_internals_path_extracted_verbatim():
    diff = "--- a/nothing\n+++ b/.git/hooks/pre-commit\n"
    assert parse_diff_files(diff) == [".git/hooks/pre-commit", "nothing"]


def test_unicode_path():
    diff = "--- a/x.py\n+++ b/src/caf\u00e9.py\n"
    assert parse_diff_files(diff) == ["src/caf\u00e9.py", "x.py"]


def test_mixed_prefixes():
    assert parse_diff_files("+++ a/x.py\n") == ["x.py"]
    assert parse_diff_files("--- a/y.py\n+++ b/y.py\n") == ["y.py"]


def test_normalize_path_separators():
    assert normalize_path("src\\app.py") == "src/app.py"
    assert normalize_path("./src/app.py") == "src/app.py"
