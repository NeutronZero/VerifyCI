"""Diff filename parsing, including hostile inputs.

The UTF-16 case is a frozen regression fixture: a real PowerShell-redirected
`git diff` decoded as UTF-8 yields NUL-interleaved garbage. The parser must
return no seeds (→ inconclusive downstream), never throw, never hallucinate.
"""
from verifyci.verification.diffmap import normalize_path, parse_diff_files


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


def test_normalize_path_preserves_dotfiles_and_parents():
    # str.lstrip("./") used to eat these; suffix matching then grounded
    # the wrong files toward false PASSes.
    assert normalize_path(".verifyci/foo.py") == ".verifyci/foo.py"
    assert normalize_path("../etc/passwd") == "../etc/passwd"
    assert normalize_path("...hidden.py") == "...hidden.py"


def test_body_lines_are_not_file_headers():
    # A removed `-- comment` line renders as `--- comment`; an added
    # `++ i` line renders as `+++ i`. Both are hunk content, never headers.
    diff = (
        "diff --git a/src/app.lua b/src/app.lua\n"
        "--- a/src/app.lua\n"
        "+++ b/src/app.lua\n"
        "@@ -1,2 +1,2 @@\n"
        "--- comment\n"
        "+++ i\n"
    )
    assert parse_diff_files(diff) == ["src/app.lua"]


def test_find_deletion_hunks_flags_net_removal_with_junk_addition():
    # The one-blank-line evasion: deleting a function and adding a single
    # `+` line in the same hunk used to verify as PASS.
    from verifyci.verification.diffmap import find_deletion_hunks
    diff = (
        "diff --git a/x.py b/x.py\n"
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,2 +1,1 @@\n"
        "-def authenticate(u, p):\n"
        "-    return True\n"
        "+\n"
    )
    result = find_deletion_hunks(diff)
    assert len(result) == 1
    assert "authenticate" in result[0][1]


def test_find_deletion_hunks_counts_dashdash_content():
    # Removed `-- x` content renders as `--- x`; it is a removal, and the
    # old code's `not startswith("---")` guard silently dropped it.
    from verifyci.verification.diffmap import find_deletion_hunks
    diff = (
        "diff --git a/x.sql b/x.sql\n"
        "--- a/x.sql\n"
        "+++ b/x.sql\n"
        "@@ -1,2 +1,1 @@\n"
        "--- drop table users\n"
        "--- backup first\n"
    )
    result = find_deletion_hunks(diff)
    assert len(result) == 1
    assert "drop table users" in result[0][1]


def test_iter_added_lines_catches_lines_outside_hunks():
    from verifyci.verification.diffmap import iter_added_lines
    diff = (
        "From abc123 Mon Sep 17 00:00:00 2001\n"
        '+password = "preamble-secret"\n'
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        '+password = "header-secret"\n'
        "@@ -1 +1,2 @@\n"
        " x = 1\n"
        '+password = "hunk-secret"\n'
    )
    got = iter_added_lines(diff)
    # Non-+ preamble prose is not diff content and is correctly ignored.
    assert all("Mon Sep 17" not in content for _, content in got)
    assert (None, 'password = "preamble-secret"') in got
    assert ("src/app.py", 'password = "header-secret"') in got
    assert ("src/app.py", 'password = "hunk-secret"') in got


def test_find_deletion_hunks_detects_pure_deletions():
    from verifyci.verification.diffmap import find_deletion_hunks
    diff = (
        "diff --git a/x.py b/x.py\n"
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,3 +1,1 @@\n"
        " context\n"
        "-deleted_line\n"
        "-deleted_line2\n"
    )
    result = find_deletion_hunks(diff)
    assert len(result) == 1
    assert "deleted_line" in result[0][1]


def test_find_deletion_hunks_empty_for_modification_only():
    # Load-bearing: modifications are `-`/`+` pairs, not deletions.
    # A per-line check would flag every modification; per-hunk must not.
    from verifyci.verification.diffmap import find_deletion_hunks
    diff = (
        "diff --git a/x.py b/x.py\n"
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,3 +1,3 @@\n"
        " context\n"
        "-old_line\n"
        "+new_line\n"
        " context2\n"
    )
    assert find_deletion_hunks(diff) == []


def test_find_deletion_hunks_empty_for_additions_only():
    from verifyci.verification.diffmap import find_deletion_hunks
    diff = (
        "diff --git a/x.py b/x.py\n"
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,2 +1,3 @@\n"
        " context\n"
        "+added_line\n"
    )
    assert find_deletion_hunks(diff) == []


def test_find_deletion_hunks_ignores_file_headers():
    from verifyci.verification.diffmap import find_deletion_hunks
    diff = (
        "diff --git a/x.py b/x.py\n"
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,2 +1 @@\n"
        "-old\n"
        " kept\n"
    )
    result = find_deletion_hunks(diff)
    assert len(result) == 1
    assert result[0][1] == "old"


def test_find_deletion_hunks_none_for_empty():
    from verifyci.verification.diffmap import find_deletion_hunks
    assert find_deletion_hunks(None) == []
    assert find_deletion_hunks("") == []


def test_seed_entities_narrows_to_touched_lines():
    # Blast seeds must be the entities the hunk touches, not every
    # entity in the file: whole-file seeding made connected diffs
    # report risk 1.0 on hundreds of untouched entities.
    from types import SimpleNamespace
    from verifyci.verification.diffmap import seed_entities_for_diff

    def ent(eid, start, end, type_="FUNCTION"):
        return SimpleNamespace(revision_entity_id=eid, name=eid,
                               file_path="src/app.py", line_start=start,
                               line_end=end, source_hash="h", type=type_)

    entities = [ent("touched", 10, 20), ent("far", 100, 120),
                ent("mod", 1, 1, "MODULE")]
    diff = ("diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n+++ b/src/app.py\n"
            "@@ -12,3 +12,4 @@\n ctx\n-old\n+new\n+added\n ctx\n")
    mapping = seed_entities_for_diff(["src/app.py"], entities, diff)
    assert mapping == {"src/app.py": ["touched"]}


def test_seed_entities_falls_back_without_hunks():
    # Header-only diffs (mode change, whole-file delete) carry no line
    # info: whole-file mapping so they still ground.
    from types import SimpleNamespace
    from verifyci.verification.diffmap import seed_entities_for_diff

    def ent(eid):
        return SimpleNamespace(revision_entity_id=eid, name=eid,
                               file_path="src/app.py", line_start=10,
                               line_end=20, source_hash="h")

    diff = ("diff --git a/src/app.py b/src/app.py\n"
            "deleted file mode 100644\n"
            "--- a/src/app.py\n+++ /dev/null\n")
    assert seed_entities_for_diff(["src/app.py"], [ent("e1")], diff) == {
        "src/app.py": ["e1"]}


def test_seed_entities_pure_addition_anchors_enclosing_scope():
    # A pure addition names no old-side lines; the hunk anchor seeds the
    # enclosing entity instead of the whole file (or nothing).
    from types import SimpleNamespace
    from verifyci.verification.diffmap import seed_entities_for_diff

    def ent(eid, start, end):
        return SimpleNamespace(revision_entity_id=eid, name=eid,
                               file_path="src/app.py", line_start=start,
                               line_end=end, source_hash="h")

    entities = [ent("outer", 1, 50), ent("unrelated", 100, 120)]
    diff = ("diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n+++ b/src/app.py\n"
            "@@ -20,0 +21,3 @@\n+def brand_new():\n+    pass\n+\n")
    assert seed_entities_for_diff(["src/app.py"], entities, diff) == {
        "src/app.py": ["outer"]}


def test_suffix_ambiguity_flagged_not_silent():
    from types import SimpleNamespace
    from verifyci.verification.diffmap import find_ambiguous_files, map_files_to_entity_ids
    from verifyci.verification.verification_ir import build_semi_check

    def ent(eid, path):
        return SimpleNamespace(revision_entity_id=eid, name="load",
                               file_path=path, line_start=1, line_end=2,
                               source_hash="h")

    entities = [ent("a", "pkg_one/utils.py"), ent("b", "pkg_two/utils.py")]
    assert find_ambiguous_files(["utils.py"], entities) == {
        "utils.py": ["pkg_one/utils.py", "pkg_two/utils.py"]}
    # Exact-path grounding is never ambiguous.
    assert find_ambiguous_files(["pkg_one/utils.py"], entities) == {}

    class _Cert:
        certificate_verified = True
        confidence = 1.0
        evidence = []
        conclusion = type("C", (), {"reasoning": "deterministic_checks_passed"})()

    check = build_semi_check(_Cert(), ["utils.py"], entities)
    assert "suffix-ambiguous grounding" in check.explanation
    assert check.passed is True  # tripwire, not a veto

    grounded = map_files_to_entity_ids(["pkg_one/utils.py"], entities)
    assert sorted(grounded["pkg_one/utils.py"]) == ["a"]


def test_git_rename_diff_files():
    diff = (
        "diff --git a/old_path.py b/new_path.py\n"
        "similarity index 100%\n"
        "rename from old_path.py\n"
        "rename to new_path.py\n"
    )
    files = parse_diff_files(diff)
    assert "new_path.py" in files
    assert "old_path.py" in files
