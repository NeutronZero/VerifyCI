"""A4: the canonical parse_unified_diff and its projections.

Before this file there were six independent diff state machines
(parse_diff_files, iter_added_lines, iter_added_lines_with_lineno,
unattributed_removed_lines, find_deletion_hunks, iter_hunks), each
terminating hunks by prefix-sniffing instead of the declared
`@@ -a,b +c,d @@` counts. Demonstrated defects, all reproduced against
the pre-fix tree via a golden snapshot of 97 corpus+test diffs:

- classic (non-git) two-file diff: the second file's `---`/`+++`
  headers were swallowed as hunk body; file 2 DISAPPEARED
  (files=['one.py'] only) and `++ two.py` leaked into added lines;
- binary-only change: files=[] — vanished from verification entirely;
- mode-only change: files=[] — same;
- mixed text+binary: only the text half was visible; a PASS on it
  certified the diff while the binary half was never considered.

Every parser below is a projection of parse_unified_diff; this file
pins the matrix the audit enumerated.
"""
from verifyci.verification.diffmap import (
    GroundingStatus,
    diff_grounding_statuses,
    find_deletion_hunks,
    iter_added_lines,
    iter_added_lines_with_lineno,
    iter_hunks,
    parse_diff_files,
    parse_unified_diff,
    uninspectable_files,
)


def _git(path, hunk):
    return (f"diff --git a/{path} b/{path}\n"
            f"--- a/{path}\n+++ b/{path}\n{hunk}")


# ---------------------------------------------------------------- matrix ---

def test_single_file_modification():
    d = _git("x.py", "@@ -1,1 +1,1 @@\n-old\n+new\n")
    fs = parse_unified_diff(d)
    assert [f.path for f in fs] == ["x.py"]
    assert fs[0].grounding_status is GroundingStatus.TEXT
    assert iter_hunks(d)[0].lines == ["-old", "+new"]
    assert parse_diff_files(d) == ["x.py"]


def test_multi_file_modification_git():
    d = _git("a.py", "@@ -1,1 +1,1 @@\n-1\n+A\n") + _git("b.py", "@@ -1,1 +1,1 @@\n-2\n+B\n")
    assert parse_diff_files(d) == ["a.py", "b.py"]
    assert [f.path for f in parse_unified_diff(d)] == ["a.py", "b.py"]
    assert iter_added_lines(d) == [("a.py", "A"), ("b.py", "B")]


def test_multi_file_classic_unified_no_git_headers():
    # The headline A4 defect: no `diff --git` line to split blocks on.
    d = ("--- one.py\n+++ one.py\n@@ -1,1 +1,1 @@\n-x1\n+y1\n"
         "--- two.py\n+++ two.py\n@@ -1,1 +1,1 @@\n-x2\n+y2\n")
    assert parse_diff_files(d) == ["one.py", "two.py"]
    assert iter_added_lines(d) == [("one.py", "y1"), ("two.py", "y2")]
    # `++ two.py` must never masquerade as an added line: headers end
    # hunk bodies via the declared counts, so the leak is structurally
    # impossible now.
    assert all("two.py" not in c for _, c in iter_added_lines(d))


def test_insertion_only_zero_count_hunk():
    d = _git("x.py", "@@ -1,0 +1,1 @@\n+new\n")
    h = iter_hunks(d)[0]
    assert (h.old_start, h.old_count, h.new_start, h.new_count) == (1, 0, 1, 1)
    assert h.lines == ["+new"]
    # 0-count declared => zero old-side consumption: nothing else enters.
    assert iter_added_lines(d) == [("x.py", "new")]


def test_deletion_only_file():
    d = ("diff --git a/g.py b/g.py\ndeleted file mode 100644\n"
         "--- a/g.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-a\n-b\n")
    fs = parse_unified_diff(d)
    assert fs[0].path == "g.py" and fs[0].old_path == "g.py"
    assert fs[0].grounding_status is GroundingStatus.TEXT
    dels = find_deletion_hunks(d)
    assert len(dels) == 1 and "a\nb" in dels[0][1]


def test_binary_only_is_visible_not_vanished():
    d = ("diff --git a/logo.png b/logo.png\nindex 8725693..e4cd01f 100644\n"
         "Binary files a/logo.png and b/logo.png differ\n")
    assert parse_diff_files(d) == ["logo.png"]
    assert diff_grounding_statuses(d)["logo.png"] is GroundingStatus.BINARY
    assert uninspectable_files(d) == ["logo.png"]


def test_mode_only_is_visible_not_vanished():
    d = "diff --git a/script.sh b/script.sh\nold mode 100644\nnew mode 100755\n"
    assert parse_diff_files(d) == ["script.sh"]
    assert diff_grounding_statuses(d)["script.sh"] is GroundingStatus.MODE_ONLY
    assert uninspectable_files(d) == ["script.sh"]


def test_mixed_text_and_binary_both_visible():
    d = ("diff --git a/logo.png b/logo.png\n"
         "Binary files a/logo.png and b/logo.png differ\n"
         + _git("m.py", "@@ -1,1 +1,1 @@\n-p\n+q\n"))
    files = parse_diff_files(d)
    assert "logo.png" in files and "m.py" in files
    assert uninspectable_files(d) == ["logo.png"]


def test_multiple_hunks_one_file():
    d = _git("x.py", "@@ -1,1 +1,1 @@\n-a\n+b\n"
                   "@@ -40,2 +40,2 @@\n-c\n+d\n-e\n+f\n")
    hs = iter_hunks(d)
    assert [(h.old_start, h.new_start) for h in hs] == [(1, 1), (40, 40)]


def test_added_line_numbers_track_the_new_side():
    d = _git("x.py", "@@ -5,3 +5,4 @@\n ctx\n-old\n+new1\n+new2\n ctx2\n")
    assert iter_added_lines_with_lineno(d) == [
        ("x.py", 6, "new1"), ("x.py", 7, "new2")]
    # A `+` line outside any hunk (diff preamble) carries no position:
    # (None, None, content), never a fake line number.
    with_stray = "+outside\n" + d
    assert (None, None, "outside") in iter_added_lines_with_lineno(with_stray)


def test_hunk_body_never_terminated_by_content_dashes():
    # Removed `-- x` renders as `--- x`: declared counts keep it in the
    # body; it must not read as a second file header.
    d = _git("x.sql", "@@ -1,2 +1,1 @@\n--- drop table users\n--- backup first\n")
    files = parse_diff_files(d)
    assert files == ["x.sql"]
    assert [f.path for f in parse_unified_diff(d)] == ["x.sql"]
    dels = find_deletion_hunks(d)
    assert len(dels) == 1 and "drop table users" in dels[0][1]


def test_counts_stop_the_hunk_not_the_next_prefix():
    # Declared counts of 1+1: the third body-looking line is NOT part of
    # the hunk (a real diff never emits it; a forged longer body can't
    # smuggle content past grounding).
    d = _git("x.py", "@@ -1,1 +1,1 @@\n-a\n+b\ncsneak\n")
    h = iter_hunks(d)[0]
    assert h.lines == ["-a", "+b"]


def test_no_newline_marker_never_consumes_counts():
    d = _git("x.py", "@@ -1,1 +1,1 @@\n-old\n+new\n"
                    "\\ No newline at end of file\n")
    h = iter_hunks(d)[0]
    assert h.lines == ["-old", "+new"]  # marker consumed, not counted
    assert iter_added_lines(d) == [("x.py", "new")]


# ------------------------------------------------------------ path shapes --

def test_spaces_in_paths_unquoted_and_quoted():
    d1 = ("diff --git a/my dir/my file.py b/my dir/my file.py\n"
          "--- a/my dir/my file.py\n+++ b/my dir/my file.py\n"
          "@@ -1,1 +1,1 @@\n-x\n+y\n")
    assert parse_diff_files(d1) == ["my dir/my file.py"]
    d2 = ('diff --git "a/my file.txt" "b/my file.txt"\n'
          '--- "a/my file.txt"\n+++ "b/my file.txt"\n'
          "@@ -1,1 +1,1 @@\n-x\n+y\n")
    assert parse_diff_files(d2) == ["my file.txt"]


def test_toplevel_a_dir_and_b_dir():
    # A repo that genuinely contains directories named `a/` or `b/`:
    # strip exactly one git prefix; the real path survives.
    d = ("diff --git a/a/inner.py b/a/inner.py\n"
         "--- a/a/inner.py\n+++ b/a/inner.py\n@@ -1,1 +1,1 @@\n-x\n+y\n")
    assert parse_diff_files(d) == ["a/inner.py"]
    d = ("diff --git a/b/inner.py b/b/inner.py\n"
         "--- a/b/inner.py\n+++ b/b/inner.py\n@@ -1,1 +1,1 @@\n-x\n+y\n")
    assert parse_diff_files(d) == ["b/inner.py"]


def test_mnemonic_prefixes():
    # --src-prefix=c/ --dst-prefix=w/ : unknown single-letter prefixes
    # keep the file name intact (documented existing semantics: strip
    # only a/ and b/, so c/w paths stay as written).
    d = ("diff --git c/want.py w/want.py\n--- c/want.py\n+++ w/want.py\n"
         "@@ -1,1 +1,1 @@\n-x\n+y\n")
    files = parse_diff_files(d)
    assert "w/want.py" in files and "c/want.py" in files


def test_ambiguous_suffix_grounding_stays_inconclusive_path():
    # Ambiguity is decided by find_ambiguous_files against the entity
    # set (unchanged contract); the parser's job is only to surface
    # every named path exactly once.
    from types import SimpleNamespace
    from verifyci.verification.diffmap import find_ambiguous_files
    ents = [SimpleNamespace(revision_entity_id="a", file_path="pkg_one/utils.py",
                            line_start=1, line_end=2, type="FUNCTION"),
            SimpleNamespace(revision_entity_id="b", file_path="pkg_two/utils.py",
                            line_start=1, line_end=2, type="FUNCTION")]
    d = _git("utils.py", "@@ -1,1 +1,1 @@\n-x\n+y\n")
    assert parse_diff_files(d) == ["utils.py"]
    assert "utils.py" in find_ambiguous_files(parse_diff_files(d), ents)


# ---------------------------------------------------- verdict wiring (A4) --

def test_mixed_binary_passes_only_after_text_and_binary_are_both_considered():
    """The decision-level defect: text half alone used to earn PASS while
    the binary half vanished. Now the binary file is uninspectable ->
    established=False -> policy routes INCONCLUSIVE, never PASS."""
    from verifyci.contracts.verification_ir import VerificationPolicy
    from verifyci.verification.diffmap import parse_diff_files
    from verifyci.verification.policy import PolicyEvaluator
    from verifyci.verification.semi_formal_reason import SemiFormalReasoner
    from verifyci.verification.verification_ir import build_semi_check

    d = ("diff --git a/logo.png b/logo.png\n"
         "Binary files a/logo.png and b/logo.png differ\n"
         + _git("m.py", "@@ -1,1 +1,1 @@\n-p\n+q\n"))
    files = parse_diff_files(d)
    assert files == ["logo.png", "m.py"]
    # Ground on a graph where m.py exists as a text entity: the cert
    # verifies the text half; build_semi_check must still refuse to
    # establish while logo.png is opaque.
    from types import SimpleNamespace
    ents = [SimpleNamespace(revision_entity_id="e1", name="m", file_path="m.py",
                            line_start=1, line_end=1, source_hash="h",
                            type=SimpleNamespace(value="FUNCTION"))]
    cert = SemiFormalReasoner().verify(diff=d, graph=None,
                                       entities=ents)
    check = build_semi_check(cert, files, ents, diff=d)
    assert check.established is False
    assert "opaque change" in check.explanation
    from verifyci.contracts.verification_ir import (
        BlastRadiusResult, VerificationReport,
    )
    report = VerificationReport(
        report_id="r", task_id="t", policy_id="p", checks=[check],
        blast_radius=BlastRadiusResult(
            affected_callers=[], affected_callees=[], test_coverage_gap=[],
            risk_score=0.0, dependency_impact=[], vulnerability_impact=[]),
        timestamp=0.0,
    )
    decision = PolicyEvaluator().evaluate(
        report,
        VerificationPolicy(policy_id="p", on_failure="block",
                           on_inconclusive="human_review",
                           on_human_review="block",
                           require_deterministic_checker=True))
    assert decision.status == "INCONCLUSIVE", decision.rationale


def test_pure_text_diff_still_establishes():
    from types import SimpleNamespace
    from verifyci.verification.semi_formal_reason import SemiFormalReasoner
    from verifyci.verification.verification_ir import build_semi_check
    d = _git("m.py", "@@ -1,1 +1,1 @@\n-p\n+q\n")
    ents = [SimpleNamespace(revision_entity_id="e1", name="m", file_path="m.py",
                            line_start=1, line_end=1, source_hash="h",
                            type=SimpleNamespace(value="FUNCTION"))]
    cert = SemiFormalReasoner().verify(diff=d, graph=None, entities=ents)
    check = build_semi_check(cert, ["m.py"], ents, diff=d)
    assert check.established is True
