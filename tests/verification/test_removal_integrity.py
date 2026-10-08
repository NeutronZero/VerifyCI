import unicodedata
from types import SimpleNamespace

from verifyci.contracts.entity import EntitySnippetRecord
from verifyci.contracts.verification_ir import (
    BlastRadiusResult,
    CheckResult,
    VerificationPolicy,
    VerificationReport,
)
from verifyci.ingestion.extractor import _source_snippet, _source_snippet_record
from verifyci.verification.policy import PolicyEvaluator
from verifyci.verification.removal import (
    _classify_removed,
    _lines_match,
    _snippet_record,
    removal_provenance_check,
)

DIFF_HEAD = "diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n"


def _make_test_entity(
    start: int,
    end: int,
    snippet: str | None,
    path: str = "src/app.py",
    is_complete: bool | None = None,
    truncated_at_line: int | None = None,
    type_=None,
):
    meta = {}
    if snippet is not None:
        meta["snippet"] = snippet
    if is_complete is not None:
        meta["snippet_is_complete"] = is_complete
    if truncated_at_line is not None:
        meta["snippet_truncated_at_line"] = truncated_at_line

    ns = SimpleNamespace(
        file_path=path,
        line_start=start,
        line_end=end,
        metadata=meta,
    )
    if type_ is not None:
        ns.type = type_
    return ns


# ---------------------------------------------------------------------------
# 1. Truncation and Line-Boundary Storage Tests
# ---------------------------------------------------------------------------


def test_extractor_source_snippet_record_complete():
    code = b"def f():\n    x = 1\n    return x\n"
    rec = _source_snippet_record(code, 1, 3, limit=2000)
    assert rec.is_complete is True
    assert rec.truncated_at_line is None
    assert rec.lines == ("def f():", "    x = 1", "    return x")
    assert rec.char_count == len(rec.text)
    assert _source_snippet(code, 1, 3, limit=2000) == rec.text


def test_extractor_source_snippet_record_newline_boundary_truncation():
    # Construct 10 lines of 50 chars each (total 500 chars)
    raw_lines = [f"line_{i:02d} = " + "x" * 40 for i in range(10)]
    code = "\n".join(raw_lines).encode("utf-8")
    # Limit to 210 chars: fits line_00 to line_03 (~203 chars), line_04 would push over 210
    rec = _source_snippet_record(code, 1, 10, limit=210)
    assert rec.is_complete is False
    assert rec.truncated_at_line == 5  # line_04 (1-based line 5) was omitted
    assert len(rec.lines) == 4
    # Ensure every stored line is intact and not sliced mid-line
    for i, line in enumerate(rec.lines):
        assert line == raw_lines[i]
    assert rec.char_count == len(rec.text)
    # _source_snippet also returns clean newline-bounded snippet
    assert _source_snippet(code, 1, 10, limit=210) == rec.text


def test_truncated_snippet_routes_omitted_lines_to_unverified_never_fabricated():
    raw_lines = [f"    line_{i:02d}()" for i in range(10)]
    # Entity covers lines 1..10, but truncated at line 5
    kept = raw_lines[:4]
    snippet = "\n".join(kept)
    ent = _make_test_entity(
        start=1,
        end=10,
        snippet=snippet,
        is_complete=False,
        truncated_at_line=5,
    )

    # Line 2 matches -> verified
    diff_ok = DIFF_HEAD + "@@ -2,1 +2,1 @@\n-    line_01()\n+    new_line()\n"
    res_ok = removal_provenance_check(diff_ok, [ent])
    assert res_ok.passed is True
    assert res_ok.established is True
    assert "verified=1" in res_ok.explanation

    # Line 7 is at or beyond truncation point (5) -> must be unverified, NEVER fabricated
    diff_trunc = DIFF_HEAD + "@@ -7,1 +7,1 @@\n-    line_06()\n+    new_line()\n"
    res_trunc = removal_provenance_check(diff_trunc, [ent])
    assert res_trunc.passed is True
    assert res_trunc.established is False
    assert res_trunc.evidence == []
    assert "unverified=1" in res_trunc.explanation


def test_legacy_midline_truncation_detected_via_2000_char_boundary():
    # If entity has snippet of exactly 2000 chars without metadata,
    # it must not trigger fabricated on the end-span lines.
    lines = ["    x = " + "a" * 50 for _ in range(45)]
    lines.append("    return something_long_and_crucial_to_verify")
    # Simulate legacy mid-line slice
    text = "\n".join(lines)[:2000]
    assert len(text) == 2000
    ent = _make_test_entity(
        start=1,
        end=46,
        snippet=text,
        # is_complete and truncated_at_line intentionally omitted (legacy format)
    )
    rec = _snippet_record(ent)
    assert rec is not None
    assert rec.is_complete is False

    # Line 46 removed line does not match the truncated 'return som...'
    diff = DIFF_HEAD + "@@ -46,1 +46,1 @@\n-    return something_long_and_crucial_to_verify\n+    return 0\n"
    res = removal_provenance_check(diff, [ent])
    assert res.passed is True
    assert res.established is False
    assert res.evidence == []


# ---------------------------------------------------------------------------
# 2. Complete-Span Mismatch vs Match Tests
# ---------------------------------------------------------------------------


def test_true_complete_span_mismatch_fails_fabricated():
    ent = _make_test_entity(
        start=10,
        end=12,
        snippet="def f():\n    return 1\n    return 2",
        is_complete=True,
    )
    diff = DIFF_HEAD + "@@ -10,3 +10,3 @@\n def f():\n-    return 1\n-    launch_missiles()\n+    return 2\n"
    res = removal_provenance_check(diff, [ent])
    assert res.passed is False
    assert res.established is True
    assert res.evidence == ["src/app.py:12"]
    assert "removed lines contradict stored content at src/app.py:12" in res.explanation


def test_true_complete_span_exact_match_passes_verified():
    ent = _make_test_entity(
        start=10,
        end=11,
        snippet="def f():\n    return 1",
        is_complete=True,
    )
    diff = DIFF_HEAD + "@@ -10,2 +10,1 @@\n def f():\n-    return 1\n"
    res = removal_provenance_check(diff, [ent])
    assert res.passed is True
    assert res.established is True
    assert res.evidence == []
    assert res.score == 1.0


# ---------------------------------------------------------------------------
# 3. Incomplete Span & Unmodeled Code Tests
# ---------------------------------------------------------------------------


def test_incomplete_span_missing_lines_routes_unverified():
    ent = _make_test_entity(
        start=10,
        end=20,
        snippet="def f():\n    a = 1\n",
        is_complete=False,
        truncated_at_line=12,
    )
    diff = DIFF_HEAD + "@@ -15,1 +15,1 @@\n-    unknown_call()\n+    replacement()\n"
    res = removal_provenance_check(diff, [ent])
    assert res.passed is True
    assert res.established is False
    assert res.evidence == []


def test_unmodeled_missing_record_routes_unverified():
    # Outside any entity span
    ent = _make_test_entity(start=50, end=60, snippet="def g():\n    pass\n", is_complete=True)
    diff = DIFF_HEAD + "@@ -1,1 +1,1 @@\n-# top-level header\n+# new header\n"
    res = removal_provenance_check(diff, [ent])
    assert res.passed is True
    assert res.established is False


# ---------------------------------------------------------------------------
# 4. Unicode NFC Normalization Tests
# ---------------------------------------------------------------------------


def test_unicode_nfc_normalization_equivalence():
    # Decomposed form: 'e' + combining acute accent
    decomposed = "def f\u0065\u0301():\n    return 1"
    # Composed form: 'é'
    composed = "def f\u00e9():\n    return 1"
    assert decomposed != composed
    assert unicodedata.normalize("NFC", decomposed) == unicodedata.normalize("NFC", composed)

    ent = _make_test_entity(start=1, end=2, snippet=decomposed, is_complete=True)
    # Diff uses composed form
    diff = DIFF_HEAD + "@@ -1,1 +1,1 @@\n-def f\u00e9():\n+def f_new():\n"
    res = removal_provenance_check(diff, [ent])
    assert res.passed is True
    assert res.established is True
    assert res.evidence == []


# ---------------------------------------------------------------------------
# 5. Mojibake / Encoding Resilience Tests
# ---------------------------------------------------------------------------


def test_mojibake_cp1252_utf8_repair_in_diff():
    # Base snippet has authentic UTF-8 characters: → (\u2192) and — (\u2014)
    snippet = '# `ACI_EMBEDDINGS` \u2192 trigram hash \u2014 default'
    ent = _make_test_entity(start=1, end=1, snippet=snippet, is_complete=True)

    # Diff has Windows CP1252 mojibake representation of those UTF-8 bytes:
    # \u2192 -> \xe2\u2020\u2019
    # \u2014 -> \xe2\u20ac\u201d
    mojibake_line = '# `ACI_EMBEDDINGS` \xe2\u2020\u2019 trigram hash \xe2\u20ac\u201d default'
    diff = DIFF_HEAD + f"@@ -1,1 +1,1 @@\n-{mojibake_line}\n+# updated comment\n"

    res = removal_provenance_check(diff, [ent])
    assert res.passed is True
    assert res.established is True
    assert res.evidence == []
    assert res.score == 1.0


def test_mojibake_cp1252_utf8_repair_in_snippet():
    # Inverse: snippet has mojibake, diff has UTF-8
    snippet = '# doc \xe2\u20ac\u201d comment'
    ent = _make_test_entity(start=1, end=1, snippet=snippet, is_complete=True)
    diff = DIFF_HEAD + "@@ -1,1 +1,1 @@\n-# doc \u2014 comment\n+# new doc\n"

    res = removal_provenance_check(diff, [ent])
    assert res.passed is True
    assert res.established is True
    assert res.evidence == []


def test_genuine_mismatch_with_unicode_fails_fabricated():
    # If the text has unicode but is genuinely different, it must fail as fabricated
    snippet = 'def f():\n    # path \u2192 alpha\n    return 1'
    ent = _make_test_entity(start=1, end=3, snippet=snippet, is_complete=True)
    # Diff removes a line claiming 'path → beta'
    diff = DIFF_HEAD + "@@ -2,1 +2,1 @@\n-    # path \u2192 beta\n+    # path \u2192 gamma\n"

    res = removal_provenance_check(diff, [ent])
    assert res.passed is False
    assert res.established is True
    assert res.evidence == ["src/app.py:2"]


# ---------------------------------------------------------------------------
# 6. Policy Evaluator & H4 Forensic Scenarios
# ---------------------------------------------------------------------------


def test_policy_routing_unverified_vs_fabricated():
    policy = VerificationPolicy(
        policy_id="default",
        on_failure="block",
        on_inconclusive="human_review",
        on_human_review="block",
        require_deterministic_checker=True,
    )
    evaluator = PolicyEvaluator()

    # Fabricated -> FAIL
    rep_fab = VerificationReport(
        report_id="1",
        task_id="t",
        policy_id="default",
        checks=[
            CheckResult(
                check_id="removal_provenance",
                passed=False,
                score=0.0,
                evidence=["src/app.py:12"],
                explanation="fabricated",
                blocking=True,
                established=True,
            )
        ],
        blast_radius=BlastRadiusResult([], [], [], 0.0, [], []),
        timestamp=0.0,
    )
    assert evaluator.evaluate(rep_fab, policy).status == "FAIL"

    # Unverified -> INCONCLUSIVE
    rep_unv = VerificationReport(
        report_id="2",
        task_id="t",
        policy_id="default",
        checks=[
            CheckResult(
                check_id="removal_provenance",
                passed=True,
                score=0.5,
                evidence=[],
                explanation="unverified",
                blocking=True,
                established=False,
            )
        ],
        blast_radius=BlastRadiusResult([], [], [], 0.0, [], []),
        timestamp=0.0,
    )
    assert evaluator.evaluate(rep_unv, policy).status == "INCONCLUSIVE"


def test_entity_snippet_record_structure():
    rec = EntitySnippetRecord(lines=["a", "b"], is_complete=True, truncated_at_line=None, char_count=3)
    assert rec.text == "a\nb"
    assert rec.is_complete is True


def test_lines_match_direct():
    assert _lines_match("foo", "foo") is True
    assert _lines_match("foo", "bar") is False
    assert _lines_match("a \u2192 b", "a \xe2\u2020\u2019 b") is True


def test_classify_removed_direct():
    ent = _make_test_entity(start=1, end=2, snippet="line1\nline2", is_complete=True)
    assert _classify_removed("src/app.py", 1, "line1", [ent]) == "verified"
    assert _classify_removed("src/app.py", 1, "diff_line", [ent]) == "fabricated"
    assert _classify_removed(None, 1, "line1", [ent]) == "unverified"


def test_h4_real_01_added_refs_scenario_simulated():
    # Simulate REAL-01 added_refs.py line 104 truncation scenario
    # 58 lines of module context
    module_lines = [f"# module header line {i}" for i in range(1, 59)]
    # Function extract_added_refs_status is 46 lines (lines 59..104)
    fn_lines = [f"    line_{i} = {i}" for i in range(59, 104)]
    fn_lines.append("    return refs, (bool(refs) or not had_error)")
    all_lines = module_lines + fn_lines
    source_bytes = "\n".join(all_lines).encode("utf-8")

    # With a limit that stops before line 104
    limit = sum(len(line_item) + 1 for line_item in fn_lines[:-1])  # exact length of first 45 fn lines
    rec = _source_snippet_record(source_bytes, 59, 104, limit=limit)
    assert rec.is_complete is False
    assert rec.truncated_at_line == 104

    ent = _make_test_entity(
        start=59,
        end=104,
        snippet=rec.text,
        is_complete=rec.is_complete,
        truncated_at_line=rec.truncated_at_line,
        path="verifyci/verification/added_refs.py",
    )

    diff = (
        "diff --git a/verifyci/verification/added_refs.py b/verifyci/verification/added_refs.py\n"
        "--- a/verifyci/verification/added_refs.py\n"
        "+++ b/verifyci/verification/added_refs.py\n"
        "@@ -104,1 +104,1 @@\n"
        "-    return refs, (bool(refs) or not had_error)\n"
        "+    return refs, (bool(refs) or not had_error), had_error\n"
    )
    res = removal_provenance_check(diff, [ent])
    # Must NOT be fabricated
    assert res.passed is True
    assert res.established is False
    assert res.evidence == []
    assert "unverified=1" in res.explanation


def test_h4_real_04_provider_mojibake_scenario_simulated():
    # Simulate REAL-04 provider.py line 175 scenario
    line_175_base = "    `ACI_EMBEDDINGS` unset/`hash` \u2192 offline trigram hash (default:"
    ent = _make_test_entity(
        start=175,
        end=175,
        snippet=line_175_base,
        is_complete=True,
        path="verifyci/retrieval/provider.py",
    )

    # Windows CP1252 diff mojibake
    line_175_diff = "    `ACI_EMBEDDINGS` unset/`hash` \xe2\u2020\u2019 offline trigram hash (default:"
    diff = (
        "diff --git a/verifyci/retrieval/provider.py b/verifyci/retrieval/provider.py\n"
        "--- a/verifyci/retrieval/provider.py\n"
        "+++ b/verifyci/retrieval/provider.py\n"
        "@@ -175,1 +175,1 @@\n"
        f"-{line_175_diff}\n"
        "+    # replaced line\n"
    )
    res = removal_provenance_check(diff, [ent])
    assert res.passed is True
    assert res.established is True
    assert res.evidence == []
    assert "verified=1" in res.explanation
