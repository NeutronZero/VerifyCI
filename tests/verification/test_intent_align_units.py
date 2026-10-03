"""Invariant-unit tests: secret helpers, carve-outs, allowlists, forbid
plumbing, graph-search helpers, and scoring branches.

Corpus-level detection behavior stays pinned in test_invariant_eval.py
and the labeled-ground-truth suites; these tests cover the helper
branches those suites never reach.
"""

from types import SimpleNamespace

from verifyci.contracts.verification_ir import CheckResult, Invariant
from verifyci.verification.intent_align import (
    _added_hits,
    _changed_anchors,
    _check_forbid,
    _check_invariant,
    _diff_files,
    _entity_spans,
    _file_in_set,
    _filter_allowlisted_forbid_hits,
    _filter_allowlisted_secret_hits,
    _graph_search,
    _has_secret,
    _is_secret_carve_out,
    _lexical_call_hits,
    _name_matches,
    _quoted_hit,
    _scan_secrets,
    _score_against_labels,
    _secret_pat_name,
    _violation_touched,
    evaluate_invariants,
    score_labeled,
)


def _inv(query, scope="global_strict", allowlist=(), blocking=True):
    return Invariant(
        invariant_id="t",
        rule="r",
        compiled_query=query,
        blocking=blocking,
        target_scope=scope,
        test_allowlist_patterns=allowlist,
    )


def _diff(path, *added, old_body=("x = 1",)):
    lines = [f"diff --git a/{path} b/{path}", f"--- a/{path}", f"+++ b/{path}"]
    n = len(old_body) + len(added)
    lines.append(f"@@ -1,{len(old_body)} +1,{n} @@")
    lines += [" " + b for b in old_body]
    lines += [f"+{a}" for a in added]
    return "\n".join(lines) + "\n"


# --- secret primitives ------------------------------------------------------


def test_quoted_hit_single_quotes():
    assert _quoted_hit("x = 'abcd'")
    assert not _quoted_hit("x = 'ab'")
    assert not _quoted_hit("x = 'abc")
    assert not _quoted_hit("no quotes here")


def test_secret_pat_name_fallback():
    assert _secret_pat_name("nothing secret-shaped") == "SECRET"
    assert _secret_pat_name('password = "abcdef"') == "SECRET_RE"


def test_carve_out_openers():
    assert _is_secret_carve_out("anything", opener='x = re.compile("y")')
    assert _is_secret_carve_out("anything", opener="password")
    assert _is_secret_carve_out('r"\\b\\w+"')
    assert _is_secret_carve_out('prefix r"(?i)foo" suffix')
    assert _is_secret_carve_out('path = "/etc/passwd"')
    assert not _is_secret_carve_out('password = "abcdef"')


def test_carve_out_test_suite_markers():
    content = "x = 'diff --git password hunter2hunter2'"
    assert _is_secret_carve_out(content, fname="tests/test_a.py")
    assert not _is_secret_carve_out(content, fname="src/a.py")
    assert not _is_secret_carve_out(content)


def test_has_secret_test_fixture_suppressed():
    line = '+password = "hunter2hunter2hunter2"  # diff --git fixture'
    assert not _has_secret(line, fname="tests/test_a.py")
    assert _has_secret(line, fname="src/a.py")


# --- multiline continuations ------------------------------------------------


def test_triple_quoted_secret_fails():
    d = _diff("src/a.py", 'password = """abcdef', 'ghijkl"""')
    passed, why, est, hits = _scan_secrets(d)
    assert not passed and est and hits


def test_triple_single_quotes_detected():
    # tsq opener enters continuation state; long closer hits bare path.
    d = _diff("src/a.py", "password = '''abcdef", "ghijkl'''")
    passed, why, est, hits = _scan_secrets(d)
    assert not passed and "multiline-triple" in hits[0]


def test_backslash_continuation_joined_only_fails():
    # Neither line is secret-shaped alone; only the joined literal is.
    d = _diff("src/a.py", 'password = "ab \\', 'cdef"')
    passed, why, est, hits = _scan_secrets(d)
    assert not passed and hits == ["src/a.py:3:multiline-backslash"]


def test_paren_continuation_split_call_fails():
    # Paren continuation whose closer is itself secret-shaped: recorded as
    # a single-line hit AND confirmed through the multiline-paren path
    # (the joined confirmation adds no second hit string, by design —
    # one detection, one hit).
    d = _diff("src/a.py", "url = password + (", "://user:pass1234@h")
    passed, why, est, hits = _scan_secrets(d)
    assert not passed and len(hits) == 1 and est


def test_headerless_opener_carve_out_in_continuation():
    # Opener without :/= cannot anchor a fragment claim: decline the
    # continuation even though a later line looks quoted.
    d = _diff("src/a.py", 'password"""ab', "x = 1")
    passed, why, est, hits = _scan_secrets(d)
    assert passed and not hits


# --- scoring ----------------------------------------------------------------


def test_score_labels_branches():
    ok = CheckResult(check_id="a", passed=True, score=1.0, evidence=[], explanation="")
    bad = CheckResult(
        check_id="b", passed=False, score=0.0, evidence=[], explanation=""
    )
    assert _score_against_labels([ok], [False]) == (1.0, 1.0)
    assert _score_against_labels([ok], [True]) == (0.0, 0.0)
    assert _score_against_labels([bad], [False]) == (0.0, 0.0)
    assert _score_against_labels([bad], [True]) == (1.0, 1.0)


def test_evaluate_with_labels_reports_metrics():
    invs = [_inv("secrets_scan")]
    d = _diff("src/a.py", 'password = "hunter2hunter2"')
    results, m = evaluate_invariants(d, invs, expected_violated=[True])
    assert m.detection_recall == 1.0 and m.detection_precision == 1.0
    m = score_labeled([(d, invs[0], None, [], False)])
    assert m.detection_recall == 0.0 and m.detection_precision == 0.0


# --- invariant plumbing ------------------------------------------------------


def test_empty_query_fails_closed():
    passed, why, est, hits = _check_invariant("diff", _inv("  "), None, [])
    assert not passed and est and "empty query" in why


def test_scoped_invariant_no_files_in_scope_passes():
    passed, why, est, hits = _check_invariant(
        "", _inv("secrets_scan", scope="code_core"), None, []
    )
    assert passed and "no files in scope" in why


def test_unknown_query_fails_closed():
    passed, why, est, hits = _check_invariant("x", _inv("forbid_imports:os"), None, [])
    assert not passed and "unknown query kind" in why


# --- allowlists --------------------------------------------------------------


def test_secret_allowlist_matrix():
    from verifyci.verification.diffmap import iter_added_lines_with_lineno

    d = _diff("tests/test_a.py", 'token = "AKIAIOSFODNN7EXAMPLE"')
    hits = ["tests/test_a.py:2:SECRET_RE"]
    assert [(f, n) for f, n, c in iter_added_lines_with_lineno(d)] == [
        ("tests/test_a.py", 2)
    ]  # fixture sanity: true added lineno
    kept = _filter_allowlisted_secret_hits(hits, d, ("AKIAIOSFODNN7EXAMPLE",))
    assert kept == []
    kept = _filter_allowlisted_secret_hits(hits, d, ("something-else",))
    assert kept == hits
    kept = _filter_allowlisted_secret_hits(["src/a.py:?:SECRET_RE"], d, ("a.py",))
    assert kept == ["src/a.py:?:SECRET_RE"]  # non-test files never filtered
    kept = _filter_allowlisted_secret_hits(
        ["tests/test_a.py:bogus:SECRET_RE"], d, ("x",)
    )
    assert kept == ["tests/test_a.py:bogus:SECRET_RE"]  # unparsable lineno kept


def test_forbid_allowlist_matrix():
    d = _diff("tests/test_a.py", "eval(x)")
    ev = ["tests/test_a.py:2:forbid_calls:eval"]
    files, kept = _filter_allowlisted_forbid_hits(["tests/test_a.py"], ev, d, ("eval",))
    assert (files, kept) == ([], [])
    files, kept = _filter_allowlisted_forbid_hits(
        ["tests/test_a.py", "src/a.py"],
        ev + ["src/a.py:2:forbid_calls:eval"],
        d,
        ("eval",),
    )
    assert files == ["src/a.py"] and kept == ["src/a.py:2:forbid_calls:eval"]
    # Unparsable lineno kept; unmatched test-suite hit survives.
    files, kept = _filter_allowlisted_forbid_hits(
        ["tests/test_a.py"],
        [
            "tests/test_a.py:bogus:forbid_calls:eval",
            "tests/test_a.py:2:forbid_calls:eval",
        ],
        d,
        ("other",),
    )
    assert files == ["tests/test_a.py"] and len(kept) == 2


def test_forbid_hit_allowlisted_in_tests_passes_without_graph():
    d = _diff("tests/test_a.py", "eval(user_input)")
    inv = _inv("forbid_call:eval", allowlist=("eval",))
    passed, why, est, ev = _check_invariant(d, inv, None, [])
    assert passed, why  # allowlisted away; graph has nothing to say


# --- added/lexical hits ------------------------------------------------------


def test_added_hits_empty_inputs():
    assert _added_hits("", "calls", "eval") == ([], True)
    assert _added_hits("diff", "calls", "") == ([], True)


def test_lexical_hits_skips_non_code_and_unscoped():
    d = _diff("README.md", "eval(x)")
    assert _lexical_call_hits(d, "eval") == ["README.md"]  # exempt partition, not exempt scan
    d = "+eval(1)\n" + _diff("src/a.py", "y = 2")
    assert _lexical_call_hits(d, "eval") == []  # preamble hit is unscoped
    d = _diff("src/a.py", "result = eval(user_input)")
    assert _lexical_call_hits(d, "eval") == ["src/a.py"]


def test_lexical_hits_entry_error_is_empty(monkeypatch):
    import verifyci.verification.diffmap as dm

    monkeypatch.setattr(
        dm, "iter_added_lines", lambda d: (_ for _ in ()).throw(RuntimeError("x"))
    )
    assert _lexical_call_hits("diff", "eval") == []


def test_lexical_hits_language_error_skips(monkeypatch):
    # The scan no longer language-gates; a broken detector must not
    # silently widen the hit set — only suppress itself.
    import verifyci.ingestion.language as lang

    monkeypatch.setattr(
        lang, "detect_language", lambda f: (_ for _ in ()).throw(RuntimeError("x"))
    )
    d = _diff("src/a.py", "result = eval(user_input)")
    assert _lexical_call_hits(d, "eval") == ["src/a.py"]


# --- graph search helpers ----------------------------------------------------


def test_name_matches():
    assert _name_matches("config", "config", "IMPORTS")
    assert _name_matches("pkg.config", "config", "IMPORTS")
    assert not _name_matches("myconfig", "config", "IMPORTS")
    assert not _name_matches("pkg.eval", "eval", "CALLS")
    assert not _name_matches("", "x", "CALLS")
    assert not _name_matches("x", "", "CALLS")


def test_entity_spans_degraded_inputs():
    assert _entity_spans(object()) == {}
    assert _entity_spans(SimpleNamespace(nodes=lambda: [object()])) == {}
    bad = SimpleNamespace(
        nodes=lambda: [
            SimpleNamespace(
                revision_entity_id="e", line_start="x", line_end="y", file_path="f"
            )
        ]
    )
    assert _entity_spans(bad) == {}

    class Boom:
        def nodes(self):
            raise RuntimeError("x")

    assert _entity_spans(Boom()) == {}


def test_changed_anchors_error_is_empty(monkeypatch):
    import verifyci.verification.diffmap as dm

    monkeypatch.setattr(
        dm,
        "changed_anchors_by_file",
        lambda d: (_ for _ in ()).throw(RuntimeError("x")),
    )
    assert _changed_anchors("anything") == {}


def test_violation_touched_matrix():
    assert _violation_touched([], {"a"}, {}, {})
    assert _violation_touched([("e", "f")], {"a"}, {}, {})
    spans = {"e": ("src/a.py", 10, 20)}
    assert _violation_touched([("e", "src/a.py")], {"src/a.py"}, spans, {})
    assert _violation_touched(
        [("e", "src/a.py")], {"src/a.py"}, spans, {"src/a.py": {15}}
    )
    assert not _violation_touched(
        [("e", "src/a.py")], {"src/a.py"}, spans, {"src/a.py": {99}}
    )


def test_diff_files_helpers():
    assert _diff_files("") == set()
    assert _diff_files(_diff("src/a.py", "y = 1")) == {"src/a.py"}
    import verifyci.verification.diffmap as dm

    real = dm.parse_diff_files
    dm.parse_diff_files = lambda d: (_ for _ in ()).throw(RuntimeError("x"))
    try:
        assert _diff_files("anything") == set()
    finally:
        dm.parse_diff_files = real
    assert _file_in_set("a/src/x.py", {"src/x.py"})
    assert _file_in_set("src/x.py", {"a/src/x.py"})
    assert not _file_in_set("src/y.py", {"src/x.py"})


def test_graph_search_broken_graph_is_unevaluated():
    class Boom:
        def nodes(self):
            raise RuntimeError("x")

    found, examined, files, evaluated, src = _graph_search(Boom(), "eval", "CALLS")
    assert (found, evaluated) == (True, False)
    assert _graph_search(None, "eval", "CALLS") == (False, 0, [], True, [])


def test_check_forbid_unreadable_graph_is_inability():
    class Boom:
        def nodes(self):
            raise RuntimeError("x")

    passed, why, est, ev = _check_forbid("x", Boom(), "eval", "CALLS")
    assert not passed and not est
