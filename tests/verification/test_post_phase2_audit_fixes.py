"""Regression tests for the post-Phase-2 adversarial audit fixes.

Each test reproduces its finding against the live code (no mocks).
Findings 6 and 11 are deferred to TODO.md (pinned-test conflict and
latency-guard freeze respectively) and have no test here.
"""
import sqlite3

from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.verification_ir import Invariant
from verifyci.verification.added_refs import extract_added_refs_status
from verifyci.verification.intent_align import (
    _added_hits,
    _has_secret,
    _is_secret_carve_out,
)


def _inv(q):
    return Invariant(invariant_id="t", rule="t", compiled_query=q, blocking=True)


def _diff(*blocks):
    return "".join(blocks)


def _f(path, *lines):
    head = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,3 @@\n"
    return head + "".join(lines)


def test_template_function_call_flagged():
    # Finding 1: evil<int>(1) must not launder through _bare_callee.
    diff = _f("src/e.cpp", " int x = 0;\n", "+evil<int>(1);\n", " int y = 1;\n")
    refs, parse_ok, _ = extract_added_refs_status(diff)
    assert "evil" in refs.get("src/e.cpp", {}).get("calls", set()), refs
    hits, _ = _added_hits(diff, "calls", "evil")
    assert hits == ["src/e.cpp"], hits


def test_forbid_import_suffix_on_added_lines():
    # Finding 2: +import pkg.config must hit forbid_import:config.
    diff = _f("src/a.py", " x = 1\n", "+import pkg.config\n", " y = 2\n")
    hits, _ = _added_hits(diff, "imports", "config")
    assert hits == ["src/a.py"], hits


def test_raw_string_secret_not_carved():
    # Finding 3: raw-prefix line carrying a real secret still flags.
    assert not _is_secret_carve_out('r"password = "s3cr3t-value-long""')
    assert _has_secret('r"password = "s3cr3t-value-long""', fname="src/a.py")
    # Genuine regex literals stay carved.
    assert _is_secret_carve_out('x = re.compile(r"^\\d+$")')
    # V-01 high-signal shapes still win over any prefix.
    assert not _is_secret_carve_out('r"AKIAIOSFODNN7EXAMPLE"')


def test_ts_and_cpp_deletion_detected():
    # Finding 4: non-Python deleted entities enter Class-1/2, not silent PASS.
    from verifyci.verification.deletion import _def_line_matches, _looks_like_def
    assert _looks_like_def("function calculateTotal(items) {")
    assert _looks_like_def("export class Foo {")
    assert _looks_like_def("const computeSum = async (items) => {")
    assert _looks_like_def("int calculate_total(int x) {")
    assert _def_line_matches("-function calculateTotal(items: number[]): number {", "calculateTotal")
    assert _def_line_matches("-int calculate_total(int x) {", "calculate_total")
    assert not _def_line_matches('  evaluation("x");', "eval")


def test_revision_query_returns_live_only():
    # Finding 5: closed intervals must not load alongside live ones.
    import os
    import tempfile
    import time
    from verifyci.contracts.revision import Revision
    from verifyci.storage.graph_store import GraphStore
    d = tempfile.mkdtemp()
    db = os.path.join(d, "v.db")
    st = GraphStore(db)
    now = time.time()
    st.insert_revision(Revision(revision_id="r1", repository_id="repo", commit_id=None,
                               parent_revision_id=None, source_hash="h1",
                               timestamp=now, ingestion_config_hash="c"))
    st.insert_revision(Revision(revision_id="r2", repository_id="repo", commit_id=None,
                               parent_revision_id="r1", source_hash="h2",
                               timestamp=now + 1, ingestion_config_hash="c"))
    def _mk(rev, vf):
        return Entity(
            repository_id="repo", logical_entity_id="L", revision_entity_id="R",
            type=EntityType.FUNCTION, name="f", file_path="a.py",
            line_start=1, line_end=2, language="python",
            source_hash="s", revision_id=rev, valid_from=vf)
    st.insert_entity(_mk("r1", now))
    st.close_superseded_entities(["L"], "r2", now + 1)
    st.insert_entity(_mk("r2", now + 1))
    old_rows = st.get_entities_by_revision("r1")
    new_rows = st.get_entities_by_revision("r2")
    st.close()
    assert old_rows == [], [e.revision_entity_id for e in old_rows]
    assert len(new_rows) == 1


def test_split_conn_string_without_keyword_flags():
    # Finding 7: keywordless opener + split secret across lines.
    diff = _diff(
        _f("src/db.py", " import os\n",
           "+conn = (\n", '+    "postgres://admin:"\n', '+    "s3cr3t-p@ss@db:5432/app"\n', "+)\n")
    )
    from verifyci.verification.intent_align import evaluate_invariants
    results, _ = evaluate_invariants(diff, [_inv("secrets_scan")])
    assert not results[0].passed, results[0].explanation


def test_format_patch_separator_not_stray():
    # Finding 8: isolated --- line must not poison removal provenance.
    from verifyci.verification.diffmap import parse_unified_diff
    files = parse_unified_diff("From abc123 Mon Sep 17 00:00:00 2001\n---\nSubject: x\n")
    stray = [ln for f in files for ln in f.stray_removed]
    assert stray == [], stray


def test_cpp_test_files_classified():
    # Finding 9: C/C++ test filenames are TEST_SUITE.
    from verifyci.verification.partition import classify_path, FilePartition
    for p in ("test_foo.cpp", "foo_test.cpp", "foo_test.cc", "test_foo.c", "foo.test.cpp"):
        assert classify_path(p) == FilePartition.TEST_SUITE, p


def test_querylog_wired_when_env_set(tmp_path, monkeypatch):
    # Finding 10: VERIFYCI_QUERYLOG receives one JSONL entry per run_query miss.
    import json
    log = str(tmp_path / "q.jsonl")
    monkeypatch.setenv("VERIFYCI_QUERYLOG", log)
    from verifyci.interface.commands.query import run_query
    out = run_query("nothing", db_path=str(tmp_path / "missing.db"))
    assert out.get("error") == "db_not_found"
    lines = open(log, encoding="utf-8").read().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["status"] == "db_not_found" and entry["results_count"] == 0
    # Unset env: no file, no crash.
    monkeypatch.delenv("VERIFYCI_QUERYLOG")
    run_query("nothing", db_path=str(tmp_path / "missing.db"))
    assert len(open(log, encoding="utf-8").read().strip().splitlines()) == 1


def test_unused_import_sqlite_ok():
    assert sqlite3.sqlite_version_info >= (3, 8)
