"""Combined-review probes: second-order fixes from both post-overhaul audits.

Covers the live-correctness items (preamble/git alignment, rename
handlers, hunk-overrun attribution, changed-line coverage, per-entity
forbid scope, read-only loading) and the smaller contract fixes
(retriever fallback, provider model case, verify-chain infra channel,
scoped-latest no-fallback). Each test names the review item it pins.
"""
from verifyci.verification.diffmap import (
    changed_anchors_by_file,
    parse_diff_files,
    parse_unified_diff,
    uninspectable_files,
)


# --- B1/R2-A5: preamble + mode-only attribution ---------------------------

def test_stray_preamble_does_not_steal_mode_only_path():
    # A stray `+line` before any `diff --git`, followed by a mode-only
    # block: the mode-only file keeps its own path (reconstruction is
    # keyed by opening git line, not zipped positions), so the mixed
    # text+mode-only PASS path stays closed.
    diff = ("+stray line\n"
            "diff --git a/m.py b/m.py\n"
            "old mode 100644\n"
            "new mode 100755\n")
    assert uninspectable_files(diff) == ["m.py"]


def test_format_patch_signature_separator_is_not_a_removal():
    # Every format-patch input ends with a bare `-- ` separator: it is
    # end-of-patch, not a removed `--` line, and must not trip the
    # removal tripwire by itself.
    from verifyci.verification.diffmap import find_deletion_hunks
    diff = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n"
            "@@ -1,1 +1,1 @@\n-a\n+b\n-- \n")
    assert find_deletion_hunks(diff) == []


# --- B2/R2-A3: rename/copy handlers ---------------------------------------

def test_rename_handlers_read_before_generic_prefixes():
    # No a/b prefixes anywhere (`--no-prefix` style): rename from/to
    # are the ONLY path source, so the dead-handler bug lost them.
    diff = ("diff --git old.py new.py\n"
            "similarity index 100%\n"
            "rename from old.py\n"
            "rename to new.py\n")
    files = parse_unified_diff(diff)
    assert [(f.old_path, f.new_path) for f in files] == [("old.py", "new.py")]
    assert parse_diff_files(diff) == ["new.py", "old.py"]


def test_no_prefix_git_line_backfills_mode_only_path():
    diff = ("diff --git m.py m.py\n"
            "old mode 100644\n"
            "new mode 100755\n")
    assert uninspectable_files(diff) == ["m.py"]


def test_hunkless_rename_is_uninspectable():
    # A pure rename carries no content: a same-named base entity must
    # not ground a PASS for the move.
    diff = ("diff --git a/o.py b/n.py\n"
            "similarity index 100%\n"
            "rename from o.py\n"
            "rename to n.py\n")
    assert uninspectable_files(diff) == ["n.py"]


# --- R2-A4: hunk overrun attribution --------------------------------------

def test_overstated_counts_do_not_swallow_next_file():
    # Declared (5,5) with only 2 body lines, then the next file's
    # headers: they must open a new file block, not render as a
    # removed `-- ...` line of the first file.
    diff = ("diff --git a/one.py b/one.py\n"
            "--- a/one.py\n+++ b/one.py\n"
            "@@ -1,5 +1,5 @@\n"
            " ctx1\n ctx2\n"
            "--- a/two.py\n+++ b/two.py\n"
            "@@ -1,1 +1,1 @@\n-a\n+b\n")
    files = parse_unified_diff(diff)
    assert [f.path for f in files] == ["one.py", "two.py"]
    two = [f for f in files if f.path == "two.py"][0]
    assert len(two.hunks) == 1


def test_exact_count_sql_content_untouched():
    # Removed `-- x` + added `++ y` with EXACT counts is real content,
    # not a file pair: the lookahead must not fire here.
    diff = ("diff --git a/x.sql b/x.sql\n"
            "--- a/x.sql\n+++ b/x.sql\n"
            "@@ -1,1 +1,1 @@\n--- x\n+++ y\n")
    files = parse_unified_diff(diff)
    assert [f.path for f in files] == ["x.sql"]
    assert files[0].hunks[0].lines == ["--- x", "+++ y"]


# --- R2-A1: changed-line coverage -----------------------------------------

def _ent(eid, path, start, end, type_="FUNCTION"):
    from types import SimpleNamespace
    return SimpleNamespace(revision_entity_id=eid, name=eid, file_path=path,
                           line_start=start, line_end=end, source_hash="h",
                           type=type_)


def _check(files, entities, diff):
    from verifyci.verification.verification_ir import build_semi_check

    class _Cert:
        certificate_verified = True
        confidence = 1.0
        evidence = []
        conclusion = type("C", (), {"reasoning": "ok"})()

    return build_semi_check(_Cert(), files, entities, diff=diff)


def test_module_constant_edit_is_not_established():
    # Edit to MAX_RETRIES (line 1) while only a function (lines 4-6)
    # exists: file grounds, but the changed line is outside every
    # span -> established=False (INCONCLUSIVE, never PASS).
    diff = ("diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n"
            "@@ -1,1 +1,1 @@\n-MAX_RETRIES = 1\n+MAX_RETRIES = 2\n")
    ents = [_ent("f", "c.py", 4, 6)]
    check = _check(["c.py"], ents, diff)
    assert check.established is False
    assert "outside every entity span" in check.explanation


def test_in_function_edit_stays_established():
    diff = ("diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n"
            "@@ -4,2 +4,2 @@\n def f():\n-    return 1\n+    return 2\n")
    ents = [_ent("f", "c.py", 4, 6)]
    check = _check(["c.py"], ents, diff)
    assert check.established is True


def test_decorator_edit_counts_as_covered():
    # Spans start at `def` (extractor frozen); the `@deco` line above
    # is the definition's decorator, not stray module text.
    diff = ("diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n"
            "@@ -3,3 +3,3 @@\n-@login_required\n+@admin_required\n def f():\n     pass\n")
    ents = [_ent("f", "c.py", 4, 6)]
    check = _check(["c.py"], ents, diff)
    assert check.established is True


# --- R2-A6: lexical fallback on partial parse ------------------------------

def test_partial_recovery_hiding_forbidden_call_still_fails():
    # `compute(` survives error recovery while the unbalanced
    # `eval(user_input` line is dropped: the lexical backstop catches
    # the hidden target (bare-name rule: `obj.eval(` still would not).
    from verifyci.contracts.verification_ir import Invariant
    from verifyci.verification.intent_align import evaluate_invariants
    diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1,0 +1,2 @@\n+x = compute(1)\n+    eval(user_input\n")
    inv = Invariant(invariant_id="f", rule="f", compiled_query="forbid_call:eval",
                    blocking=True)
    checks, _ = evaluate_invariants(diff, [inv], graph=None, evidence=[])
    assert checks[0].passed is False


# --- B3/R2-A2: read-only loading -------------------------------------------

def test_load_graph_missing_returns_empty_without_creating(tmp_path):
    from verifyci.interface.commands.graph_loader import load_graph
    db = str(tmp_path / "missing.db")
    assert load_graph(db) == (None, {}, [])
    import os
    assert not os.path.exists(db)


def test_load_graph_unreadable_raises_infra_error(tmp_path):
    import pytest
    from verifyci.interface.commands import InfraError
    from verifyci.interface.commands.graph_loader import load_graph
    db = str(tmp_path / "corrupt.db")
    with open(db, "wb") as fh:
        fh.write(b"x" * 4096)
    with pytest.raises(InfraError):
        load_graph(db)


def test_read_only_open_does_not_flip_journal_mode(tmp_path):
    # A DELETE-mode DB opened read-only stays DELETE: readers never
    # run the WAL pragma.
    from verifyci.storage.graph_store import GraphStore
    db = str(tmp_path / "legacy.db")
    store = GraphStore(db)
    store.conn.execute("PRAGMA journal_mode=DELETE")
    store.close()
    ro = GraphStore(db, read_only=True)
    try:
        mode = ro.conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        ro.close()
    assert mode.lower() == "delete"


def test_scoped_latest_never_falls_back_to_foreign_repo(tmp_path):
    # Shared DB, two repos: asking for an ABSENT repo returns "", not
    # the other repo's revision.
    from verifyci.storage.graph_store import GraphStore, latest_revision_id
    from verifyci.storage.revision import create_revision
    db = str(tmp_path / "shared.db")
    store = GraphStore(db)
    try:
        rev = create_revision(repository_id="repoA", files=[("a.py", "h1")])
        store.insert_revision(rev)
        assert latest_revision_id(store.conn, "repoA") == rev.revision_id
        assert latest_revision_id(store.conn, "ghost-repo") == ""
        assert latest_revision_id(store.conn, None) == rev.revision_id
    finally:
        store.close()


# --- C5/C6: retriever fallback + provider case ------------------------------

def test_retriever_fallback_normalizes_payload_neighbors():
    # Adapter exposing only successors()/predecessors() yielding
    # PAYLOADS (rustworkx shape): ids come from the node map, not
    # str(payload).
    from types import SimpleNamespace
    from verifyci.retrieval.graph_retriever import GraphRetriever

    a = SimpleNamespace(revision_entity_id="A", name="a")
    b = SimpleNamespace(revision_entity_id="B", name="b")

    class _PayloadGraph:
        def successors(self, idx):
            return [b] if idx == 0 else []

        def predecessors(self, idx):
            return [a] if idx == 1 else []

    r = GraphRetriever(_PayloadGraph(), node_map={"A": 0, "B": 1})
    hits = r.retrieve(["A"], max_hops=1)
    assert [h.id for h in hits] == ["B"]


def test_provider_keeps_ollama_model_case(monkeypatch):
    from verifyci.retrieval.provider import (
        CachedEmbeddingProvider,
        OllamaEmbeddingProvider,
        default_dense_provider,
    )
    monkeypatch.setenv("VERIFYCI_EMBEDDINGS", "ollama:MyModel")
    _p = default_dense_provider()
    assert isinstance(_p, CachedEmbeddingProvider)
    assert isinstance(_p.base, OllamaEmbeddingProvider)
    assert _p.base.model == "MyModel"
    monkeypatch.setenv("VERIFYCI_EMBEDDINGS", "OLLAMA")
    _p2 = default_dense_provider()
    assert isinstance(_p2, CachedEmbeddingProvider)
    assert isinstance(_p2.base, OllamaEmbeddingProvider)
    assert _p2.base.model == "nomic-embed-text"


# --- shared anchor helper sanity --------------------------------------------

def test_changed_anchors_match_seed_geometry():
    diff = ("diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n"
            "@@ -4,2 +4,3 @@\n def f():\n-    a = 1\n+    a = 2\n+    b = 3\n tail\n")
    anchors = changed_anchors_by_file(diff)
    assert anchors["c.py"] == {4, 5, 6}
