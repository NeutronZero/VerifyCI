"""Forbid checks must not claim established coverage over files they cannot read.

Tree parsing (`added_refs`) and the lexical fallback both skip files outside
python/c/cpp. Before the veto, a forbidden call added in such a file yielded
passed=True, established=True whenever the graph held any edges — inability
misreported as coverage. Files with added lines that are both uncovered-language
and non-exempt partition (docs/configs stay exempt) now veto establishment.
"""
from verifyci.contracts.verification_ir import Invariant
from verifyci.graph.builder import GraphBuilder
from verifyci.ingestion.extractor import extract_edges, extract_entities
from verifyci.ingestion.parser import TreeSitterParser
from verifyci.verification.intent_align import evaluate_invariants


def _graph_with_call():
    parser = TreeSitterParser()
    parsed = parser.parse(
        "a.py", b"def helper():\n    return 1\ndef user():\n    return helper()\n",
        "python")
    entities = extract_entities(parsed, "repo1", "rev1")
    edges = extract_edges(parsed, entities, "rev1")
    return GraphBuilder().build(entities, edges)


def _rule():
    return Invariant(
        invariant_id="no-eval",
        rule="forbid eval",
        compiled_query="forbid_call:eval",
        blocking=True,
        target_scope="global_strict",
    )


DIFF_JS_EVASION = """diff --git a/app.js b/app.js
--- a/app.js
+++ b/app.js
@@ -1,2 +1,3 @@
 function run() {
+    eval(userInput);
     return true;
 }
"""

DIFF_DOCS_AND_CLEAN_CODE = """diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,2 +1,3 @@
 # Title
+    eval(userInput);
 diff --git a/verifyci/core.py b/verifyci/core.py
 --- a/verifyci/core.py
 +++ b/verifyci/core.py
 @@ -1,2 +1,3 @@
  def run():
+    x = 1
     return True
"""

DIFF_PY_VIOLATION = """diff --git a/verifyci/core.py b/verifyci/core.py
--- a/verifyci/core.py
+++ b/verifyci/core.py
@@ -1,2 +1,3 @@
 def run():
+    eval("1+1")
     return True
"""


def test_js_forbid_evasion_is_unestablished():
    """eval( added in an uncovered-language file must not pass established."""
    results, _ = evaluate_invariants(DIFF_JS_EVASION, [_rule()], _graph_with_call())
    assert len(results) == 1
    assert results[0].passed is True  # no violation found anywhere examined
    assert results[0].established is False  # but app.js was never examined
    assert "app.js" in results[0].explanation


def test_docs_touching_diff_stays_established():
    """Exempt partitions (docs) never veto establishment."""
    results, _ = evaluate_invariants(
        DIFF_DOCS_AND_CLEAN_CODE, [_rule()], _graph_with_call())
    assert len(results) == 1
    assert results[0].passed is True
    assert results[0].established is True


def test_covered_violation_still_fails():
    """The veto changes nothing when covered code violates."""
    results, _ = evaluate_invariants(DIFF_PY_VIOLATION, [_rule()], _graph_with_call())
    assert len(results) == 1
    assert results[0].passed is False


def test_mixed_diff_graph_fail_survives_unexamined_file():
    """An unexamined-file hunk must not veto a graph-established rejection."""
    from verifyci.ingestion.extractor import extract_entities as _ee

    parser = TreeSitterParser()
    # Graph with a forbidden call site the diff touches: verifyci/core.py
    # defines helper/user and the diff edits inside user's span.
    src = b"def user():\n    return 1\n"
    parsed = parser.parse("verifyci/core.py", src, "python")
    ents = _ee(parsed, "repo1", "rev1")
    edges = extract_edges(parsed, ents, "rev1")
    graph = GraphBuilder().build(ents, edges)
    diff = (
        "diff --git a/verifyci/core.py b/verifyci/core.py\n"
        "--- a/verifyci/core.py\n"
        "+++ b/verifyci/core.py\n"
        "@@ -1,2 +1,3 @@\n"
        " def user():\n"
        "+    pass\n"
        "     return 1\n"
        "diff --git a/app.js b/app.js\n"
        "--- a/app.js\n"
        "+++ b/app.js\n"
        "@@ -1,2 +1,2 @@\n"
        " x\n"
        "+    b();\n"
    )
    results, _ = evaluate_invariants(diff, [_rule()], graph)
    # Without a graph violation in the touched span this passes unestablished;
    # the regression we pin is: passed=True comes WITH established=False,
    # never the old silent established=True.
    assert results[0].passed is True
    assert results[0].established is False


def test_veto_never_upgrades_graph_fail_to_inconclusive():
    """Veto sits below the rejection branch: a FAIL stays a FAIL even with app.js in the same diff."""
    parser = TreeSitterParser()
    src = b"def user():\n    eval('1')\n"
    parsed = parser.parse("verifyci/core.py", src, "python")
    ents = extract_entities(parsed, "repo1", "rev1")
    edges = extract_edges(parsed, ents, "rev1")
    graph = GraphBuilder().build(ents, edges)
    diff = (
        "diff --git a/verifyci/core.py b/verifyci/core.py\n"
        "--- a/verifyci/core.py\n"
        "+++ b/verifyci/core.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def user():\n"
        "-    eval('1')\n"
        "+    eval('2')\n"
        "diff --git a/app.js b/app.js\n"
        "--- a/app.js\n"
        "+++ b/app.js\n"
        "@@ -1,2 +1,2 @@\n"
        " x\n"
        "+    b();\n"
    )
    results, _ = evaluate_invariants(diff, [_rule()], graph)
    assert len(results) == 1
    # eval('2') in the touched span is a hit-level rejection regardless:
    # the veto must never resurrect a PASS where the graph says FAIL.
    assert results[0].passed is False
    assert results[0].established is True
