"""A3 probes: forbid_* must distinguish introduced from pre-existing.

Audit claim: the graph-side scan ran over the ENTIRE base graph, so a
forbidden call that already existed in an untouched file failed an
unrelated diff (demonstrated against the pre-fix code: legacy.py calls
eval, diff touches other.py, verdict FAIL with established=True).

Intended V1 semantics (PLAN + README + B1 labels): fail-closed,
one-sided detection on what THIS diff introduces or touches. A diff
that names no files at all keeps whole-graph semantics (the frozen
B1 v2-forbid-direct-call positive is that case and stays a positive).
"""
from verifyci.contracts.verification_ir import Invariant
from verifyci.graph.builder import GraphBuilder
from verifyci.ingestion.extractor import extract_edges, extract_entities
from verifyci.ingestion.parser import TreeSitterParser
from verifyci.verification.intent_align import evaluate_invariants


def _inv(iid, query):
    return Invariant(invariant_id=iid, rule=iid, compiled_query=query, blocking=True)


def _graph(name, source):
    parsed = TreeSitterParser().parse(name, source, "python")
    ents = extract_entities(parsed, "repo", "rev1")
    edges = extract_edges(parsed, ents, "rev1")
    return GraphBuilder().build(ents, edges)


# legacy.py carries the PRE-EXISTING violation; the base graph for every
# scenario below.
LEGACY = _graph("legacy.py",
                b"def eval(x):\n    return x\n\ndef legacy_bad():\n    return eval(1)\n")


def _diff_touching(path):
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            "@@ -1,1 +1,2 @@\n untouched_line\n+    added = 3\n")


def test_A_preexisting_violation_does_not_fail_unrelated_diff():
    checks, _ = evaluate_invariants(_diff_touching("other.py"),
                                    [_inv("f", "forbid_call:eval")],
                                    graph=LEGACY, evidence=[])
    assert checks[0].passed is True, checks[0].explanation
    assert "pre-existing" in checks[0].explanation
    # The scan really ran (edges examined) — this is an attributed pass,
    # not inability.
    assert checks[0].established is True


def test_B_forbidden_call_introduced_by_diff_fails():
    diff = ("diff --git a/new.py b/new.py\n--- a/new.py\n+++ b/new.py\n"
            "@@ -1,0 +1,2 @@\n+def use():\n+    return eval(code)\n")
    checks, _ = evaluate_invariants(diff, [_inv("f", "forbid_call:eval")],
                                    graph=LEGACY, evidence=[])
    assert checks[0].passed is False
    assert "added in new.py" in checks[0].explanation


def test_C_forbidden_call_inside_touched_file_fails():
    # Violation lives in the very file the diff modifies: graph-side hit
    # in touched scope -> rejection stands (no scoped exemption). The
    # modification is a line replacement (equal counts): it touches the
    # violating file without adding any forbidden reference itself, so
    # the FAIL can only come from the graph side inside touched scope.
    # The scoping is file-granular (does the diff name the file holding
    # the violating edge?), so a clean modification anywhere in
    # legacy.py keeps the rejection: no scoped exemption for a touched
    # file.
    diff = ("diff --git a/legacy.py b/legacy.py\n--- a/legacy.py\n+++ b/legacy.py\n"
            "@@ -1,1 +1,2 @@\n def eval(x):\n+    z = 1\n")
    checks, _ = evaluate_invariants(diff, [_inv("f", "forbid_call:eval")],
                                    graph=LEGACY, evidence=[])
    assert checks[0].passed is False, checks[0].explanation
    assert "pre-existing" not in checks[0].explanation


def test_D_unrelated_forbidden_call_does_not_contaminate_second_file():
    # A diff touching TWO files, neither containing the violation.
    diff = (_diff_touching("one.py") + _diff_touching("two.py"))
    checks, _ = evaluate_invariants(diff, [_inv("f", "forbid_call:eval")],
                                    graph=LEGACY, evidence=[])
    assert checks[0].passed is True


def test_E_no_file_attribution_keeps_whole_graph_semantics():
    # Frozen B1 semantics: a diff naming no files ('x') cannot be scoped;
    # the graph-wide violation remains the authoritative verdict (this is
    # v2-forbid-direct-call's true positive, preserved by construction).
    checks, _ = evaluate_invariants("x", [_inv("f", "forbid_call:checkout")],
                                    graph=_graph("shop.py",
                                                 b'def order():\n    return checkout("x")\n\n'
                                                 b'def checkout(c):\n    return c\n'),
                                    evidence=[])
    assert checks[0].passed is False


def test_F_forbid_import_fail_closed_semantics_preserved():
    # Import side: pre-existing outside scope passes with note; added
    # import fails; unattributed diff keeps whole-graph semantics.
    imp_graph = _graph("legacy_import.py",
                       b"import subprocess\n\ndef run():\n    return subprocess.run(['ls'])\n")
    checks, _ = evaluate_invariants(_diff_touching("other.py"),
                                    [_inv("i", "forbid_import:subprocess")],
                                    graph=imp_graph, evidence=[])
    assert checks[0].passed is True and "pre-existing" in checks[0].explanation
    checks, _ = evaluate_invariants(
        "diff --git a/pkg/mod.py b/pkg/mod.py\n--- a/pkg/mod.py\n+++ b/pkg/mod.py\n"
        "@@ -1,0 +1,1 @@\n+import subprocess\n",
        [_inv("i", "forbid_import:subprocess")], graph=imp_graph, evidence=[])
    assert checks[0].passed is False


def test_calls_unresolved_is_unreachable_on_builder_graphs():
    """CALLS_UNRESOLVED edges exist only in the builder's `pending`
    list: build() links or drops them and never inserts one into the
    graph (a wrong link invents impact). Therefore the CALLS_UNRESOLVED
    branch in _graph_search is dead for every real graph and reachable
    only through fake/resolver-emitting graphs — pinned here so the
    branch is honest about whom it serves."""
    g = _graph("u.py", b"def go():\n    return mystery(1)\n")
    from verifyci.graph.traverse import iter_edge_payloads
    types = {str(getattr(getattr(e, "type", None), "value", getattr(e, "type", None)))
             for e in iter_edge_payloads(g)}
    assert "CALLS_UNRESOLVED" not in types, types
    # The fake-graph path stays functional (kept for explicit emitters):
    from verifyci.contracts.edge import Edge, EdgeType

    class _FakeUnresolved:
        def nodes(self):
            return []

        def edge_index_map(self):
            e = Edge(id="e1", revision_id="rev1", src_entity_id="s",
                     dst_entity_id="", type=EdgeType.CALLS_UNRESOLVED,
                     metadata={"callee": "eval"})
            return {0: (0, 0, e)}

    checks, _ = evaluate_invariants("x", [_inv("f", "forbid_call:eval")],
                                    graph=_FakeUnresolved(), evidence=[])
    assert checks[0].passed is False


def test_alias_documentation_limitation_still_holds():
    # Deterministic invariant checks are not a security boundary:
    # rebinding `eval` through an alias defeats the bare-name scan. The
    # pre-existing documented limitation is preserved, not fixed here.
    diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
            "@@ -1,0 +1,2 @@\n+e = eval\n+e(x)\n")
    checks, _ = evaluate_invariants(diff, [_inv("f", "forbid_call:eval")],
                                    graph=None, evidence=[])
    # line 1 (`e = eval`) has no call syntax, line 2 (`e(x)`) names `e`:
    # neither matches bare `eval(` — the alias passes by design.
    assert checks[0].passed is True
