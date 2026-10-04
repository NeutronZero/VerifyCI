"""Audit batch gate: pins for the six confirmed live-code findings.

C-1: guard preservation requires the SAME predicate (callee/exception/
  abort-code), not any-raise.
H-1: guard detection covers the deny/capability family (PermissionDenied,
  NotAuthenticated, abort/status 401+403, return 403, throw, !auth).
waiver: file-only targets never waive Class-3 (require file:symbol).
verification_ir: 1-line-above-span grace is decorator-only; uncovered
  anchors dedupe preserving order.
partition: LICENSE match is basename-exact (licensed_code/*.py is code).
diffmap H-3: stray +/- on CODE_CORE files never certifies.
"""
import hashlib
import hmac
from types import SimpleNamespace

from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.verification_ir import ExecutionWitness, SignedIntentWaiver
from verifyci.verification.deletion import (
    _is_guard_line,
    _is_guard_preserved_in_additions,
    _matches_waiver,
    evaluate_deletions,
)
from verifyci.verification.diffmap import files_with_stray_lines
from verifyci.verification.partition import FilePartition, classify_path
from verifyci.verification.verification_ir import (
    _uncovered_changed_lines,
    build_semi_check,
)


def _waiver(target, key="s3cret"):
    w = SignedIntentWaiver(
        waiver_id="w1", target=target, signer="rev",
        signature="", reason="t", valid=True,
    )
    sig = hmac.new(key.encode(), w.canonical_bytes(), hashlib.sha256).hexdigest()
    return SignedIntentWaiver(
        waiver_id="w1", target=target, signer="rev",
        signature=sig, reason="t", valid=True,
    )


def _entity(name="f", start=10, end=12, snippet=None):
    return Entity(
        repository_id="r",
        logical_entity_id=f"log_{name}",
        revision_entity_id="e1",
        type=EntityType.FUNCTION,
        name=name,
        file_path="src/app.py",
        line_start=start,
        line_end=end,
        language="python",
        source_hash="h",
        revision_id="rev1",
        metadata={
            "snippet": snippet or "def f():\n    return 1\n",
            "snippet_is_complete": True,
        },
    )


def _semi_ent(eid, path, start, end):
    return SimpleNamespace(
        revision_entity_id=eid, name=eid, file_path=path,
        line_start=start, line_end=end, source_hash="h", type="FUNCTION",
    )


class _Cert:
    certificate_verified = True
    confidence = 1.0
    evidence = []
    conclusion = SimpleNamespace(reasoning="ok")


# --- C-1: same guard predicate ---------------------------------------------

def test_guard_swap_is_not_preservation():
    # Swapping one guard for another must NOT read as preserved.
    assert _is_guard_preserved_in_additions(
        ["    raise ValueError('bad')"], ["    raise PermissionError('no')"]
    ) is False
    assert _is_guard_preserved_in_additions(
        ["    check_permission(u)"], ["    require_auth()"]
    ) is False
    assert _is_guard_preserved_in_additions(
        ["    abort(401)"], ["    abort(403)"]
    ) is False


def test_same_guard_is_preservation():
    assert _is_guard_preserved_in_additions(
        ["    raise PermissionError('denied')"], ["    raise PermissionError('no')"]
    ) is True
    assert _is_guard_preserved_in_additions(
        ["    assert y is not None"], ["    assert x > 0"]
    ) is True
    assert _is_guard_preserved_in_additions(
        ["    abort(403)"], ["    abort(403)"]
    ) is True


def test_guard_swap_fails_closed_end_to_end():
    ent = _entity(
        snippet="def f():\n    raise PermissionError('no')\n    return 1\n",
    )
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,3 +10,3 @@\n"
        " def f():\n"
        "-    raise PermissionError('no')\n"
        "+    raise ValueError('bad')\n"
        "     return 1\n"
    )
    passed, status, reason, _ = evaluate_deletions(
        diff, ["src/app.py"], [ent], graph=None, node_map={}
    )
    assert not passed and status == "FAIL"
    assert "class_3" in reason


def test_same_guard_replacement_leaves_class_3():
    ent = _entity(
        snippet="def f():\n    raise PermissionError('no')\n    return 1\n",
    )
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,3 +10,3 @@\n"
        " def f():\n"
        "-    raise PermissionError('no')\n"
        "+    raise PermissionError('denied')\n"
        "     return 1\n"
    )
    passed, status, reason, _ = evaluate_deletions(
        diff, ["src/app.py"], [ent], graph=None, node_map={}
    )
    assert "class_3" not in reason  # preserved: routed past Class-3


# --- H-1: deny/capability guard family --------------------------------------

def test_deny_capability_lines_are_guards():
    assert _is_guard_line("    raise PermissionDenied('no')")
    assert _is_guard_line("    raise NotAuthenticated('who')")
    assert _is_guard_line("    raise Unauthorized('no')")
    assert _is_guard_line("    abort(403)")
    assert _is_guard_line("    abort(401)")
    assert _is_guard_line("    res.status(403).send('no')")
    assert _is_guard_line("    return 403")
    assert _is_guard_line("    throw new ForbiddenError()")
    assert _is_guard_line("    if (!auth) return;")
    assert _is_guard_line("    if (!authenticated) throw;")
    assert _is_guard_line("    access denied")
    # Existing contract still holds: ordinary errors are not guards.
    assert not _is_guard_line("    raise ValueError('bad input')")
    assert not _is_guard_line("    return 1")


# --- waiver: file-only never waives Class-3 ---------------------------------

def test_file_only_waiver_denied_file_symbol_allowed(monkeypatch):
    monkeypatch.setenv("VERIFYCI_WAIVER_KEYS", "s3cret")
    assert (
        _matches_waiver(["    require_auth()"], "src/app.py", [_waiver("src/app.py")])
        is None
    )
    qual = _waiver("src/app.py:require_auth")
    assert (
        _matches_waiver(["    require_auth()"], "src/app.py", [qual]) is qual
    )
    assert (
        _matches_waiver(["    require_auth()"], "src/other.py", [qual]) is None
    )


def test_file_only_waiver_fails_closed_end_to_end(monkeypatch):
    monkeypatch.setenv("VERIFYCI_WAIVER_KEYS", "s3cret")
    ent = _entity(
        snippet="def f():\n    require_auth()\n    return 1\n",
    )
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,3 +10,3 @@\n"
        " def f():\n"
        "-    require_auth()\n"
        "+    return 1\n"
        "     return 1\n"
    )
    passed, status, reason, _ = evaluate_deletions(
        diff, ["src/app.py"], [ent], graph=None, node_map={},
        waivers=[_waiver("src/app.py")],
    )
    assert not passed and status == "FAIL"
    assert "class_3" in reason
    passed, status, reason, _ = evaluate_deletions(
        diff, ["src/app.py"], [ent], graph=None, node_map={},
        waivers=[_waiver("src/app.py:require_auth")],
    )
    assert passed and status == "PASS", reason


# --- verification_ir: decorator-only grace + dedupe -------------------------

def test_non_decorator_line_above_span_is_uncovered():
    diff = ("diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n"
            "@@ -3,1 +3,1 @@\n-MAX_LIMIT = 1\n+MAX_LIMIT = 2\n")
    ents = [_semi_ent("f", "c.py", 4, 6)]
    assert _uncovered_changed_lines(diff, ents) == ["c.py:3"]
    check = build_semi_check(_Cert(), ["c.py"], ents, diff=diff)
    assert check.established is False
    assert "outside every entity span" in check.explanation


def test_decorator_line_above_span_stays_covered():
    diff = ("diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n"
            "@@ -3,3 +3,3 @@\n-@login_required\n+@admin_required\n def f():\n     pass\n")
    ents = [_semi_ent("f", "c.py", 4, 6)]
    assert _uncovered_changed_lines(diff, ents) == []
    check = build_semi_check(_Cert(), ["c.py"], ents, diff=diff)
    assert check.established is True


def test_duplicate_anchors_dedupe_preserving_order():
    diff = ("diff --git a/c.py b/c.py\n--- a/c.py\n+++ b/c.py\n"
            "@@ -1,1 +1,1 @@\n-a\n+b\n")
    ents = [_semi_ent("f", "c.py", 10, 12)]
    assert _uncovered_changed_lines(diff, ents) == ["c.py:1"]


# --- partition: basename-exact LICENSE --------------------------------------

def test_licensed_code_tree_is_code_core():
    assert classify_path("licensed_code/foo.py") == FilePartition.CODE_CORE
    assert classify_path("licensed_code/bar/baz.py") == FilePartition.CODE_CORE


def test_license_basename_variants_stay_documentation():
    assert classify_path("LICENSE") == FilePartition.DOCUMENTATION
    assert classify_path("LICENSE.txt") == FilePartition.DOCUMENTATION
    assert classify_path("LICENCE") == FilePartition.DOCUMENTATION
    assert classify_path("LICENCE.md") == FilePartition.DOCUMENTATION
    assert classify_path("third_party/LICENSE") == FilePartition.DOCUMENTATION


# --- diffmap H-3: strays on CODE_CORE never certify ---------------------------

def test_stray_on_code_core_forces_unestablished():
    diff = ("diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n+++ b/src/app.py\n"
            "@@ -4,2 +4,2 @@\n def f():\n-    return 1\n+    return 2\n"
            "+sneaked = 1\n")
    assert files_with_stray_lines(diff) == ["src/app.py"]
    ents = [_semi_ent("f", "src/app.py", 4, 6)]
    check = build_semi_check(_Cert(), ["src/app.py"], ents, diff=diff)
    assert check.established is False
    assert "stray" in check.explanation


def test_pure_hunk_diff_still_establishes():
    diff = ("diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n+++ b/src/app.py\n"
            "@@ -4,2 +4,2 @@\n def f():\n-    return 1\n+    return 2\n")
    assert files_with_stray_lines(diff) == []
    ents = [_semi_ent("f", "src/app.py", 4, 6)]
    check = build_semi_check(_Cert(), ["src/app.py"], ents, diff=diff)
    assert check.established is True


def _witness_unused():
    return ExecutionWitness(
        witness_id="w",
        test_file="tests/test_app.py",
        test_function="test_f",
        target_entity_id=None,
        target_file=None,
        is_general_regression=False,
        association_method="direct_ast",
    )
