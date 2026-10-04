"""Deletion unit tests: guard/waiver/signature pure functions.

Hunk-level class behavior is pinned in test_deletion_verification.py;
these tests cover the decision helpers branch-by-branch: guard
detection, guard preservation, waiver matching (deny-by-default),
signature parsing/compatibility, surviving-caller guards, and witness
scoping.
"""

import hashlib
import hmac

from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.verification_ir import ExecutionWitness, SignedIntentWaiver
from verifyci.verification.deletion import (
    _check_signature_compatibility,
    _find_surviving_callers,
    _has_associated_witness,
    _is_guard_line,
    _is_guard_preserved_in_additions,
    _matches_waiver,
    _parse_params_from_def,
    evaluate_deletions,
)


def _waiver(target, key="s3cret", valid=True, signer="rev"):
    w = SignedIntentWaiver(
        waiver_id="w1",
        target=target,
        signer=signer,
        signature="",
        reason="t",
        valid=valid,
    )
    sig = hmac.new(key.encode(), w.canonical_bytes(), hashlib.sha256).hexdigest()
    return SignedIntentWaiver(
        waiver_id="w1",
        target=target,
        signer=signer,
        signature=sig,
        reason="t",
        valid=valid,
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


# --- guard detection --------------------------------------------------------


def test_guard_lines():
    assert _is_guard_line("    assert x > 0")
    assert _is_guard_line("@require_auth")
    assert _is_guard_line("    check_permission(user)")
    assert _is_guard_line("    raise PermissionError('no')")
    assert not _is_guard_line("    return 1")
    assert not _is_guard_line("    raise ValueError('bad input')")


def test_guard_preserved_in_additions():
    assert _is_guard_preserved_in_additions(["    assert x"])
    assert _is_guard_preserved_in_additions(["    raise ValueError('b')"])
    assert not _is_guard_preserved_in_additions(["    return 1"])
    assert not _is_guard_preserved_in_additions([])


# --- waiver matching --------------------------------------------------------


def test_waiver_file_and_text_match(monkeypatch):
    monkeypatch.setenv("VERIFYCI_WAIVER_KEYS", "s3cret")
    by_file = _waiver("src/app.py")
    assert _matches_waiver(["    require_auth()"], "src/app.py", [by_file]) is by_file
    by_text = _waiver("require_auth")
    assert _matches_waiver(["    require_auth()"], "src/other.py", [by_text]) is by_text
    assert _matches_waiver(["    return 1"], "src/other.py", [by_text]) is None

    # V-11: Loose substring must NOT match (e.g. "auth" does not match "require_auth()")
    loose_text = _waiver("auth")
    assert _matches_waiver(["    require_auth()"], "src/other.py", [loose_text]) is None

    # V-11: Qualified file:symbol matching
    qual_match = _waiver("src/app.py:require_auth")
    assert _matches_waiver(["    require_auth()"], "src/app.py", [qual_match]) is qual_match
    assert _matches_waiver(["    require_auth()"], "src/other.py", [qual_match]) is None


def test_waiver_deny_by_default(monkeypatch):
    # No key configured, no opt-in: an unverifiable waiver suppresses nothing.
    monkeypatch.delenv("VERIFYCI_WAIVER_KEYS", raising=False)
    monkeypatch.delenv("VERIFYCI_WAIVER_PUBLIC_KEYS", raising=False)
    monkeypatch.delenv("VERIFYCI_WAIVER_ALLOW_UNAUTHENTICATED", raising=False)
    w = SignedIntentWaiver(
        waiver_id="w", target="src/app.py", signer="r", signature="made-up", reason=""
    )
    assert _matches_waiver(["    require_auth()"], "src/app.py", [w]) is None
    # Empty target never matches; invalid entries skipped.
    assert _matches_waiver(["    x"], "src/app.py", [_waiver("", valid=False)]) is None
    assert (
        _matches_waiver(["    x"], "src/app.py", [_waiver("src/app.py", valid=False)])
        is None
    )


def test_waiver_wrong_key_rejected(monkeypatch):
    monkeypatch.setenv("VERIFYCI_WAIVER_KEYS", "other-secret")
    assert (
        _matches_waiver(
            ["    require_auth()"], "src/app.py", [_waiver("src/app.py", key="s3cret")]
        )
        is None
    )


def test_waiver_empty_target_never_matches(monkeypatch):
    # A validly-signed but empty target must not waive everything.
    monkeypatch.setenv("VERIFYCI_WAIVER_KEYS", "s3cret")
    assert _matches_waiver(["    require_auth()"], "src/app.py", [_waiver("")]) is None


def test_no_diff_no_verdicts():
    passed, status, reason, verdicts = evaluate_deletions(
        None, ["src/app.py"], [_entity()]
    )
    assert (passed, status, verdicts) == (True, "PASS", [])


def test_nameless_entity_skipped_in_deletion_scan():
    from verifyci.verification.deletion import verify_deletion_hunks

    named = _entity(
        name="f", start=10, end=12, snippet="def f():\n    return 1\n    return 1\n"
    )
    nameless = _entity(
        name="", start=10, end=12, snippet="def f():\n    return 1\n    return 1\n"
    )
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -11,2 +11,1 @@\n"
        "-    return 1\n"
        "-    return 1\n"
        "+    return 2\n"
    )
    verdicts = verify_deletion_hunks(
        diff,
        ["src/app.py"],
        [named, nameless],
        witnesses=[_wit(target_file="src/app.py")],
    )
    assert len(verdicts) == 1
    assert verdicts[0].reasoning == "class_2_refactoring_verified:f"


def test_unresolvable_pred_skipped():
    out = _find_surviving_callers(
        _entity(), _G(preds={0: [object()]}), {"e1": 0}, [], set()
    )
    assert out == []


def test_declaration_replaced_by_non_def_breaks_continuity():
    ent = _entity(
        start=10, end=12, snippet="def f():\n    def other():\n    return 1\n"
    )
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -11,1 +11,1 @@\n"
        "-    def other():\n"
        "+    x = 1\n"
    )
    passed, status, reason, _ = evaluate_deletions(
        diff, ["src/app.py"], [ent], graph=None, node_map={}
    )
    assert not passed and status == "INCONCLUSIVE"
    assert "entity_continuity_broken" in reason


def test_refactoring_needs_witness_then_passes_with_one():
    ent = _entity(start=10, end=12, snippet="def f():\n    return 1\n    return 1\n")
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -11,2 +11,1 @@\n"
        "-    return 1\n"
        "-    return 1\n"
        "+    return 2\n"
    )
    passed, status, reason, _ = evaluate_deletions(
        diff, ["src/app.py"], [ent], graph=None, node_map={}
    )
    assert not passed and status == "INCONCLUSIVE"
    assert "missing_execution_witness" in reason
    passed, status, reason, verdicts = evaluate_deletions(
        diff,
        ["src/app.py"],
        [ent],
        graph=None,
        node_map={},
        witnesses=[_wit(target_file="src/app.py")],
    )
    assert passed and status == "PASS", reason
    assert "class_2_refactoring_verified" in verdicts[0].reasoning


# --- signature compatibility ------------------------------------------------


def test_parse_params():
    assert _parse_params_from_def("def f(a, b=1):") == [("a", False), ("b", True)]
    assert _parse_params_from_def("async def f(a):") == [("a", False)]
    assert _parse_params_from_def("def broken(:") is None
    assert _parse_params_from_def("x = 1") is None


def test_signature_compatibility():
    ok, _ = _check_signature_compatibility("def f(a, b):", "def f(a, b):")
    assert ok
    ok, _ = _check_signature_compatibility("def f(a):", "def f(a, b=1):")
    assert ok  # added optional is compatible
    ok, why = _check_signature_compatibility("def f(a):", "def f(a, b, c):")
    assert not ok and why.startswith("new_signature_requires_more_args")
    ok, why = _check_signature_compatibility("def f(a, b):", "def f(a, c):")
    assert not ok and why.startswith("param_position_mismatch")
    ok, why = _check_signature_compatibility("def f(a, b):", "def f(a):")
    assert not ok and why.startswith("required_param_removed")
    ok, _ = _check_signature_compatibility("???", "???")
    assert ok  # identically unparseable: no observable change
    ok, why = _check_signature_compatibility("def f(a):", "???")
    assert not ok and why == "unparseable_signature_change"


# --- surviving callers ------------------------------------------------------


class _G:
    def __init__(self, preds=None, raises=False, no_fn=False):
        self._preds = preds or {}
        self._raises = raises
        self._no_fn = no_fn

    def predecessors(self, idx):
        if self._no_fn:
            raise AssertionError("unreachable")
        if self._raises:
            raise RuntimeError("boom")
        return self._preds.get(idx, [])


def test_surviving_caller_guards():
    ent = _entity()
    assert _find_surviving_callers(ent, None, {"e1": 0}, [], set()) == []
    assert _find_surviving_callers(ent, _G(), None, [], set()) == []
    assert _find_surviving_callers(ent, _G(), {}, [], set()) == []
    noname = _entity()
    object.__setattr__(noname, "revision_entity_id", "")
    assert _find_surviving_callers(noname, _G(), {"e1": 0}, [], set()) == []
    assert _find_surviving_callers(ent, _G(), {"other": 0}, [], set()) == []
    assert _find_surviving_callers(ent, object(), {"e1": 0}, [], set()) == []
    assert _find_surviving_callers(ent, _G(raises=True), {"e1": 0}, [], set()) == []


def test_surviving_caller_scoping():
    caller_in_diff = _entity(name="c1")
    object.__setattr__(caller_in_diff, "revision_entity_id", "e2")
    object.__setattr__(caller_in_diff, "file_path", "src/app.py")
    survivor = _entity(name="c2")
    object.__setattr__(survivor, "revision_entity_id", "e3")
    object.__setattr__(survivor, "file_path", "src/keep.py")
    g = _G(preds={0: [2, 3]})
    node_map = {"e1": 0, "e2": 2, "e3": 3}
    out = _find_surviving_callers(
        _entity(), g, node_map, [caller_in_diff, survivor], {"src/app.py"}
    )
    assert len(out) == 1 and "src/keep.py" in out[0]
    # Unknown index with no entity falls back to the raw index string.
    out = _find_surviving_callers(_entity(), _G(preds={0: [9]}), {"e1": 0}, [], set())
    assert out == ["9"]


# --- witness scoping --------------------------------------------------------


def _wit(eid=None, target_file=None, general=False):
    return ExecutionWitness(
        witness_id="w",
        test_file="tests/test_app.py",
        test_function="test_f",
        target_entity_id=eid,
        target_file=target_file,
        is_general_regression=general,
        association_method="direct_ast",
    )


def test_witness_scoping():
    ent = _entity()
    assert _has_associated_witness("src/app.py", ent, [_wit(eid="e1")])
    # Entity-targeted witness does NOT fall back to file match.
    assert not _has_associated_witness("src/app.py", ent, [_wit(eid="other")])
    # General regression witnesses never corroborate.
    assert not _has_associated_witness(
        "src/app.py", ent, [_wit(target_file="src/app.py", general=True)]
    )
    assert _has_associated_witness("src/app.py", ent, [_wit(target_file="src/app.py")])
    assert not _has_associated_witness("src/app.py", ent, [])


# --- waived class-3 end to end ----------------------------------------------


def test_waived_guard_removal_passes(monkeypatch):
    monkeypatch.setenv("VERIFYCI_WAIVER_KEYS", "s3cret")
    ent = _entity(
        start=10, end=12, snippet="def f():\n    require_auth()\n    return 1\n"
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
    waivers = [_waiver("require_auth")]
    passed, status, reason, verdicts = evaluate_deletions(
        diff,
        ["src/app.py"],
        [ent],
        graph=None,
        node_map={},
        witnesses=(),
        waivers=waivers,
    )
    assert passed and status == "PASS", reason
    assert "keyed" in verdicts[0].reasoning


def test_unwaived_guard_removal_fails():
    ent = _entity(
        start=10, end=12, snippet="def f():\n    require_auth()\n    return 1\n"
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
        diff, ["src/app.py"], [ent], graph=None, node_map={}
    )
    assert not passed and status == "FAIL"
    assert "class_3_guard_removal_without_waiver" in reason
