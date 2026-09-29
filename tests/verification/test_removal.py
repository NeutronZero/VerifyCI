"""Removal provenance: `-` lines must have existed where claimed.

A diff deleting code that was never at those lines is stale, hallucinated,
or forged → FAIL (fail closed). Verified removals of known code stay with
the deletion tripwire (INCONCLUSIVE); removals outside entity spans or
inside truncated snippets are inability (INCONCLUSIVE), never PASS and
never FAIL — absence of record is not contradiction.
"""
from types import SimpleNamespace

from src.verification.removal import removal_provenance_check


def _ent(start, end, snippet, path="src/app.py", type_=None):
    ns = SimpleNamespace(
        file_path=path, line_start=start, line_end=end,
        metadata={"snippet": snippet} if snippet is not None else {},
    )
    if type_ is not None:
        ns.type = type_
    return ns


DIFF_HEAD = ("diff --git a/src/app.py b/src/app.py\n"
             "--- a/src/app.py\n+++ b/src/app.py\n")


def test_no_removals_is_vacuous_pass():
    diff = DIFF_HEAD + "@@ -1,2 +1,3 @@\n ctx\n+added\n ctx\n"
    check = removal_provenance_check(diff, [_ent(1, 10, "ctx\nctx")])
    assert check.check_id == "removal_provenance"
    assert check.passed is True
    assert check.established is True


def test_verified_removal_passes_established():
    ent = _ent(10, 11, "def f():\n    return 1")
    diff = DIFF_HEAD + "@@ -10,2 +10,1 @@\n def f():\n-    return 1\n"
    check = removal_provenance_check(diff, [ent])
    assert check.passed is True
    assert check.established is True
    assert check.evidence == []


def test_fabricated_removal_fails_closed():
    ent = _ent(10, 12, "def f():\n    return 1\n    return 2")
    diff = DIFF_HEAD + "@@ -10,3 +10,3 @@\n def f():\n-    return 1\n-    launch_missiles()\n+    return 2\n"
    check = removal_provenance_check(diff, [ent])
    assert check.passed is False
    assert check.established is True
    assert check.evidence == ["src/app.py:12"]
    assert "src/app.py:12" in check.explanation


def test_unmodeled_removal_is_inability_not_fail():
    # Comment/header lines live outside entity spans: no record exists,
    # so the check declines (INCONCLUSIVE at policy) rather than failing
    # or passing.
    ent = _ent(10, 12, "def f():\n    return 1\n")
    diff = DIFF_HEAD + "@@ -4,2 +4,2 @@\n-# old comment\n+# new comment\n"
    check = removal_provenance_check(diff, [ent])
    assert check.passed is True
    assert check.established is False


def test_truncated_snippet_cannot_contradict():
    # Stored snippet covers fewer lines than the entity span: too partial
    # to fail on, so inability — not a fabricated finding.
    ent = _ent(10, 20, "def f():\n    a = 1\n    b = 2\n")
    diff = DIFF_HEAD + "@@ -15,1 +15,1 @@\n-    something()\n+    other()\n"
    check = removal_provenance_check(diff, [ent])
    assert check.passed is True
    assert check.established is False


def test_module_only_covering_is_unverified():
    from src.contracts.entity import EntityType
    ent = _ent(1, 1, "src/app.py", type_=EntityType.MODULE)
    diff = DIFF_HEAD + "@@ -1,1 +1,1 @@\n-x = 1\n+x = 2\n"
    check = removal_provenance_check(diff, [ent])
    assert check.passed is True
    assert check.established is False


def test_ungrounded_file_never_fabricates():
    diff = DIFF_HEAD + "@@ -10,1 +10,1 @@\n-    return 1\n+    return 2\n"
    check = removal_provenance_check(diff, [])
    assert check.passed is True
    assert check.established is False


def test_empty_and_none_diffs_pass():
    assert removal_provenance_check("", []).passed is True
    assert removal_provenance_check(None, []).passed is True


def test_policy_routes_fabricated_to_fail_and_unverified_to_inconclusive():
    import time
    import uuid
    from src.contracts.verification_ir import (
        BlastRadiusResult, CheckResult, VerificationPolicy, VerificationReport,
    )
    from src.verification.policy import PolicyEvaluator

    def _report(check):
        return VerificationReport(
            report_id=str(uuid.uuid4()), task_id="t", policy_id="default",
            checks=[check],
            blast_radius=BlastRadiusResult(
                affected_callers=[], affected_callees=[], test_coverage_gap=[],
                risk_score=0.0, dependency_impact=[], vulnerability_impact=[]),
            timestamp=time.time(),
        )

    policy = VerificationPolicy(
        policy_id="default", on_failure="block", on_inconclusive="human_review",
        on_human_review="block", require_deterministic_checker=True)
    evaluator = PolicyEvaluator()

    fail_check = CheckResult(
        check_id="removal_provenance", passed=False, score=0.0,
        evidence=["src/app.py:12"], explanation="fabricated", blocking=True,
        established=True)
    assert evaluator.evaluate(_report(fail_check), policy).status == "FAIL"

    inability_check = CheckResult(
        check_id="removal_provenance", passed=True, score=0.5,
        evidence=[], explanation="unverified", blocking=True,
        established=False)
    assert evaluator.evaluate(_report(inability_check), policy).status == "INCONCLUSIVE"


def test_run_verify_routes_fabricated_removal_to_fail(tmp_path):
    # End-to-end wiring through verify.py: a `-` line contradicting the
    # stored snippet must FAIL, not ride the tripwire to INCONCLUSIVE.
    from src.contracts.entity import Entity, EntityType
    from src.interface.commands.verify import run_verify
    from src.storage.graph_store import GraphStore
    from src.storage.revision import create_revision

    db = str(tmp_path / "v.db")
    store = GraphStore(db)
    try:
        revision = create_revision(repository_id="r", files=[("src/app.py", "h")])
        store.insert_revision(revision)
        store.insert_entity(Entity(
            repository_id="r", logical_entity_id="l", revision_entity_id="e1",
            type=EntityType.FUNCTION, name="f", file_path="src/app.py",
            line_start=10, line_end=12, language="python", source_hash="h",
            revision_id=revision.revision_id,
            metadata={"snippet": "def f():\n    return 1\n    return 2"}))
    finally:
        store.close()
    diff = DIFF_HEAD + "@@ -10,3 +10,3 @@\n def f():\n-    return 1\n-    launch_missiles()\n+    return 2\n"
    out = run_verify(diff, db_path=db)
    assert out["status"] == "FAIL"
    assert out["rationale"] == "blocking_check_failed"
