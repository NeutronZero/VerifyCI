"""PHASE 0 soundness tranche regression tests."""

import pytest

from verifyci.contracts.edge import Edge, EdgeType
from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.verification_ir import (
    BlastRadiusResult, Certificate, CheckResult, Conclusion,
    ExecutionWitness, VerificationPolicy, VerificationReport,
)
from verifyci.contracts.provenance import validate_provenance_chain
from verifyci.contracts.validate import validate_entity
from verifyci.graph.builder import GraphBuilder
from verifyci.graph.traverse import TraversalInconclusiveError, iter_edge_payloads
from verifyci.verification.config import extract_base_file_content
from verifyci.verification.deletion import (
    DeletionClass, _has_associated_witness, evaluate_deletions,
)
from verifyci.verification.import_resolution import import_resolution_check
from verifyci.verification.policy import PolicyEvaluator
from verifyci.verification.semi_formal_reason import SemiFormalReasoner
from verifyci.verification.witness import extract_execution_witnesses


def _report(checks):
    return VerificationReport(
        report_id="r", task_id="t", policy_id="p", checks=checks,
        blast_radius=BlastRadiusResult(
            affected_callers=[], affected_callees=[], test_coverage_gap=[],
            risk_score=0.0, dependency_impact=[], vulnerability_impact=[]),
        timestamp=0.0,
    )


def _policy(required=True):
    return VerificationPolicy(
        policy_id="p", on_failure="block", on_inconclusive="warn",
        on_human_review="block", require_deterministic_checker=required,
    )


def _entity(name="f", path="src/app.py", start=10, end=12, rev="e1"):
    return Entity(
        repository_id="repo", logical_entity_id="a" * 64,
        revision_entity_id=rev, type=EntityType.FUNCTION, name=name,
        file_path=path, line_start=start, line_end=end, language="python",
        source_hash="h", revision_id="rev1",
        metadata={"snippet": "def f():\n    return 1\n    return 2\n",
                  "snippet_is_complete": True},
    )


def _diff(body):
    return ("diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n+++ b/src/app.py\n" + body)


def test_empty_report_is_inconclusive_even_without_required_checker():
    decision = PolicyEvaluator().evaluate(_report([]), _policy(required=False))
    assert decision.status == "INCONCLUSIVE"


def test_pass_with_unverified_certificate_is_inconclusive():
    cert = Certificate(
        certificate_id="c", premises=[], evidence=[], execution_traces=[],
        conclusion=Conclusion(result="pass", reasoning="unverified"),
        confidence=1.0, generated_by="test", checked_by=["checker"],
        verification_method="test", certificate_verified=False, timestamp=0.0,
    )
    check = CheckResult(
        check_id="c", passed=True, score=1.0, evidence=[], explanation="x",
        blocking=True, certificate=cert, established=True, deterministic=True,
    )
    assert PolicyEvaluator().evaluate(_report([check]), _policy()).status == "INCONCLUSIVE"


def test_equal_line_swap_in_entity_span_is_class2_not_skipped():
    passed, status, _, verdicts = evaluate_deletions(
        _diff("@@ -11,1 +11,1 @@\n-    return 1\n+    return 3\n"),
        ["src/app.py"], [_entity()],
    )
    assert not passed and status == "INCONCLUSIVE"
    assert verdicts and verdicts[0].deletion_class == DeletionClass.CLASS_2_REFACTORING


def test_class1_missing_graph_is_inconclusive():
    diff = _diff("@@ -10,3 +10,0 @@\n-def f():\n-    return 1\n-    return 2\n")
    passed, status, reason, verdicts = evaluate_deletions(
        diff, ["src/app.py"], [_entity()], graph=None, node_map={}
    )
    assert not passed and status == "INCONCLUSIVE"
    assert "class_1_graph_unavailable" in reason
    assert verdicts[0].deletion_class == DeletionClass.CLASS_1_DEAD_CODE


def test_diff_extracted_witness_is_unverified_and_file_scope_cannot_pass():
    diff = (
        "diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n"
        "@@ -1,1 +1,1 @@\n-def f(): pass\n+def f(): return 1\n"
        "diff --git a/tests/test_app.py b/tests/test_app.py\n--- a/tests/test_app.py\n+++ b/tests/test_app.py\n"
        "@@ -1,0 +1,2 @@\n+def test_f():\n+    assert f() == 1\n"
    )
    ent = _entity(start=1, end=1)
    witnesses = extract_execution_witnesses(
        diff, ["src/app.py"], ["tests/test_app.py"], entities=[ent]
    )
    assert witnesses and not witnesses[0].execution_verified
    assert witnesses[0].execution_receipt_id is None
    assert not _has_associated_witness("src/app.py", ent, witnesses)

    verified = ExecutionWitness(
        witness_id="w", test_file="tests/test_app.py", test_function="test_f",
        target_entity_id=ent.revision_entity_id, target_file="src/app.py",
        association_method="ci_receipt", execution_receipt_id="run-1",
        execution_verified=True,
    )
    assert _has_associated_witness("src/app.py", ent, [verified])
    file_only = ExecutionWitness(
        witness_id="w2", test_file="tests/test_app.py", test_function="test_f",
        target_file="src/app.py", association_method="ci_receipt",
        execution_receipt_id="run-2", execution_verified=True,
    )
    assert not _has_associated_witness("src/app.py", ent, [file_only])


def test_config_matching_rejects_same_basename(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    diff = ("diff --git a/other/invariants.yaml b/other/invariants.yaml\n"
            "--- a/other/invariants.yaml\n+++ b/other/invariants.yaml\n"
            "@@ -1,1 +1,1 @@\n-old: 1\n+new: 2\n")
    assert extract_base_file_content(".verifyci/invariants.yaml", diff) is None


def test_config_does_not_use_current_worktree_as_base(tmp_path, monkeypatch):
    target = tmp_path / ".verifyci" / "invariants.yaml"
    target.parent.mkdir()
    target.write_text("attacker: trusted\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    diff = ("diff --git a/.verifyci/invariants.yaml b/.verifyci/invariants.yaml\n"
            "--- a/.verifyci/invariants.yaml\n+++ b/.verifyci/invariants.yaml\n"
            "@@ -1,1 +1,1 @@\n-old: trusted\n+new: untrusted\n")
    base = extract_base_file_content(".verifyci/invariants.yaml", diff)
    assert base == "old: trusted\n"
    assert "attacker" not in base


def test_import_manifest_and_relative_non_python_gates(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\ndependencies = ['acme-lib>=1']\n", encoding="utf-8"
    )
    declared = ("diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n"
                "@@ -1,0 +1,1 @@\n+import acme_lib\n")
    assert import_resolution_check(declared, repo_root=tmp_path).passed is True
    relative = declared.replace("import acme_lib", "from .helpers import value")
    check = import_resolution_check(relative, repo_root=tmp_path)
    assert not check.passed and check.blocking and not check.established
    non_python = ("diff --git a/src/app.ts b/src/app.ts\n--- a/src/app.ts\n+++ b/src/app.ts\n"
                   "@@ -1,0 +1,1 @@\n+import value from 'x';\n")
    check = import_resolution_check(non_python, repo_root=tmp_path)
    assert not check.passed and check.blocking and not check.established


def test_traverse_propagates_edge_payload_errors():
    class BrokenGraph:
        def edge_index_map(self):
            raise RuntimeError("boom")
    with pytest.raises(TraversalInconclusiveError):
        iter_edge_payloads(BrokenGraph())


def test_provenance_uses_canonical_record_shape():
    ent = Entity(
        repository_id="repo", logical_entity_id="a" * 64, revision_entity_id="b" * 64,
        type=EntityType.FUNCTION, name="f", file_path="src/app.py",
        line_start=1, line_end=2, language="python", source_hash="h", revision_id="rev",
    )
    records = ent.provenance_chain()
    assert records and isinstance(records[0], dict)
    assert validate_provenance_chain(records) is True
    assert validate_provenance_chain(["raw-provenance"]) is False


def test_external_entities_validate_and_builder_preserves_them():
    ent = Entity(
        repository_id="repo", logical_entity_id="a" * 64, revision_entity_id="b" * 64,
        type=EntityType.FUNCTION, name="f", file_path="src/app.py",
        line_start=1, line_end=2, language="python", source_hash="h", revision_id="rev",
    )
    edge = Edge(
        id="dep", revision_id="rev", src_entity_id=ent.revision_entity_id,
        dst_entity_id="pypi:requests", type=EdgeType.DEPENDS_ON,
    )
    graph = GraphBuilder().build([ent], [edge])
    externals = [node for node in graph.nodes()
                 if (getattr(node, "metadata", {}) or {}).get("external")]
    assert len(externals) == 1
    assert validate_entity(externals[0]) == []


def test_test_only_deletion_path_is_not_a_free_pass():
    ent = Entity(
        repository_id="repo", logical_entity_id="a" * 64, revision_entity_id="b" * 64,
        type=EntityType.FUNCTION, name="f", file_path="tests/test_feature.py",
        line_start=10, line_end=12, language="python", source_hash="h", revision_id="rev1",
        metadata={"snippet": "def f():\n    return 1\n    return 2\n",
                  "snippet_is_complete": True},
    )
    diff = ("diff --git a/tests/test_feature.py b/tests/test_feature.py\n"
            "--- a/tests/test_feature.py\n+++ b/tests/test_feature.py\n"
            "@@ -10,3 +10,0 @@\n-def f():\n-    return 1\n-    return 2\n")
    cert = SemiFormalReasoner().verify(diff=diff, graph=None, node_map={}, entities=[ent])
    assert cert.conclusion.result == "inconclusive"
    assert cert.certificate_verified is False
