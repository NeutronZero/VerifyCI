from verifyci.contracts.entity import Entity, EntityType
from verifyci.verification.semi_formal_reason import SemiFormalReasoner
from verifyci.verification.verification_ir import build_semi_check
from verifyci.verification.witness import extract_execution_witnesses


def _mock_graph(nodes):
    class MockGraph:
        def nodes(self):
            return nodes

    return MockGraph()


def _mock_entity(
    name: str = "f",
    file_path: str = "src/app.py",
    rev_id: str = "e1",
    start: int = 10,
    end: int = 15,
):
    return Entity(
        repository_id="repo",
        logical_entity_id=f"log_{name}",
        revision_entity_id=rev_id,
        type=EntityType.FUNCTION,
        name=name,
        file_path=file_path,
        line_start=start,
        line_end=end,
        language="python",
        source_hash="hash1",
        revision_id="rev1",
        metadata={"snippet": f"def {name}():\n    return 42\n"},
    )


# ---------------------------------------------------------------------------
# 1. Mixed Code + Test Diffs
# ---------------------------------------------------------------------------


def test_mixed_code_and_test_diff_grounds_successfully():
    ent = _mock_entity(name="compute", file_path="src/app.py", rev_id="e1", start=10, end=15)
    graph = _mock_graph([ent])
    node_map = {"e1": 0}

    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,3 +10,4 @@\n"
        " def compute():\n"
        "+    x = 1\n"
        "     return 42\n"
        "diff --git a/tests/test_app.py b/tests/test_app.py\n"
        "--- a/tests/test_app.py\n"
        "+++ b/tests/test_app.py\n"
        "@@ -1,1 +1,3 @@\n"
        "+def test_compute():\n"
        "+    assert compute() == 42\n"
    )

    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(diff=diff, graph=graph, node_map=node_map, entities=[ent])

    # Test file must NOT trigger ungrounded seed failure
    sg_check = next(c for c in cert.checked_by if c == "seeds_grounded")
    assert sg_check is not None
    assert cert.conclusion.result == "pass"
    assert cert.certificate_verified is True

    # Check semi_check established
    check = build_semi_check(cert, ["src/app.py", "tests/test_app.py"], [ent], diff=diff)
    assert check.established is True
    assert check.passed is True


# ---------------------------------------------------------------------------
# 2. Test-Only Diffs
# ---------------------------------------------------------------------------


def test_test_only_diff_does_not_fail_seeds_grounded():
    diff = (
        "diff --git a/tests/test_feature.py b/tests/test_feature.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/tests/test_feature.py\n"
        "@@ -0,0 +1,3 @@\n"
        "+def test_feature():\n"
        "+    assert True\n"
    )

    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(diff=diff, graph=None, entities=[])
    assert cert.conclusion.result == "pass"
    assert cert.certificate_verified is True

    check = build_semi_check(cert, ["tests/test_feature.py"], [], diff=diff)
    assert check.established is True
    assert check.passed is True


# ---------------------------------------------------------------------------
# 3. Execution Witnesses and Ambiguity Handling
# ---------------------------------------------------------------------------


def test_execution_witness_extraction_and_association():
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,1 +10,1 @@\n"
        "-def f(): pass\n"
        "+def f(): return 1\n"
        "diff --git a/tests/test_app.py b/tests/test_app.py\n"
        "--- a/tests/test_app.py\n"
        "+++ b/tests/test_app.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+def test_f():\n"
        "+    assert f() == 1\n"
        "diff --git a/tests/test_unrelated.py b/tests/test_unrelated.py\n"
        "--- a/tests/test_unrelated.py\n"
        "+++ b/tests/test_unrelated.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+def test_unrelated():\n"
        "+    assert 1 == 1\n"
    )

    witnesses = extract_execution_witnesses(
        diff,
        code_files=["src/app.py"],
        test_files=["tests/test_app.py", "tests/test_unrelated.py"],
    )

    assert len(witnesses) >= 2
    w_linked = next(w for w in witnesses if w.test_file == "tests/test_app.py")
    assert w_linked.is_general_regression is False
    assert w_linked.target_file == "src/app.py"

    w_unrelated = next(w for w in witnesses if w.test_file == "tests/test_unrelated.py")
    assert w_unrelated.is_general_regression is True
    assert w_unrelated.target_file is None


def test_ts_js_execution_witness_extraction():
    diff = (
        "diff --git a/tests/app.test.ts b/tests/app.test.ts\n"
        "--- a/tests/app.test.ts\n"
        "+++ b/tests/app.test.ts\n"
        "@@ -1,3 +1,7 @@\n"
        "+it('should handle request correctly', () => {\n"
        "+    expect(true).toBe(true);\n"
        "+});\n"
        "+test.skip('handles fallback', async () => {});\n"
    )
    witnesses = extract_execution_witnesses(
        diff,
        code_files=["src/app.ts"],
        test_files=["tests/app.test.ts"],
    )
    assert len(witnesses) == 2
    fns = {w.test_function for w in witnesses}
    assert "should handle request correctly" in fns
    assert "handles fallback" in fns
    for w in witnesses:
        assert w.is_general_regression is False
        assert w.target_file == "src/app.ts"



# ---------------------------------------------------------------------------
# 4. Documentation-Only Fast Path
# ---------------------------------------------------------------------------


def test_documentation_only_diff_uses_fast_path():
    diff = (
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1,2 +1,3 @@\n"
        " # Project\n"
        "-Old doc\n"
        "+New doc line\n"
        "+Another doc line\n"
        "diff --git a/docs/guide.md b/docs/guide.md\n"
        "--- a/docs/guide.md\n"
        "+++ b/docs/guide.md\n"
        "@@ -1,1 +1,2 @@\n"
        "+Documentation update\n"
    )

    reasoner = SemiFormalReasoner()
    # graph is None: doc fast-path requires no CPG graph
    cert = reasoner.verify(diff=diff, graph=None, entities=None)
    assert cert.conclusion.result == "pass"
    assert "documentation" in cert.conclusion.reasoning
    assert cert.certificate_verified is True

    check = build_semi_check(cert, ["README.md", "docs/guide.md"], [], diff=diff)
    assert check.established is True
    assert check.passed is True


# ---------------------------------------------------------------------------
# 5. Configuration-Only Schema Validation
# ---------------------------------------------------------------------------


def test_configuration_only_diff_validates_schema():
    diff_valid = (
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1,2 +1,3 @@\n"
        " [project]\n"
        "-version = '0.1.0'\n"
        "+version = '0.2.0'\n"
        "+description = 'Valid TOML'\n"
    )

    reasoner = SemiFormalReasoner()
    cert_valid = reasoner.verify(diff=diff_valid, graph=None, entities=None)
    assert cert_valid.conclusion.result == "pass"
    assert cert_valid.certificate_verified is True

    diff_invalid = (
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1,1 +1,2 @@\n"
        "+[project\n"
        "+this is blatant invalid toml = = =\n"
    )
    cert_invalid = reasoner.verify(diff=diff_invalid, graph=None, entities=None)
    assert cert_invalid.conclusion.result == "fail"
    assert cert_invalid.certificate_verified is False


def test_headerless_ini_fragment_declines_not_rejects():
    # A hunk far from any [section] header carries only `key = value`
    # lines: validity indeterminate → inconclusive, never fail.
    diff = (
        "diff --git a/setup.cfg b/setup.cfg\n"
        "--- a/setup.cfg\n"
        "+++ b/setup.cfg\n"
        "@@ -50,1 +50,2 @@\n"
        " timeout = 30\n"
        "+retries = 5\n"
    )
    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(diff=diff, graph=None, entities=None)
    assert cert.conclusion.result == "inconclusive"
    assert "headerless_ini_fragment" in cert.conclusion.reasoning
    assert cert.certificate_verified is False


def test_ini_with_header_still_rejects_garbage():
    # A section header in-hunk makes the fragment a standalone document:
    # genuine syntax errors still fail.
    diff = (
        "diff --git a/setup.cfg b/setup.cfg\n"
        "--- a/setup.cfg\n"
        "+++ b/setup.cfg\n"
        "@@ -1,1 +1,3 @@\n"
        "+[tool:pytest]\n"
        "+timeout = 30\n"
        "+[tool:pytest]\n"
    )
    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(diff=diff, graph=None, entities=None)
    assert cert.conclusion.result == "fail"
    assert cert.certificate_verified is False


def test_valid_full_ini_diff_passes():
    diff = (
        "diff --git a/setup.cfg b/setup.cfg\n"
        "--- a/setup.cfg\n"
        "+++ b/setup.cfg\n"
        "@@ -1,2 +1,3 @@\n"
        " [tool:pytest]\n"
        " timeout = 30\n"
        "+retries = 5\n"
    )
    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(diff=diff, graph=None, entities=None)
    assert cert.conclusion.result == "pass"
    assert cert.certificate_verified is True


# ---------------------------------------------------------------------------
# 6. Mixed Diff with All Partitions
# ---------------------------------------------------------------------------


def test_mixed_all_partitions_diff_grounds_cleanly():
    ent = _mock_entity(name="core_fn", file_path="src/core.py", rev_id="e1", start=1, end=5)
    graph = _mock_graph([ent])
    node_map = {"e1": 0}

    diff = (
        "diff --git a/src/core.py b/src/core.py\n"
        "--- a/src/core.py\n"
        "+++ b/src/core.py\n"
        "@@ -1,2 +1,3 @@\n"
        " def core_fn():\n"
        "+    extra = 1\n"
        "     return 42\n"
        "diff --git a/tests/test_core.py b/tests/test_core.py\n"
        "--- a/tests/test_core.py\n"
        "+++ b/tests/test_core.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+def test_core():\n"
        "+    assert core_fn() == 42\n"
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1,1 +1,2 @@\n"
        "+Update documentation\n"
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1,1 +1,2 @@\n"
        "+version = '1.0.1'\n"
    )

    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(diff=diff, graph=graph, node_map=node_map, entities=[ent])
    assert cert.conclusion.result == "pass"
    assert cert.certificate_verified is True

    check = build_semi_check(
        cert,
        ["src/core.py", "tests/test_core.py", "README.md", "pyproject.toml"],
        [ent],
        diff=diff,
    )
    assert check.established is True
    assert check.passed is True


# ---------------------------------------------------------------------------
# 7. Genuinely Ungrounded CODE_CORE Remains INCONCLUSIVE
# ---------------------------------------------------------------------------


def test_genuinely_ungrounded_code_core_remains_inconclusive():
    ent = _mock_entity(name="existing_fn", file_path="src/existing.py", rev_id="e1")
    graph = _mock_graph([ent])
    node_map = {"e1": 0}

    # Diff touches src/unindexed.py which is CODE_CORE and has no entities in CPG
    diff = (
        "diff --git a/src/unindexed.py b/src/unindexed.py\n"
        "--- a/src/unindexed.py\n"
        "+++ b/src/unindexed.py\n"
        "@@ -1,1 +1,2 @@\n"
        "+def unindexed(): pass\n"
        "diff --git a/tests/test_unindexed.py b/tests/test_unindexed.py\n"
        "--- a/tests/test_unindexed.py\n"
        "+++ b/tests/test_unindexed.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+def test_unindexed(): assert True\n"
    )

    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(diff=diff, graph=graph, node_map=node_map, entities=[ent])
    assert cert.conclusion.result == "inconclusive"
    assert "seeds_grounded" in cert.conclusion.reasoning
    assert "src/unindexed.py" in cert.conclusion.reasoning
    assert cert.certificate_verified is False


# ---------------------------------------------------------------------------
# 8. Tests Cannot Override Deterministic Blocker
# ---------------------------------------------------------------------------


def test_tests_cannot_override_deterministic_blocker(tmp_path):
    from verifyci.interface.commands.verify import run_verify
    from verifyci.storage.graph_store import GraphStore
    from verifyci.storage.revision import create_revision

    db = str(tmp_path / "v.db")
    store = GraphStore(db)
    try:
        revision = create_revision(repository_id="r", files=[("src/app.py", "h")])
        store.insert_revision(revision)
        store.insert_entity(Entity(
            repository_id="r",
            logical_entity_id="l",
            revision_entity_id="e1",
            type=EntityType.FUNCTION,
            name="f",
            file_path="src/app.py",
            line_start=10,
            line_end=12,
            language="python",
            source_hash="h",
            revision_id=revision.revision_id,
            metadata={"snippet": "def f():\n    return 1\n    return 2"},
        ))
    finally:
        store.close()

    # Diff has a fabricated removal in src/app.py, but adds tests in tests/test_app.py
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,3 +10,3 @@\n"
        " def f():\n"
        "-    return 1\n"
        "-    launch_missiles()\n"  # fabricated line
        "+    return 2\n"
        "diff --git a/tests/test_app.py b/tests/test_app.py\n"
        "--- a/tests/test_app.py\n"
        "+++ b/tests/test_app.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+def test_f():\n"
        "+    assert f() == 2\n"
    )

    out = run_verify(diff, db_path=db)
    # Must FAIL due to removal_provenance, passing test CANNOT override blocker
    assert out["status"] == "FAIL"
    assert out["rationale"] == "blocking_check_failed"
