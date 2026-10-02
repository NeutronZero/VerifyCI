"""Semi-formal reasoner units: config-format matrix, partition branches,
and helper fallbacks.

End-to-end gate behavior stays pinned in test_ungrounded_policy.py and
the corpus suites; these tests cover the format/branch matrix those
suites never reach.
"""

from types import SimpleNamespace

from verifyci.contracts.entity import Entity, EntityType
from verifyci.verification.semi_formal_reason import (
    SemiFormalReasoner,
    _find_code_deletion_hunks,
    _validate_configuration_diff,
)


def _mock_graph(nodes):
    class MockGraph:
        def nodes(self):
            return nodes

    return MockGraph()


def _mock_entity(name="f", file_path="src/app.py", rev_id="e1", start=10, end=15):
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


def _code_diff(path="src/app.py", old_start=10):
    return (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -{old_start},3 +{old_start},4 @@\n"
        " def f():\n"
        "+    x = 1\n"
        "     return 42\n"
    )


# --- configuration formats --------------------------------------------------


def test_yaml_valid_and_invalid():
    valid = (
        "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n"
        "--- a/.github/workflows/ci.yml\n"
        "+++ b/.github/workflows/ci.yml\n"
        "@@ -1,1 +1,2 @@\n"
        " name: ci\n"
        "+runs-on: ubuntu-latest\n"
    )
    cert = SemiFormalReasoner().verify(diff=valid, graph=None, entities=None)
    assert cert.conclusion.result == "pass" and cert.certificate_verified
    invalid = valid.replace("runs-on: ubuntu-latest", "key: [unclosed")
    cert = SemiFormalReasoner().verify(diff=invalid, graph=None, entities=None)
    assert cert.conclusion.result == "fail" and not cert.certificate_verified


def test_json_fragment_valid_invalid_multi_hunk():
    def pkg(*hunks):
        head = (
            "diff --git a/package.json b/package.json\n"
            "--- a/package.json\n"
            "+++ b/package.json\n"
        )
        return head + "".join(hunks)

    valid = pkg('@@ -1,2 +1,3 @@\n {\n+  "name": "x"\n }\n')
    cert = SemiFormalReasoner().verify(diff=valid, graph=None, entities=None)
    assert cert.conclusion.result == "pass" and cert.certificate_verified
    invalid = pkg("@@ -1,1 +1,2 @@\n {\n+  {{{{\n")
    cert = SemiFormalReasoner().verify(diff=invalid, graph=None, entities=None)
    assert cert.conclusion.result == "fail" and not cert.certificate_verified
    multi = pkg("@@ -1,1 +1,2 @@\n {\n+  {{{\n", "@@ -5,1 +6,2 @@\n }\n+  }}}\n")
    cert = SemiFormalReasoner().verify(diff=multi, graph=None, entities=None)
    assert cert.conclusion.result == "inconclusive"
    assert "multi_hunk_json_configuration" in cert.conclusion.reasoning


def test_removal_only_config_diff_has_nothing_to_validate():
    diff = (
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1,2 +1,1 @@\n"
        " [project]\n"
        "-version = '0.1.0'\n"
    )
    status, _ = _validate_configuration_diff(diff, ["pyproject.toml"])
    assert status == "pass"
    cert = SemiFormalReasoner().verify(diff=diff, graph=None, entities=None)
    assert cert.conclusion.result == "pass"


def test_context_free_removal_only_config_diff_skipped():
    # A hunk with zero new-side lines carries no content to validate:
    # skipped, not rejected.
    diff = (
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -2,1 +1,0 @@\n"
        "-version = '0.1.0'\n"
    )
    status, _ = _validate_configuration_diff(diff, ["pyproject.toml"])
    assert status == "pass"


# --- partition branches ------------------------------------------------------


def test_tests_plus_invalid_config_fails():
    diff = (
        "diff --git a/tests/test_a.py b/tests/test_a.py\n"
        "--- a/tests/test_a.py\n"
        "+++ b/tests/test_a.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+def test_a():\n"
        "+    assert True\n"
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1,1 +1,2 @@\n"
        "+[project\n"
        "+broken = = =\n"
    )
    cert = SemiFormalReasoner().verify(diff=diff, graph=None, entities=None)
    assert cert.conclusion.result == "fail"


def test_tests_plus_indeterminate_config_declines():
    multi = "@@ -1,1 +1,2 @@\n {\n+  {{{\n@@ -5,1 +6,2 @@\n }\n+  }}}\n"
    diff = (
        "diff --git a/tests/test_a.py b/tests/test_a.py\n"
        "--- a/tests/test_a.py\n"
        "+++ b/tests/test_a.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+def test_a():\n"
        "+    assert True\n"
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n" + multi
    )
    cert = SemiFormalReasoner().verify(diff=diff, graph=None, entities=None)
    assert cert.conclusion.result == "inconclusive"
    assert "test_suite_policy" in cert.conclusion.reasoning


def test_ancillary_only_takes_non_code_policy():
    diff = (
        "diff --git a/benchmarks/score.py b/benchmarks/score.py\n"
        "--- a/benchmarks/score.py\n"
        "+++ b/benchmarks/score.py\n"
        "@@ -1,1 +1,2 @@\n"
        " # bench\n"
        "+x = 1\n"
    )
    cert = SemiFormalReasoner().verify(diff=diff, graph=None, entities=None)
    assert cert.conclusion.result == "pass"
    assert cert.conclusion.reasoning == "non_code_change"
    assert cert.certificate_verified


def test_docs_plus_config_takes_non_code_policy():
    diff = (
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1,1 +1,2 @@\n"
        " # doc\n"
        "+more\n"
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1,2 +1,3 @@\n"
        " [project]\n"
        "+version = '0.2.0'\n"
    )
    cert = SemiFormalReasoner().verify(diff=diff, graph=None, entities=None)
    assert cert.conclusion.result == "pass"


def test_docs_plus_indeterminate_config_declines():
    diff = (
        "diff --git a/README.md b/README.md\n"
        "--- a/README.md\n"
        "+++ b/README.md\n"
        "@@ -1,1 +1,2 @@\n"
        " # doc\n"
        "+more\n"
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -1,1 +1,2 @@\n"
        " {\n"
        "+  {{{\n"
        "@@ -5,1 +6,2 @@\n"
        " }\n"
        "+  }}}\n"
    )
    cert = SemiFormalReasoner().verify(diff=diff, graph=None, entities=None)
    assert cert.conclusion.result == "inconclusive"
    assert "non_code_policy" in cert.conclusion.reasoning


# --- code + config -----------------------------------------------------------


def _grounded():
    ent = _mock_entity()
    return _mock_graph([ent]), {"e1": 0}, [ent]


def test_code_plus_invalid_config_fails():
    graph, node_map, entities = _grounded()
    diff = _code_diff() + (
        "diff --git a/pyproject.toml b/pyproject.toml\n"
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1,1 +1,2 @@\n"
        "+[project\n"
        "+broken = = =\n"
    )
    cert = SemiFormalReasoner().verify(
        diff=diff, graph=graph, node_map=node_map, entities=entities
    )
    assert cert.conclusion.result == "fail"
    assert "configuration_schema_invalid" in cert.conclusion.reasoning


def test_code_plus_headerless_ini_declines():
    graph, node_map, entities = _grounded()
    diff = _code_diff() + (
        "diff --git a/setup.cfg b/setup.cfg\n"
        "--- a/setup.cfg\n"
        "+++ b/setup.cfg\n"
        "@@ -50,1 +50,2 @@\n"
        " timeout = 30\n"
        "+retries = 5\n"
    )
    cert = SemiFormalReasoner().verify(
        diff=diff, graph=graph, node_map=node_map, entities=entities
    )
    assert cert.conclusion.result == "inconclusive"
    assert "headerless_ini_fragment" in cert.conclusion.reasoning


def test_code_plus_multi_hunk_json_declines():
    graph, node_map, entities = _grounded()
    diff = _code_diff() + (
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -1,1 +1,2 @@\n"
        " {\n"
        "+  {{{\n"
        "@@ -5,1 +6,2 @@\n"
        " }\n"
        "+  }}}\n"
    )
    cert = SemiFormalReasoner().verify(
        diff=diff, graph=graph, node_map=node_map, entities=entities
    )
    assert cert.conclusion.result == "inconclusive"


# --- graph/seed fallbacks ----------------------------------------------------


def test_unreadable_node_map_declines_without_crash():
    class BrokenMap:
        def node_indices(self):
            raise RuntimeError("corrupt")

    ent = _mock_entity()
    graph = _mock_graph([ent])
    graph.node_indices = BrokenMap().node_indices
    cert = SemiFormalReasoner().verify(
        diff=_code_diff(), graph=graph, node_map=None, entities=[ent]
    )
    assert cert.conclusion.result == "inconclusive"


def test_graph_nodes_helpers():
    r = SemiFormalReasoner()
    assert r._graph_nodes(None) == []
    assert r._graph_nodes(object()) == []

    class Broken:
        def nodes(self):
            raise RuntimeError("x")

    assert r._graph_nodes(Broken()) == []
    assert r._graph_nodes(_mock_graph([None, _mock_entity()])) != []


def test_trace_from_seeds_guards():
    r = SemiFormalReasoner()
    assert r._trace_from_seeds(None, ["e1"], {"e1": 0}) == []
    assert r._trace_from_seeds(_mock_graph([]), ["e1"], {}) == []
    assert r._trace_from_seeds(_mock_graph([]), ["ghost"], {"other": 9}) == []


def test_collect_evidence_skips():
    r = SemiFormalReasoner()
    good = _mock_entity()
    no_file = SimpleNamespace(
        revision_entity_id="a",
        file_path="",
        source_hash="h",
        line_start=1,
        line_end=1,
        metadata={},
        name="a",
    )
    no_hash = SimpleNamespace(
        revision_entity_id="b",
        file_path="f.py",
        source_hash="",
        line_start=1,
        line_end=1,
        metadata={},
        name="b",
    )
    ev = r._collect_evidence(
        ["missing", "a", "b", "e1"], [None, no_file, no_hash, good]
    )
    assert [e.file_path for e in ev] == ["src/app.py"]


# --- check constructor branches ----------------------------------------------


def test_checks_derive_code_files_when_absent():
    r = SemiFormalReasoner()
    checks = r._run_deterministic_checks(
        files=["src/a.py"], mapping={}, paths=[], evidence=[]
    )
    seeds = next(c for c in checks if c.checker_id == "seeds_grounded")
    assert not seeds.passed and "src/a.py" in seeds.detail


def test_checks_deletion_fallback_counts_hunks():
    r = SemiFormalReasoner()
    checks = r._run_deterministic_checks(
        files=["src/a.py"],
        mapping={},
        paths=[],
        evidence=[],
        code_files=["src/a.py"],
        deletion_hunks=[(1, "x")],
    )
    deletion = next(c for c in checks if c.checker_id == "deletion_verification")
    assert not deletion.passed
    assert deletion.detail == "deletion_hunks=1"
    checks = r._run_deterministic_checks(
        files=["src/a.py"], mapping={}, paths=[], evidence=[], code_files=["src/a.py"]
    )
    deletion = next(c for c in checks if c.checker_id == "deletion_verification")
    assert deletion.passed


def test_compute_confidence_empty_is_zero():
    assert SemiFormalReasoner()._compute_confidence([]) == 0.0


def test_approximate_hunk_deletions_found():
    diff = (
        "diff --git a/src/a.py b/src/a.py\n"
        "--- a/src/a.py\n"
        "+++ b/src/a.py\n"
        "@@@ -1,1 -1,1 +1,1 @@@\n"
        "-removed_call()\n"
    )
    hunks = _find_code_deletion_hunks(diff, {"src/a.py"})
    assert hunks and hunks[0][1] == "removed_call()"
    assert _find_code_deletion_hunks(diff, {"src/other.py"}) == []
