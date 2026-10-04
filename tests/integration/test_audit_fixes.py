from verifyci.contracts.verification_ir import Invariant
from verifyci.contracts.event import Event, AttestationMetadata
from verifyci.verification.intent_align import evaluate_invariants
from verifyci.verification.deletion import _check_signature_compatibility, _is_guard_preserved_in_additions
from verifyci.verification.diffmap import _split_git_paths, _strip_prefix
from verifyci.ingestion.ignore import _rel_matches
from verifyci.retrieval.fusion import rrf_fusion_with_scores
from verifyci.retrieval.dense import SearchResult
from verifyci.memory.replay import ReplayEngine
from verifyci.storage.graph_store import GraphStore
from verifyci.interface.commands import resolve_repository
from verifyci.verification.semi_formal_reason import _validate_configuration_diff


def _inv(query):
    return Invariant(invariant_id="test", rule="test", compiled_query=query, blocking=True)


def test_secret_not_bypassed_by_endpoint_path():
    diff = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,0 +1,1 @@
+client = AuthClient(api_key="AKIA1234567890123456", endpoint="/v1/auth")
+"""
    checks, _ = evaluate_invariants(diff, [_inv("secrets_scan")], graph=None, evidence=[])
    assert checks[0].passed is False, "Secret must be detected even when line contains a path"


def test_signature_compatibility_catches_optional_to_required():
    old_sig = "def execute(query, timeout=10):"
    new_sig = "def execute(query, timeout):"
    compat, reason = _check_signature_compatibility(old_sig, new_sig)
    assert compat is False
    assert "new_signature_requires_more_args" in reason


def test_signature_compatibility_handles_async_and_kwonly():
    old_sig = "async def fetch(user_id):"
    new_sig = "async def fetch(user_id, *, token):"
    compat, reason = _check_signature_compatibility(old_sig, new_sig)
    assert compat is False
    assert "new_signature_requires_more_args" in reason


def test_guard_preservation_ignores_comments():
    added = ["# assert is removed", "x = 1"]
    assert _is_guard_preserved_in_additions(added) is False


def test_split_git_paths_with_spaces_and_quotes():
    line = 'diff --git "a/path with spaces/file.bin" "b/path with spaces/file.bin"'
    old, new = _split_git_paths(line)
    assert old == "path with spaces/file.bin"
    assert new == "path with spaces/file.bin"


def test_strip_prefix_windows_backslashes():
    assert _strip_prefix("a\\src\\app.py") == "src\\app.py"
    assert _strip_prefix("b\\src\\app.py") == "src\\app.py"


def test_root_anchored_ignore_patterns():
    patterns = ["/build", "/dist/"]
    assert _rel_matches("build/output.o", patterns) is True
    assert _rel_matches("build", patterns) is True
    assert _rel_matches("dist/bundle.js", patterns) is True


def test_rrf_fusion_deterministic_ties_and_safe_k():
    d1 = [SearchResult(id="doc_b", score=0.9, metadata={}), SearchResult(id="doc_a", score=0.8, metadata={})]
    s1 = [SearchResult(id="doc_a", score=0.9, metadata={}), SearchResult(id="doc_b", score=0.8, metadata={})]
    # k=0 must not divide by zero
    fused = rrf_fusion_with_scores(d1, s1, [], k=0)
    assert len(fused) == 2
    assert {fused[0][0], fused[1][0]} == {"doc_a", "doc_b"}
    assert fused[0][1] == fused[1][1]  # Equal RRF score sum, k=0 safely defaulted to k=60


def test_resolve_repository_on_relative_default_path():
    repo = resolve_repository(".verifyci/verifyci.db")
    assert repo is not None
    assert repo == "verifyci"


def test_replay_engine_branching_paths():
    engine = ReplayEngine()
    engine.add_anchor("rev_root", {"count": 0})
    engine.add_delta("rev_root", "rev_branch_a", {"count": 1, "branch": "A"})
    engine.add_delta("rev_root", "rev_branch_b", {"count": 2, "branch": "B"})

    # Should find path to rev_branch_b rather than blindly taking rev_branch_a
    proj = engine.replay("rev_root", "rev_branch_b")
    assert proj.state.get("branch") == "B"
    assert proj.state.get("count") == 2


def test_toml_fragment_validation_yields_inconclusive_not_fail():
    diff = """diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -10,3 +10,4 @@
     "pydantic>=2.0",
+    "rich>=13.0",
 ]
"""
    status, err = _validate_configuration_diff(diff, ["pyproject.toml"])
    assert status == "inconclusive"
    assert "toml_fragment" in err


def test_graph_store_event_attestation_serialization(tmp_path):
    db_file = tmp_path / "test.db"
    store = GraphStore(str(db_file))
    att = AttestationMetadata(
        key_id="k1",
        signature_algorithm="ed25519",
        public_key_id="pub1",
        signed_at=100.0,
        signature="sig",
        signed_hash="phash",
    )
    event = Event(
        id="evt_1",
        type="task.verified",
        timestamp=100.0,
        task_id="t1",
        conversation_id="c1",
        attestation=att,
    )
    # Must serialize without TypeError
    store.insert_event(event)
    events = store.get_events()
    assert len(events) == 1
    assert events[0].id == "evt_1"
    store.close()


def test_cargo_subtable_package_does_not_emit_ghost_dependencies():
    from verifyci.ingestion.dependency import _subtable_package, _parse_cargo

    # Section headers must return None
    assert _subtable_package("[dependencies]") is None
    assert _subtable_package("[dev-dependencies]") is None
    assert _subtable_package("[build-dependencies]") is None
    assert _subtable_package("[workspace.dependencies]") is None
    assert _subtable_package("[target.'cfg(windows)'.dependencies]") is None
    assert _subtable_package("[target.'cfg(unix)'.build-dependencies]") is None

    # Genuine package subtables must return the package name
    assert _subtable_package("[dependencies.serde]") == "serde"
    assert _subtable_package("[build-dependencies.cc]") == "cc"
    assert _subtable_package("[target.'cfg(windows)'.dependencies.winapi]") == "winapi"

    # End-to-end parse must not create ghost dependency for section name
    cargo_toml = """
[package]
name = "my-crate"
version = "0.1.0"

[build-dependencies]
cc = "1.0"

[build-dependencies.bindgen]
version = "0.60"
"""
    edges = _parse_cargo(cargo_toml, "Cargo.toml", "rev1")
    pkgs = {e.metadata.get("package") for e in edges}
    assert "build-dependencies" not in pkgs
    assert "cc" in pkgs
    assert "bindgen" in pkgs


def test_parameter_containment_scoped_to_enclosing_function():
    from verifyci.ingestion.parser import TreeSitterParser
    from verifyci.ingestion.extractor import extract_entities, extract_edges
    from verifyci.contracts.edge import EdgeType

    src = """
def func_a(param_x):
    return param_x

def func_b(param_y):
    return param_y
"""
    parser = TreeSitterParser()
    parsed = parser.parse("sample.py", src.encode("utf-8"), "python")
    entities = extract_entities(parsed, "repo1", "rev1")
    edges = extract_edges(parsed, entities, "rev1")

    contains_edges = [e for e in edges if e.type == EdgeType.CONTAINS]
    ent_by_id = {e.revision_entity_id: e for e in entities}

    for edge in contains_edges:
        parent = ent_by_id.get(edge.src_entity_id)
        child = ent_by_id.get(edge.dst_entity_id)
        if parent and child and parent.name == "func_a" and child.name == "param_y":
            assert False, "func_a must not contain param_y from func_b"
        if parent and child and parent.name == "func_b" and child.name == "param_x":
            assert False, "func_b must not contain param_x from func_a"


def test_config_load_handles_malformed_yaml_structures_with_value_error(tmp_path):
    import pytest
    from verifyci.verification.config import _load_file, _load_waivers_file

    bad_inv = tmp_path / "invariants.yaml"
    bad_inv.write_text("- id: rule1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        _load_file(str(bad_inv))

    bad_waiver = tmp_path / "waivers.yaml"
    bad_waiver.write_text("- target: auth.py\n", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        _load_waivers_file(str(bad_waiver))


def test_validate_task_ir_rejects_cycles_dangling_and_missing_budget():
    from verifyci.contracts.task_ir import TaskIR, Step, Budget
    from verifyci.orchestration.compiler.validation import validate_task_ir

    # Budget is None
    task_no_budget = TaskIR(
        goal="run task",
        intent_package_id="intent-1",
        steps=[Step(step_id="step_a", type="t", config={}, pre_commit_hook_id="h", depends_on=[])],
        constraints=[],
        budget=None,
        policy_id="default",
    )
    assert validate_task_ir(task_no_budget) is False

    # Cycle in steps
    task_cycle = TaskIR(
        goal="run task",
        intent_package_id="intent-1",
        steps=[
            Step(step_id="step_a", type="t", config={}, pre_commit_hook_id="h", depends_on=["step_b"]),
            Step(step_id="step_b", type="t", config={}, pre_commit_hook_id=None, depends_on=["step_a"]),
        ],
        constraints=[],
        budget=Budget(budget_id="b", nano_usd=1000),
        policy_id="default",
    )
    assert validate_task_ir(task_cycle) is False

    # Dangling dependency
    task_dangling = TaskIR(
        goal="run task",
        intent_package_id="intent-1",
        steps=[
            Step(step_id="step_a", type="t", config={}, pre_commit_hook_id="h", depends_on=["ghost_step"]),
        ],
        constraints=[],
        budget=Budget(budget_id="b", nano_usd=1000),
        policy_id="default",
    )
    assert validate_task_ir(task_dangling) is False


def test_emit_event_supports_task_and_conversation_id_and_none_ledger():
    from verifyci.memory.ledger import EventLedger
    from verifyci.orchestration.events import emit_event

    assert emit_event(None, "EVT", {}, {}) is None

    ledger = EventLedger()
    event = emit_event(ledger, "TASK_COMPLETED", {"status": "ok"}, {"src": "test"}, task_id="task-99", conversation_id="conv-1")
    assert event is not None
    assert event.task_id == "task-99"
    assert event.conversation_id == "conv-1"


def test_cosine_similarity_dimension_mismatch_and_empty():
    from verifyci.retrieval.dense import _cosine_similarity

    assert _cosine_similarity([], [1.0, 2.0]) == 0.0
    assert _cosine_similarity([1.0], [1.0, 2.0]) == 0.0
    assert _cosine_similarity([1.0, 0.0], [1.0, 0.0]) == 1.0


def test_metadata_store_wal_and_context_manager(tmp_path):
    from verifyci.storage.metadata import MetadataStore

    db_path = str(tmp_path / "meta.db")
    with MetadataStore(db_path) as store:
        store.upsert_file("app.py", "hash1", "python", "rev1")
        row = store.get_file("app.py")
        assert row is not None
        assert row[0] == "app.py"


