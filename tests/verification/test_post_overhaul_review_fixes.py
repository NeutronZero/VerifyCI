"""Tests for post-overhaul audit findings (B1-B5, C1, C2, C4, C5).

Validates fixes for:
- B1: _has_associated_witness does not allow unrelated non-general witness to bypass entity check
- B2: _is_guard_line narrowed to auth/security guards; rename or replace assert with custom error does not FAIL
- B3: verify_deletion_hunks uses anchored def/class matching (no substring collisions like foo -> foobar)
- B4: _extract_file_diff_texts does not lose preamble when followed by new-file block
- B5: _validate_configuration_diff multi-hunk JSON config declines to INCONCLUSIVE, not false FAIL
- C1: SignedIntentWaiver verification hook and load_repo_waivers
- C2: Structured FAIL rationale on malformed invariants.yaml (no unhandled traceback)
- C4: classify_path recognizes all DEPENDENCY_FILES (Cargo.toml, package.json, go.mod, pom.xml) as CONFIGURATION
- C5: Witness extraction requires structured AST references
- D: Singular test/ directory classified as TEST_SUITE; EntitySnippetRecord immutability
"""
import pytest
from types import SimpleNamespace

from verifyci.contracts.entity import EntitySnippetRecord
from verifyci.contracts.verification_ir import ExecutionWitness, SignedIntentWaiver
from verifyci.verification.deletion import (
    _has_associated_witness,
    _is_guard_line,
    _is_guard_preserved_in_additions,
    verify_deletion_hunks,
)
from verifyci.verification.partition import (
    FilePartition,
    classify_path,
    partition_diff,
)


# ---------------------------------------------------------------------------
# B1: _has_associated_witness scoping
# ---------------------------------------------------------------------------

def test_b1_witness_does_not_match_unrelated_file_even_if_non_general():
    """A non-general witness pointing to file B must NOT witness file A."""
    ent = SimpleNamespace(revision_entity_id="ent_a", name="compute", file_path="src/a.py")
    w = ExecutionWitness(
        witness_id="w1",
        test_file="tests/test_b.py",
        test_function="test_b",
        target_file="src/b.py",
        target_entity_id="ent_b",
        is_general_regression=False,
        association_method="direct_ast",
    )
    # Target file is src/b.py, entity is in src/a.py -> must be False
    assert not _has_associated_witness("src/a.py", ent, [w])


def test_b1_witness_matches_when_target_file_or_entity_matches():
    """Witness matches when target_file or target_entity_id matches."""
    ent = SimpleNamespace(revision_entity_id="ent_a", name="compute", file_path="src/a.py")
    w_file = ExecutionWitness(
        witness_id="w1",
        test_file="tests/test_a.py",
        target_file="src/a.py",
        target_entity_id=None,
        is_general_regression=False,
    )
    assert _has_associated_witness("src/a.py", ent, [w_file])

    w_ent = ExecutionWitness(
        witness_id="w2",
        test_file="tests/test_a.py",
        target_file=None,
        target_entity_id="ent_a",
        is_general_regression=False,
    )
    assert _has_associated_witness("src/a.py", ent, [w_ent])


def test_b1_witness_entity_scoping_disambiguates_multi_entity_file():
    """In a file with multiple entities, an entity-specific witness for entity A

    must NOT corroborate entity B in the same file.
    """
    ent_add = SimpleNamespace(revision_entity_id="ent_add", name="add", file_path="src/calc.py")
    ent_mult = SimpleNamespace(revision_entity_id="ent_mult", name="multiply", file_path="src/calc.py")

    # Witness 1 specifically targets 'add' (both target_file and target_entity_id set)
    w_add = ExecutionWitness(
        witness_id="w_add",
        test_file="tests/test_calc.py",
        test_function="test_add",
        target_file="src/calc.py",
        target_entity_id="ent_add",
        is_general_regression=False,
    )
    # Must match add
    assert _has_associated_witness("src/calc.py", ent_add, [w_add]) is True
    # Must NOT match multiply even though it is in the same file
    assert _has_associated_witness("src/calc.py", ent_mult, [w_add]) is False

    # Witness 2 is a file-level witness without specific target_entity_id
    w_file = ExecutionWitness(
        witness_id="w_file",
        test_file="tests/test_calc.py",
        test_function=None,
        target_file="src/calc.py",
        target_entity_id=None,
        is_general_regression=False,
    )
    assert _has_associated_witness("src/calc.py", ent_add, [w_file]) is True
    assert _has_associated_witness("src/calc.py", ent_mult, [w_file]) is True


# ---------------------------------------------------------------------------
# B2: _is_guard_line narrowing
# ---------------------------------------------------------------------------

def test_b2_ordinary_verbs_and_exceptions_are_not_guards():
    """Ordinary verbs (authenticate, authorize, sanitize) and standard exceptions

    (ValueError, KeyError, TypeError, RuntimeError) are not security guards.
    """
    assert not _is_guard_line("    authenticate(user)")
    assert not _is_guard_line("    authorize(token)")
    assert not _is_guard_line("    data = sanitize(raw_input)")
    assert not _is_guard_line("    raise ValueError('invalid param')")
    assert not _is_guard_line("    raise KeyError('missing key')")
    assert not _is_guard_line("    raise TypeError('bad type')")
    assert not _is_guard_line("    raise RuntimeError('failed')")


def test_b2_security_exceptions_and_checks_are_guards():
    """Specific security exceptions and auth decorators remain guards."""
    assert _is_guard_line("    raise PermissionError('forbidden')")
    assert _is_guard_line("    raise AuthenticationError('bad creds')")
    assert _is_guard_line("    raise SecurityError('access denied')")
    assert _is_guard_line("    @require_auth")
    assert _is_guard_line("    @login_required")
    assert _is_guard_line("    check_permission(user, 'admin')")
    assert _is_guard_line("    verify_token(token)")


def test_b2_assert_replaced_by_custom_exception_is_preserved():
    """Replacing an assert with if not x: raise CustomError(...) preserves the guard."""
    added = ["    if not condition:", "        raise DomainValidationFailed('err')"]
    assert _is_guard_preserved_in_additions(added)


# ---------------------------------------------------------------------------
# B3: verify_deletion_hunks anchored matching
# ---------------------------------------------------------------------------

def test_b3_anchored_def_matching_avoids_prefix_collisions():
    """e_name = 'foo' must NOT match def foobar()."""
    ent_foo = SimpleNamespace(
        revision_entity_id="e_foo",
        name="foo",
        file_path="src/app.py",
        line_start=1,
        line_end=5,
        type="FUNCTION",
    )
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1,3 +1,0 @@\n"
        "-def foobar():\n"
        "-    return 1\n"
    )
    # The diff deletes foobar, NOT foo. ent_foo should NOT be marked deleted!
    verdicts = verify_deletion_hunks(
        diff=diff,
        code_files=["src/app.py"],
        entities=[ent_foo],
    )
    # Should not classify as class_1_dead_code_verified:foo
    for v in verdicts:
        assert "class_1_dead_code_verified:foo" not in v.reasoning


# ---------------------------------------------------------------------------
# B4: _extract_file_diff_texts with preamble followed by new file
# ---------------------------------------------------------------------------

def test_b4_preamble_preserved_when_followed_by_new_file():
    """A stray preamble preceding a new-file block (/dev/null) must not be lost."""
    diff = (
        "+stray line\n"
        "diff --git a/new.py b/new.py\n"
        "--- /dev/null\n"
        "+++ b/new.py\n"
        "@@ -0,0 +1,1 @@\n"
        "+x = 1\n"
    )
    pdiff = partition_diff(diff)
    core_diff = pdiff.raw_diff_for_partition(FilePartition.CODE_CORE)
    assert "+stray line" in core_diff


# ---------------------------------------------------------------------------
# C4: Dependency files classified as CONFIGURATION
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename", [
    "Cargo.toml", "Cargo.lock",
    "package.json", "package-lock.json",
    "go.mod", "go.sum",
    "pom.xml",
    "requirements.txt", "requirements-dev.txt",
    "pyproject.toml",
    "setup.py", "setup.cfg",
])
def test_c4_manifest_dependency_files_classified_as_configuration(filename):
    assert classify_path(filename) == FilePartition.CONFIGURATION
    assert classify_path(f"subproject/{filename}") == FilePartition.CONFIGURATION


def test_d_singular_test_directory_classified_as_test_suite():
    assert classify_path("test/test_core.py") == FilePartition.TEST_SUITE
    assert classify_path("test/core_test.py") == FilePartition.TEST_SUITE
    assert classify_path("test/conftest.py") == FilePartition.TEST_SUITE


# ---------------------------------------------------------------------------
# D: EntitySnippetRecord immutability
# ---------------------------------------------------------------------------

def test_d_entity_snippet_record_immutable():
    rec = EntitySnippetRecord(
        lines=("line 1", "line 2"),
        is_complete=True,
        truncated_at_line=None,
        char_count=12,
    )
    assert isinstance(rec.lines, tuple)
    assert rec.lines == ("line 1", "line 2")
    assert rec.text == "line 1\nline 2"
    with pytest.raises(TypeError):
        rec.lines[0] = "mutated"  # type: ignore[index]


# ---------------------------------------------------------------------------
# B5: Multi-hunk JSON config declines to INCONCLUSIVE
# ---------------------------------------------------------------------------

def test_b5_multi_hunk_json_diff_declines_to_inconclusive():
    diff = (
        "diff --git a/package.json b/package.json\n"
        "--- a/package.json\n"
        "+++ b/package.json\n"
        "@@ -5,3 +5,3 @@\n"
        '-  "items": [\n'
        '+  "items": [ 1,\n'
        "@@ -20,3 +20,3 @@\n"
        '-  "license": "MIT"\n'
        '+  "license": "Apache-2.0"\n'
    )
    from verifyci.verification.semi_formal_reason import SemiFormalReasoner
    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(diff=diff, graph=None)
    assert cert.conclusion.result == "inconclusive"
    assert "multi_hunk_json_configuration" in cert.conclusion.reasoning


# ---------------------------------------------------------------------------
# B6: Documentation of fast paths in docstring
# ---------------------------------------------------------------------------

def test_b6_docstring_documents_documentation_and_config_fast_paths():
    import verifyci.verification.semi_formal_reason as sfr
    doc = sfr.__doc__ or ""
    assert "DOCUMENTATION" in doc
    assert "CONFIGURATION" in doc
    assert "fast path" in doc.lower()


# ---------------------------------------------------------------------------
# C1: SignedIntentWaiver verification and loading
# ---------------------------------------------------------------------------

def test_c1_signed_intent_waiver_verification():
    import hashlib
    import hmac
    waiver = SignedIntentWaiver(
        waiver_id="w-1",
        target="app.guard",
        signer="sec-lead",
        signature="legacy-sig",
        reason="authorized refactor",
        valid=True,
        algorithm="hmac-sha256",
    )
    # 1. Canonical payload definition
    assert waiver.canonical_bytes() == b"w-1:app.guard:sec-lead:authorized refactor"

    # 2. Unconfigured keys: DENY by default (no silent bearer fallback).
    assert waiver.verify_signature(None) is False

    # 2b. Bearer fallback is explicit opt-in only, and warns loudly.
    import warnings
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert waiver.verify_signature(None, allow_bearer=True) is True
    assert any(issubclass(w.category, RuntimeWarning) for w in caught)

    # 3. Symmetric HMAC-SHA256 verification
    expected_sig = hmac.new(b"secret-key", waiver.canonical_bytes(), hashlib.sha256).hexdigest()
    valid_hmac_waiver = SignedIntentWaiver(
        waiver_id="w-1",
        target="app.guard",
        signer="sec-lead",
        signature=expected_sig,
        reason="authorized refactor",
        valid=True,
        algorithm="hmac-sha256",
    )
    assert valid_hmac_waiver.verify_signature("secret-key") is True
    assert waiver.verify_signature("secret-key") is False

    # 4. Asymmetric Ed25519 verification
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_hex = pub.public_bytes_raw().hex()
    ed_sig = priv.sign(waiver.canonical_bytes()).hex()

    ed_waiver = SignedIntentWaiver(
        waiver_id="w-1",
        target="app.guard",
        signer="sec-lead",
        signature=ed_sig,
        reason="authorized refactor",
        valid=True,
        algorithm="ed25519",
    )
    assert ed_waiver.verify_signature(pub_hex) is True
    assert ed_waiver.verify_signature("00" * 32) is False


def test_c1_load_repo_waivers(tmp_path):
    from verifyci.verification.config import load_repo_waivers
    db = tmp_path / "verifyci.db"
    db.write_text("")
    (tmp_path / "waivers.yaml").write_text(
        "waivers:\n"
        "  - id: w-1\n"
        "    target: auth.check\n"
        "    signer: alice\n"
        "    signature: sig123\n"
        "    reason: migration\n",
        encoding="utf-8",
    )
    waivers = load_repo_waivers(str(db))
    assert len(waivers) == 1
    assert waivers[0].waiver_id == "w-1"
    assert waivers[0].target == "auth.check"
    assert waivers[0].signer == "alice"
    assert waivers[0].signature == "sig123"
    assert waivers[0].valid is True


# ---------------------------------------------------------------------------
# C2: Malformed invariants.yaml fail-closed structured returns
# ---------------------------------------------------------------------------

def test_c2_malformed_invariants_yaml_structured_fail_run_verify(tmp_path):
    import sqlite3
    from verifyci.interface.commands.verify import run_verify
    db = tmp_path / "verifyci.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE schema_version (version INT)")
    (tmp_path / "invariants.yaml").write_text("invariants:\n  - bad : : yaml\n", encoding="utf-8")
    diff = "diff --git a/src/app.py b/src/app.py\n+x = 1\n"
    res = run_verify(diff, db_path=str(db))
    assert res["status"] == "FAIL"
    assert res["rationale"] == "invalid_invariants_config"


def test_c2_malformed_invariants_yaml_structured_failed_run_task(tmp_path):
    import sqlite3
    from verifyci.interface.commands.run import run_task
    db = tmp_path / "verifyci.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE schema_version (version INT)")
    (tmp_path / "invariants.yaml").write_text("invariants:\n  - bad : : yaml\n", encoding="utf-8")
    res = run_task("do test task", db_path=str(db))
    assert res["status"] == "FAILED"
    assert res["error"] == "invalid_invariants_config"
    assert res["decision"] == "FAIL"
    assert res["rationale"] == "invalid_invariants_config"


def test_c2_malformed_invariants_yaml_structured_fail_mcp_server(tmp_path):
    import asyncio
    from verifyci.interface.mcp_server import create_mcp_server
    from types import SimpleNamespace
    db = tmp_path / "verifyci.db"
    db.write_text("")
    (tmp_path / "invariants.yaml").write_text("invariants:\n  - bad : : yaml\n", encoding="utf-8")
    store = SimpleNamespace(db_path=str(db))
    server = create_mcp_server(store=store)
    diff = "diff --git a/src/app.py b/src/app.py\n+x = 1\n"
    res = asyncio.run(server.call_tool("verify.diff", diff=diff))
    assert res["status"] == "FAIL"
    assert res["rationale"] == "invalid_invariants_config"

    res_task = asyncio.run(server.call_tool("task.run", task="do task"))
    assert res_task["status"] == "FAILED"
    assert res_task["error"] == "invalid_invariants_config"

