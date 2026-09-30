from verifyci.verification.config import load_repo_invariants
from verifyci.verification.defaults import default_invariants


def _sig(inv):
    return [(i.invariant_id, i.compiled_query, i.blocking) for i in inv]


def test_no_file_resolves_to_builtins():
    assert _sig(load_repo_invariants(None)) == _sig(default_invariants())
    assert _sig(load_repo_invariants("/nonexistent/x.db")) == _sig(default_invariants())


def test_repo_file_extends_builtins(tmp_path):
    db = tmp_path / "verifyci.db"
    db.write_text("")
    (tmp_path / "invariants.yaml").write_text(
        "invariants:\n"
        "  - id: no-sync-in-sansio\n"
        '    rule: sansio must not import sync flask\n'
        '    query: "forbid_import:..config"\n'
        "    blocking: true\n",
        encoding="utf-8",
    )
    resolved = load_repo_invariants(str(db))
    assert _sig(resolved)[:2] == _sig(default_invariants())
    assert ("no-sync-in-sansio", "forbid_import:..config", True) in _sig(resolved)
    assert len(resolved) == 3


def test_malformed_yaml_is_loud(tmp_path):
    import pytest
    from verifyci.verification.config import load_repo_invariants
    bad = tmp_path / "invariants.yaml"
    bad.write_text("invariants:\n  - id: x\n   - bad indent\n", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed invariants file"):
        load_repo_invariants(path=str(bad))


def test_empty_file_is_quiet(tmp_path):
    from verifyci.verification.config import load_repo_invariants
    empty = tmp_path / "invariants.yaml"
    empty.write_text("", encoding="utf-8")
    assert _sig(load_repo_invariants(path=str(empty))) == _sig(default_invariants())


def test_typo_rule_blocks_everything_explicitly():
    # Misspelled kind fails closed: surprising, intentional, and pinned.
    from verifyci.verification.intent_align import evaluate_invariants
    from verifyci.contracts.verification_ir import Invariant
    inv = Invariant(invariant_id="typo", rule="typo",
                    compiled_query="forbid_imports:typing", blocking=True)
    (check,), _ = evaluate_invariants("x = 1", [inv], graph=None)
    assert check.passed is False
    assert "fail-closed" in check.explanation
