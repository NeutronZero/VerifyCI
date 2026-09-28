from src.verification.config import load_repo_invariants
from src.verification.defaults import default_invariants


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
