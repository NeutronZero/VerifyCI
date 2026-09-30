"""One skip classifier for every discovery path.

Invariant: a path classified as skipped must not become an indexed
source entity or dependency merely because it is discovered through a
different ingestion path. Ingest and `aci deps` previously disagreed
(deps matched absolute path parts), so node_modules/.venv/build
manifests leaked into deps output.
"""
import sqlite3

from verifyci.ingestion.ignore import iter_repo_files
from verifyci.interface.commands.deps import run_deps
from verifyci.interface.commands.ingest import run_ingest


def _repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("def f():\n    pass\n")
    (tmp_path / "requirements.txt").write_text("requests==2.0\n")
    for d in ("node_modules/leftpad", "build", ".venv/lib", ".git", "deep/nested/dist"):
        (tmp_path / d).mkdir(parents=True)
    (tmp_path / "node_modules" / "leftpad" / "package.json").write_text(
        '{"name":"leftpad","dependencies":{"evil":"1.0"}}')
    (tmp_path / "build" / "requirements.txt").write_text("built-thing==1.0\n")
    (tmp_path / ".venv" / "pyvenv.cfg").write_text("home = /usr\n")
    (tmp_path / ".venv" / "lib" / "requirements.txt").write_text("venv-only==3.0\n")
    (tmp_path / ".git" / "requirements.txt").write_text("gitthing==9.9\n")
    (tmp_path / "deep" / "nested" / "dist" / "requirements.txt").write_text("nested==1.0\n")
    return tmp_path


def _indexed_paths(db):
    conn = sqlite3.connect(db)
    try:
        return {r[0] for r in conn.execute(
            "SELECT DISTINCT file_path FROM entities WHERE valid_until IS NULL"
        ).fetchall()}
    finally:
        conn.close()


def test_deps_and_ingest_agree_on_skips(tmp_path):
    repo = str(_repo(tmp_path))
    out = run_ingest(repo)
    indexed = _indexed_paths(out["db_path"])
    deps_files = set(run_deps(repo))
    # No default-skipped dir leaks through either path.
    for leak in ("node_modules", ".venv", ".git"):
        assert not any(leak in p for p in deps_files), f"{leak} leaked into deps"
        assert not any(leak in p for p in indexed), f"{leak} leaked into ingest"
    # Ambiguous names (build/dist) are NOT default-skipped, so both paths
    # include them — agreement is the invariant, not exclusion.
    assert "build/requirements.txt" in deps_files
    # Registry manifest in the repo root is present through both paths.
    assert "requirements.txt" in deps_files


def test_venv_detected_by_marker_not_name(tmp_path):
    repo = _repo(tmp_path)
    # A venv under an arbitrary name is still pruned (pyvenv.cfg marker).
    (repo / "myenv").mkdir()
    (repo / "myenv" / "pyvenv.cfg").write_text("home = /usr\n")
    (repo / "myenv" / "requirements.txt").write_text("venv-only==4.0\n")
    rel = {p.relative_to(repo).as_posix() for p in iter_repo_files(repo)}
    assert not any(p.startswith("myenv/") for p in rel)
    assert "src/a.py" in rel


def test_verifyciignore_prunes_ambiguous_dirs(tmp_path):
    repo = _repo(tmp_path)
    # `dist` is a legitimate package name in some repos, so it is NOT a
    # default skip; a `.verifyciignore` opts back in to pruning it.
    (repo / ".verifyciignore").write_text("build/\ndist/\n")
    rel = {p.relative_to(repo).as_posix() for p in iter_repo_files(repo)}
    assert not any(p.startswith("build/") for p in rel)
    assert not any("nested/dist/" in p for p in rel)


def test_default_does_not_skip_ambiguous_names(tmp_path):
    repo = _repo(tmp_path)
    (repo / "build").mkdir(exist_ok=True)
    (repo / "build" / "module.py").write_text("x = 1\n")
    rel = {p.relative_to(repo).as_posix() for p in iter_repo_files(repo)}
    # Without .verifyciignore, `build/` is walked.
    assert "build/module.py" in rel


def test_file_moved_into_skipped_dir_disappears_incrementally(tmp_path):
    repo = str(_repo(tmp_path))
    out = run_ingest(repo)
    db = out["db_path"]
    assert any("src/a.py" in p for p in _indexed_paths(db))

    # Move the file into a skipped directory, re-ingest incrementally.
    (tmp_path / "src" / "a.py").rename(tmp_path / "node_modules" / "a.py")
    out2 = run_ingest(repo, incremental=True)
    db2 = out2["db_path"]
    indexed = _indexed_paths(db2)
    assert not any(p.endswith("src/a.py") for p in indexed)
    assert not any("node_modules" in p for p in indexed)
    # The skipped directory is reported, not silently zero-file.
    assert "node_modules" in (out2.get("skipped_dirs") or [])


def test_skip_state_does_not_change_revision_identity(tmp_path):
    repo = _repo(tmp_path)
    # Adding content under a skipped dir must not change revision identity.
    before = run_ingest(str(repo))["revision_id"]
    (repo / "node_modules" / "leftpad" / "extra.js").write_text("x=1\n")
    after = run_ingest(str(repo))["revision_id"]
    assert before == after