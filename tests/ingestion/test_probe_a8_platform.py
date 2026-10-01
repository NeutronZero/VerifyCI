"""A8 probes: platform hardening items demonstrated against the tree.

Covered (each reproduced before the fix):
- PlatformIO build/lib trees (.pio) were ingested as ordinary source;
- manifest reads decoded with the LOCALE encoding (cp1252 on Windows,
  utf-8 on Linux) so identical bytes produced different source hashes
  across platforms, and a UTF-8 BOM made json.loads reject a valid
  package.json;
- a manifest that failed to parse returned [] silently: the dependency
  graph lost facts with no record ("no dependencies" and "corrupt
  manifest" were indistinguishable).

NOT reproduced (recorded, not changed):
- .verifyciignore path matching: already one representation (probe:
  `pkg/` prunes children, `sub/*.py` globs match) — no defect found;
- requires-python: pyproject says >=3.12, tomllib needs 3.11 — already
  consistent (the audit's 3.11 claim does not match the tree).
"""
import sqlite3

from verifyci.ingestion.ignore import DEFAULT_SKIP_DIRS, iter_repo_files, skipped_dir_names
from verifyci.interface.commands.ingest import run_ingest
from verifyci.interface.commands.init import run_init


# ------------------------------------------------------------------ .pio --

def test_pio_is_a_default_skip():
    assert ".pio" in DEFAULT_SKIP_DIRS


def test_pio_trees_never_ingested(tmp_path):
    repo = tmp_path / "fw"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "main.cpp").write_text("int main(){return 0;}\n")
    lib = repo / ".pio" / "libdeps" / "Unity" / "src"
    lib.mkdir(parents=True)
    (lib / "unity.c").write_text("void setUp(void){}\n")
    build = repo / ".pio" / "build"
    build.mkdir()
    (build / "generated.c").write_text("int gen(void){return 1;}\n")
    rels = {str(p.relative_to(repo).as_posix()) for p in iter_repo_files(repo)}
    assert rels == {"src/main.cpp"}, rels
    assert ".pio" in skipped_dir_names(repo)
    run_init(str(repo))
    out = run_ingest(str(repo))
    assert out["entities"] >= 1
    store_db = str(repo / ".verifyci" / "verifyci.db")
    conn = sqlite3.connect(store_db)
    try:
        paths = [r[0] for r in conn.execute("SELECT DISTINCT file_path FROM entities")]
    finally:
        conn.close()
    assert not any(".pio" in p for p in paths), paths


# ------------------------------------------------------- manifest encoding -

def test_manifest_utf8_bom_parses(tmp_path):
    """A BOM'd package.json is a real Windows-tool artifact; it must not
    erase the SBOM."""
    repo = tmp_path / "bomrepo"
    repo.mkdir()
    (repo / "package.json").write_bytes(
        '\ufeff{"dependencies": {"left-pad": "1.0.0"}}'.encode("utf-8"))
    (repo / "app.js").write_text("x=1\n")
    run_init(str(repo))
    out = run_ingest(str(repo))
    assert not out["manifest_errors"], out["manifest_errors"]
    conn = sqlite3.connect(out["db_path"])
    try:
        pkgs = conn.execute(
            "SELECT metadata_json FROM edges WHERE type='DEPENDS_ON'").fetchall()
    finally:
        conn.close()
    assert any("left-pad" in (r[0] or "") for r in pkgs), pkgs


def test_manifest_hash_deterministic_across_reads(tmp_path):
    """The same utf-8 bytes must hash identically no matter the platform
    locale — the old locale decode made Windows/Linux disagree."""
    from verifyci.interface.commands.ingest import _read_manifest_text
    repo = tmp_path / "m"
    repo.mkdir()
    f = repo / "package.json"
    content = '{"name": "café-pkg", "dependencies": {"a": "1"}}'
    f.write_bytes(content.encode("utf-8"))          # raw utf-8
    got = _read_manifest_text(f)
    assert got == content                            # exact, not replaced
    assert "caf\u00e9" in got


# ------------------------------------------------ per-file manifest errors -

def test_corrupt_manifest_recorded_not_silent(tmp_path):
    repo = tmp_path / "cm"
    repo.mkdir()
    (repo / "package.json").write_text("{definitely not json", encoding="utf-8")
    (repo / "requirements.txt").write_text("requests==2.0\n", encoding="utf-8")
    run_init(str(repo))
    out = run_ingest(str(repo))
    assert out["manifest_errors"], "corrupt manifest vanished silently"
    assert any("package.json" in e for e in out["manifest_errors"])
    # the healthy sibling manifest still lands:
    conn = sqlite3.connect(out["db_path"])
    try:
        deps = conn.execute(
            "SELECT metadata_json FROM edges WHERE type='DEPENDS_ON'").fetchall()
    finally:
        conn.close()
    assert any("requests" in (r[0] or "") for r in deps), deps


def test_manifest_error_cli_reports(tmp_path):
    from typer.testing import CliRunner
    from verifyci.interface.cli import app
    repo = tmp_path / "cm2"
    repo.mkdir()
    (repo / "package.json").write_text("{oops", encoding="utf-8")
    runner = CliRunner()
    assert runner.invoke(app, ["init", str(repo)]).exit_code == 0
    r = runner.invoke(app, ["ingest", str(repo)])
    assert r.exit_code == 1, r.output
    assert "Manifest errors" in r.output


def test_extract_dependencies_errors_list_optional():
    # Back-compat: callers without an errors list keep the old contract.
    from verifyci.ingestion.dependency import extract_dependencies
    assert extract_dependencies("package.json", "{broken", "rev") == []
    errs: list = []
    assert extract_dependencies("package.json", "{broken", "rev", errors=errs) == []
    assert len(errs) == 1 and "package.json" in errs[0]
