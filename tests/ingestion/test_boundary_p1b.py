"""PHASE 1-B: ingestion/interface boundary integrity.

Hostile or degenerate repository input must be rejected, skipped with an
explicit record, or truncated with a flag — never crash the run, never
silently index attacker-chosen bytes, never OOM.
"""
import os

import pytest


def test_symlink_escape_not_ingested(tmp_path):
    from verifyci.ingestion.ignore import iter_repo_files
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.py"
    secret.write_text("PASSWORD = 'x'\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    link = repo / "evil.py"
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("symlinks unavailable")
    yielded = [p.name for p in iter_repo_files(repo)]
    assert "evil.py" not in yielded
    assert "app.py" in yielded


def test_symlinked_dir_not_descended(tmp_path):
    from verifyci.ingestion.ignore import iter_repo_files
    ext = tmp_path / "ext"
    ext.mkdir()
    (ext / "lib.py").write_text("x = 1\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    try:
        (repo / "linked").symlink_to(ext, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    yielded = [p.as_posix() for p in iter_repo_files(repo)]
    assert not any("lib.py" in p for p in yielded)


def test_fifo_not_ingested_and_does_not_block(tmp_path):
    from verifyci.ingestion.ignore import iter_repo_files
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    fifo = repo / "stream.py"
    _mkfifo = getattr(os, "mkfifo", None)
    if _mkfifo is None:
        pytest.skip("FIFOs unavailable")
    try:
        _mkfifo(fifo)
    except (OSError, NotImplementedError):
        pytest.skip("FIFOs unavailable")
    yielded = [p.name for p in iter_repo_files(repo)]
    assert "stream.py" not in yielded
    assert "app.py" in yielded


def test_oversize_file_skipped_and_recorded(tmp_path, monkeypatch):
    from verifyci.interface.commands import ingest as ingmod
    monkeypatch.setattr(ingmod, "MAX_INGEST_FILE_BYTES", 100)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "small.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "big.py").write_text("x = '" + "y" * 500 + "'\n", encoding="utf-8")
    sources, _texts, manifest, oversize, truncated = ingmod._collect(repo)
    rels = [r for r, _, _ in sources]
    assert "repo/small.py" in rels or "small.py" in rels
    assert any("big.py" in o for o in oversize)
    assert not truncated
    assert not any("big.py" in p for p, _ in manifest)


def test_aggregate_budget_truncates_with_flag(tmp_path, monkeypatch):
    from verifyci.interface.commands import ingest as ingmod
    monkeypatch.setattr(ingmod, "MAX_INGEST_FILE_BYTES", 10_000_000)
    monkeypatch.setattr(ingmod, "MAX_INGEST_TOTAL_BYTES", 100)
    repo = tmp_path / "repo"
    repo.mkdir()
    for i in range(5):
        (repo / f"f{i}.py").write_text("x = 1  # padding padding pad\n", encoding="utf-8")
    _sources, _texts, _manifest, _oversize, truncated = ingmod._collect(repo)
    assert truncated is True


def test_ingest_totals_carry_boundary_signals(tmp_path):
    from verifyci.interface.commands.ingest import run_ingest
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    totals = run_ingest(str(repo))
    assert "oversize_files" in totals
    assert "collection_truncated" in totals
    assert totals["collection_truncated"] is False


def test_file_slice_splits_on_newline_only():
    from verifyci.ingestion.file_slice import slice_source
    # \x0b and \x0c must NOT create line boundaries: tree-sitter and git
    # count \n alone.
    source = b"a = 1\x0bb = 2\x0cc = 3\nsecond\n"
    out = slice_source(source, 1, 2)
    assert "".join(out) == "a = 1\x0bb = 2\x0cc = 3\nsecond\n"


def test_sqlite_chunk_under_variable_floor():
    from verifyci.storage import graph_store as gs
    assert gs._SQLITE_PARAM_CHUNK * 2 + 10 <= 999


def test_cli_oversize_diff_fails_closed_at_command(tmp_path):
    from typer.testing import CliRunner
    from verifyci.interface import cli as climod
    from verifyci.interface.limits import MAX_DIFF_CHARS
    big = tmp_path / "big.diff"
    big.write_bytes(b"x" * (MAX_DIFF_CHARS + 10))
    result = CliRunner().invoke(climod.app, ["verify-diff", "--diff-file", str(big)])
    assert result.exit_code == 3, result.output


def test_cli_read_diff_boundary_exact(tmp_path):
    from verifyci.interface import cli as climod
    from verifyci.interface.limits import MAX_DIFF_CHARS
    ok = tmp_path / "ok.diff"
    ok.write_bytes(b"+x\n" * 10)
    assert "+x" in climod._read_diff("", str(ok))
    bad = tmp_path / "bad.diff"
    bad.write_bytes(b"x" * (MAX_DIFF_CHARS + 1))
    with pytest.raises(climod._DiffTooLarge):
        climod._read_diff("", str(bad))
