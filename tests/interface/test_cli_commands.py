"""CLI wrapper coverage: init/ingest/stats/query/deps through typer runner."""
import shutil

from typer.testing import CliRunner

from verifyci.interface.cli import app

runner = CliRunner()


def _repo(tmp_path):
    dest = tmp_path / "repo"
    shutil.copytree("samples/test-repo", dest)
    return str(dest)


def test_init_ingest_stats_query_deps(tmp_path):
    repo = _repo(tmp_path)
    assert runner.invoke(app, ["init", repo]).exit_code == 0
    r = runner.invoke(app, ["ingest", repo])
    assert r.exit_code == 0, r.output
    assert "entities:" in r.output
    db = str(tmp_path / "repo" / ".verifyci" / "verifyci.db")
    s = runner.invoke(app, ["stats", "--db", db])
    assert s.exit_code == 0
    assert "entities:" in s.output
    q = runner.invoke(app, ["query", "where is auth", "--db", db])
    assert q.exit_code == 0
    d = runner.invoke(app, ["deps", "--path", repo])
    assert d.exit_code == 0


def test_ingest_incremental_and_commit(tmp_path):
    repo = _repo(tmp_path)
    assert runner.invoke(app, ["ingest", repo, "--commit", "abc123"]).exit_code == 0
    assert runner.invoke(app, ["ingest", repo, "--incremental"]).exit_code == 0
