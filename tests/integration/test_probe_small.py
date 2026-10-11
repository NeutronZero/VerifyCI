"""PROBES item 9: small CLI/MCP surface fixes."""


def _repo_with_func(tmp_path, name="proj"):
    repo = tmp_path / name
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text(
        "def authenticate():\n    return 1\n")
    return str(repo)


def test_probe_query_cli_prints_file_lines(tmp_path):
    from typer.testing import CliRunner
    from verifyci.interface.cli import app
    from verifyci.interface.commands.ingest import run_ingest
    repo = _repo_with_func(tmp_path)
    out = run_ingest(repo)
    runner = CliRunner()
    r = runner.invoke(app, ["query", "authenticate", "--db", out["db_path"]])
    assert r.exit_code == 0, r.output
    assert ".py:" in r.output, r.output


def test_probe_ingest_reports_parse_errors(tmp_path):
    from typer.testing import CliRunner
    from verifyci.interface.cli import app
    repo = tmp_path / "proj"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "bad.py").write_text("def broken(:\n    pass\n")
    (repo / "src" / "ok.py").write_text("x = 1\n")
    runner = CliRunner()
    r = runner.invoke(app, ["ingest", str(repo)])
    assert r.exit_code == 0, r.output
    assert "parse error" in r.output.lower(), r.output


def test_probe_verify_diff_no_echo():
    import asyncio
    from verifyci.interface.mcp_server import (
        MAX_DIFF_CHARS, create_mcp_server,
    )

    class _Payload:
        revision_entity_id = "e1"
        logical_entity_id = "logical:e1"
        revision_id = "revX"
        name = "func"
        file_path = "src/app.py"
        line_start = 10
        line_end = 20
        source_hash = "abc123"

    class _FakeGraph:
        def nodes(self):
            return [_Payload()]

        def node_indices(self):
            return [0]

    server = create_mcp_server(graph=_FakeGraph(), node_map={"e1": 0},
                               entities=[_Payload()], store=None)
    ok = asyncio.run(server.call_tool("verify.diff", diff="small diff"))
    assert "diff" not in ok, sorted(ok)
    assert ok["revision_id"] == "revX", ok
    err = asyncio.run(server.call_tool("verify.diff", diff="x" * (MAX_DIFF_CHARS + 1)))
    assert "diff" not in err, sorted(err)
    assert err["error"] == "diff_too_large"


def test_probe_verify_reports_resolved_revision(tmp_path):
    import os
    from verifyci.interface.commands.ingest import run_ingest
    from verifyci.interface.commands.verify import run_verify
    from verifyci.storage.graph_store import GraphStore
    repo = _repo_with_func(tmp_path)
    out = run_ingest(repo)
    rev = out["revision_id"]
    got = run_verify("", db_path=out["db_path"])
    assert got["revision_id"] == rev, got
    got2 = run_verify("", revision_id=rev, db_path=out["db_path"])
    assert got2["revision_id"] == rev, got2
    empty = str(tmp_path / "empty.db")
    GraphStore(empty).close()
    got3 = run_verify("", db_path=empty)
    assert got3["revision_id"] == "", got3
    assert os.path.exists(empty)
