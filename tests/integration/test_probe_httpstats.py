"""PROBES item 5: HTTP auth, readonly URI, stats error, fail-closed DBs."""
import os


def _req(host):
    from fastapi import Request
    scope = {"type": "http", "client": (host, 1234)}
    return Request(scope)


def test_probe_auth_non_ascii_header_is_401(monkeypatch):
    import asyncio
    import pytest
    from fastapi import HTTPException
    from verifyci.interface.http import require_auth
    monkeypatch.setenv("ACI_API_TOKEN", "s3cret")
    with pytest.raises(HTTPException) as ei:
        asyncio.run(require_auth(_req("203.0.113.7"), "Bearer s\xe9cret"))
    assert ei.value.status_code == 401


def test_probe_stats_special_char_path(tmp_path):
    from verifyci.interface.commands.stats import run_stats
    from verifyci.storage.graph_store import GraphStore
    from verifyci.storage.revision import create_revision
    weird = tmp_path / "weird #dir"
    weird.mkdir()
    db = str(weird / "v.db")
    store = GraphStore(db)
    try:
        store.insert_revision(create_revision(repository_id="r", files=[("a.py", "h")]))
    finally:
        store.close()
    stats = run_stats(db)
    assert stats["revisions"] == 1, stats


def test_probe_stats_missing_db_has_error(tmp_path):
    from verifyci.interface.commands.stats import run_stats
    r = run_stats(str(tmp_path / "nope.db"))
    assert "error" in r, r


def test_probe_load_graph_missing_no_create(tmp_path):
    from verifyci.interface.commands.graph_loader import load_graph
    db = str(tmp_path / "missing.db")
    assert load_graph(db) == (None, {}, [])
    assert not os.path.exists(db)


def test_probe_run_query_missing_db(tmp_path):
    from verifyci.interface.commands.query import run_query
    db = str(tmp_path / "missing.db")
    r = run_query("q", db_path=db)
    assert r.get("error") == "db_not_found", r
    assert r["results"] == []
    assert not os.path.exists(db)


def test_probe_run_task_missing_db(tmp_path):
    from verifyci.interface.commands.run import run_task
    db = str(tmp_path / "missing.db")
    r = run_task("t", db_path=db)
    assert r.get("error") == "db_not_found", r
    assert not os.path.exists(db)


def test_probe_run_ingest_missing_repo(tmp_path):
    import pytest
    from verifyci.interface.commands.ingest import run_ingest
    ghost = str(tmp_path / "ghost")
    with pytest.raises(FileNotFoundError):
        run_ingest(ghost)
    assert not (tmp_path / "ghost").exists()


def test_probe_fastmcp_missing_db_no_create(tmp_path):
    from verifyci.interface.fastmcp_server import create_fastmcp_server
    db = str(tmp_path / "missing.db")
    create_fastmcp_server(db)
    assert not os.path.exists(db)
