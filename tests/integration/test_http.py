from fastapi.testclient import TestClient

from verifyci.interface.http import MAX_DIFF_CHARS, MAX_K, app


def _client():
    return TestClient(app)


def test_health_needs_no_auth(monkeypatch):
    monkeypatch.setenv("ACI_API_TOKEN", "s3cret")
    assert _client().get("/health").status_code == 200


def test_search_rejects_huge_k(monkeypatch):
    monkeypatch.setenv('ACI_API_TOKEN', 's3cret')
    r = _client().get('/search', params={'q': 'x', 'k': MAX_K + 1}, headers={'Authorization': 'Bearer s3cret'})
    assert r.status_code == 422


def test_search_rejects_nonpositive_k(monkeypatch):
    # Negative/zero k slices from the end or empties results downstream;
    # the boundary rejects it with 422 before any retrieval runs.
    monkeypatch.setenv('ACI_API_TOKEN', 's3cret')
    c = _client()
    for bad in ("0", "-1"):
        r = c.get('/search', params={'q': 'x', 'k': bad},
                  headers={'Authorization': 'Bearer s3cret'})
        assert r.status_code == 422, bad
    r = c.get('/search', params={'q': 'x', 'k': '1'},
              headers={'Authorization': 'Bearer s3cret'})
    assert r.status_code != 422


def test_verify_rejects_oversize_diff(monkeypatch):
    monkeypatch.setenv('ACI_API_TOKEN', 's3cret')
    r = _client().post('/verify/diff', json={'diff': 'x' * (MAX_DIFF_CHARS + 1)}, headers={'Authorization': 'Bearer s3cret'})
    assert r.status_code == 422


def test_token_required_when_set(monkeypatch):
    monkeypatch.setenv("ACI_API_TOKEN", "s3cret")
    c = _client()
    assert c.get("/stats").status_code == 401
    assert c.get("/search", params={"q": "x"}).status_code == 401
    assert c.post("/verify/diff", json={"diff": "x"}).status_code == 401
    ok = c.get("/stats", headers={"Authorization": "Bearer s3cret"})
    assert ok.status_code in (200, 500)  # auth passed; DB may be missing
    bad = c.get("/stats", headers={"Authorization": "Bearer wrong"})
    assert bad.status_code == 401


def _req(host):
    from fastapi import Request
    scope = {'type': 'http', 'client': (host, 1234)}
    return Request(scope)


def test_require_auth_loopback_allowed(monkeypatch):
    import asyncio
    from verifyci.interface.http import require_auth
    monkeypatch.delenv('ACI_API_TOKEN', raising=False)
    asyncio.run(require_auth(_req('127.0.0.1')))


def test_require_auth_non_loopback_denied(monkeypatch):
    import asyncio
    import pytest
    from fastapi import HTTPException
    from verifyci.interface.http import require_auth
    monkeypatch.delenv('ACI_API_TOKEN', raising=False)
    with pytest.raises(HTTPException) as ei:
        asyncio.run(require_auth(_req('203.0.113.7')))
    assert ei.value.status_code == 401


def test_require_auth_token_correct(monkeypatch):
    import asyncio
    from verifyci.interface.http import require_auth
    monkeypatch.setenv('ACI_API_TOKEN', 's3cret')
    asyncio.run(require_auth(_req('203.0.113.7'), 'Bearer s3cret'))


def test_require_auth_token_wrong(monkeypatch):
    import asyncio
    import pytest
    from fastapi import HTTPException
    from verifyci.interface.http import require_auth
    monkeypatch.setenv('ACI_API_TOKEN', 's3cret')
    with pytest.raises(HTTPException) as ei:
        asyncio.run(require_auth(_req('203.0.113.7'), 'Bearer wrong'))
    assert ei.value.status_code == 401


def test_revise_command_is_gone():
    # `aci revise` inserted contentless revisions that poisoned every
    # latest-revision lookup; commit recording lives on ingest now.
    from typer.testing import CliRunner
    from verifyci.interface.cli import app
    runner = CliRunner()
    assert "revise" not in runner.invoke(app, ["--help"]).output
    assert runner.invoke(app, ["revise", "--commit", "abc"]).exit_code != 0


def test_verify_diff_cli_exit_codes(tmp_path):
    # CI gating: PASS 0, FAIL 1, INCONCLUSIVE 2, INFRA_ERROR 3.
    # (The missing-DB case used to read as INCONCLUSIVE/2 — a broken
    # gate wearing a verdict's clothes; the A5 fix moved it to 3, so
    # this test now pins the valid-empty DB for the 2 case.)
    from typer.testing import CliRunner
    from verifyci.interface.cli import app
    from verifyci.storage.graph_store import GraphStore
    runner = CliRunner()
    db = str(tmp_path / "v.db")
    GraphStore(db).close()  # readable, just empty: a verdict, not infra
    empty = runner.invoke(app, ["verify-diff", "", "--db", db])
    assert empty.exit_code == 2
    missing = runner.invoke(app, ["verify-diff", "", "--db",
                                  str(tmp_path / "ghost.db")])
    assert missing.exit_code == 3, missing.output
    secret = ('diff --git a/s.py b/s.py\n--- a/s.py\n+++ b/s.py\n'
              '@@ -1,0 +1,1 @@\n+password = "hunter2hunter2"\n')
    out = runner.invoke(app, ["verify-diff", secret, "--db", db])
    assert out.exit_code == 1
