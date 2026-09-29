from fastapi.testclient import TestClient

from src.interface.http import MAX_DIFF_CHARS, MAX_K, app


def _client():
    return TestClient(app)


def test_health_needs_no_auth(monkeypatch):
    monkeypatch.setenv("ACI_API_TOKEN", "s3cret")
    assert _client().get("/health").status_code == 200


def test_search_rejects_huge_k():
    r = _client().get("/search", params={"q": "x", "k": MAX_K + 1})
    assert r.status_code == 422


def test_verify_rejects_oversize_diff():
    r = _client().post("/verify/diff", json={"diff": "x" * (MAX_DIFF_CHARS + 1)})
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


def test_no_token_set_means_open(monkeypatch):
    monkeypatch.delenv("ACI_API_TOKEN", raising=False)
    assert _client().get("/search", params={"q": "x", "k": 1}).status_code == 200
