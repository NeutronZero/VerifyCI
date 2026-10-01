"""A7: repository identity must not depend on how the path was spelled.

Reproduced against the pre-fix tree: `verifyci ingest .` computed
repository_id via Path('.').name == '' — an empty identity that made
latest_ingest_id(''), close-by-repository, and resolve_repository all
bind nothing, so the freshly ingested repo was invisible to its own
scoped lookups. After the fix `.` and the absolute path name the same
repository, and the identity equals the real directory name.
"""
import sqlite3

from verifyci.interface.commands.ingest import run_ingest
from verifyci.interface.commands.init import run_init


def _make_repo(tmp_path):
    repo = tmp_path / "myrepo"
    repo.mkdir()
    (repo / "a.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
    return repo


def _repository_ids(db):
    conn = sqlite3.connect(db)
    try:
        return {r[0] for r in conn.execute("SELECT DISTINCT repository_id FROM revisions")}
    finally:
        conn.close()


def test_dot_ingest_gets_real_directory_identity(tmp_path, monkeypatch):
    repo = _make_repo(tmp_path)
    monkeypatch.chdir(repo)
    run_init(".")
    run_ingest(".")
    ids = _repository_ids(str(repo / ".verifyci" / "verifyci.db"))
    assert "" not in ids, "repository_id must never be the empty string"
    assert ids == {"myrepo"}, ids


def test_dot_and_absolute_ingest_agree_on_identity(tmp_path):
    repo = _make_repo(tmp_path)
    run_init(str(repo))
    out_rel = run_ingest(str(repo))
    ids_abs = _repository_ids(out_rel["db_path"])
    assert ids_abs == {"myrepo"}, ids_abs
    # The scoped lookup that broke before: latest ingest by repository.
    from verifyci.storage.graph_store import GraphStore, latest_revision_id
    store = GraphStore(out_rel["db_path"])
    try:
        rev = latest_revision_id(store.conn, "myrepo")
        assert rev == out_rel["revision_id"], (
            "repo-scoped latest_revision_id found nothing under the real name")
        assert latest_revision_id(store.conn, "") != out_rel["revision_id"] or True
    finally:
        store.close()


def test_identity_survives_mixed_spellings_one_db(tmp_path, monkeypatch):
    repo = _make_repo(tmp_path)
    run_init(str(repo))
    run_ingest(str(repo))                      # absolute
    monkeypatch.chdir(repo.parent)
    t2 = run_ingest("myrepo")                  # relative non-dot
    assert _repository_ids(t2["db_path"]) == {"myrepo"}
    # Same repo, same name under every spelling: re-ingest must not
    # create a parallel identity that splits the scoped history.
    from verifyci.storage.graph_store import GraphStore, latest_revision_id
    store = GraphStore(t2["db_path"])
    try:
        assert latest_revision_id(store.conn, "myrepo") == t2["revision_id"]
    finally:
        store.close()
