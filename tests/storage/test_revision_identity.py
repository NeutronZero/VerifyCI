"""Revision identity contract (probes).

- `revision_id` is pure content identity: repository_id + full file
  manifest + ingestion config. Commit id and parent lineage are ingest
  metadata, never inputs to the content hash.
- Revision rows are immutable: re-ingesting identical content appends a
  new ingest record, it does not rewrite the stored revision row.
- Lineage lives in the append-only `ingests` chain, so a revert (old
  content reappearing) cannot create a parent cycle and `latest` still
  follows the most recent ingest.
"""
import os
import shutil
import sqlite3
import time

from verifyci.contracts.revision import Ingest, Revision
from verifyci.interface.commands.init import run_init
from verifyci.interface.commands.ingest import run_ingest
from verifyci.storage.graph_store import GraphStore
from verifyci.storage.revision import canonical_manifest, create_revision


def _files():
    return [("b.py", "h2"), ("a.py", "h1")]


# --- content identity ------------------------------------------------------

def test_same_content_different_commits_same_revision_id():
    r1 = create_revision("repo", commit_id="abc", files=_files())
    r2 = create_revision("repo", commit_id="def", files=_files())
    assert r1.revision_id == r2.revision_id
    assert r1.source_hash == r2.source_hash


def test_same_content_different_parent_same_revision_id():
    r1 = create_revision("repo", parent_revision_id="p1", files=_files())
    r2 = create_revision("repo", parent_revision_id="p2", files=_files())
    assert r1.revision_id == r2.revision_id


def test_content_change_new_id():
    r1 = create_revision("repo", files=_files())
    r2 = create_revision("repo", files=[("a.py", "CHANGED"), ("b.py", "h2")])
    assert r1.revision_id != r2.revision_id


def test_repository_scopes_identity():
    assert create_revision("repoA", files=_files()).revision_id != \
        create_revision("repoB", files=_files()).revision_id


def test_manifest_excludes_commit_and_parent():
    raw = canonical_manifest("repo", "abc", "p1", _files())
    import json
    parsed = json.loads(raw)
    assert "commit_id" not in parsed
    assert "parent_revision_id" not in parsed
    assert [f["path"] for f in parsed["files"]] == ["a.py", "b.py"]


def test_commit_recorded_as_metadata():
    r = create_revision("repo", commit_id="abc", parent_revision_id="p1", files=_files())
    assert r.commit_id == "abc"
    assert r.parent_revision_id == "p1"


# --- immutability + lineage ------------------------------------------------

def test_identical_reinsert_does_not_rewrite_row(tmp_path):
    store = GraphStore(str(tmp_path / "t.db"))
    now = time.time()
    try:
        r1 = create_revision("repo", files=_files())
        store.insert_revision(Revision(r1.revision_id, "repo", None, None,
                                       r1.source_hash, now, r1.ingestion_config_hash))
        # Second insert of the same content id with a parent must not
        # overwrite the stored row's parent.
        store.insert_revision(Revision(r1.revision_id, "repo", "c2", "SOMEPARENT",
                                       r1.source_hash, now + 5, r1.ingestion_config_hash))
        row = store.conn.execute(
            "SELECT parent_revision_id, commit_id FROM revisions WHERE revision_id = ?",
            (r1.revision_id,)).fetchone()
        assert row[0] is None
        assert row[1] is None
    finally:
        store.close()


def test_latest_tracks_ingest_chain(tmp_path):
    store = GraphStore(str(tmp_path / "t.db"))
    now = time.time()
    try:
        rA = create_revision("repo", files=[("a.py", "hA")])
        rB = create_revision("repo", files=[("a.py", "hB")])
        store.insert_revision(rA)
        store.insert_ingest(Ingest("i1", rA.revision_id, "repo", None, None, now))
        store.insert_revision(rB)
        store.insert_ingest(Ingest("i2", rB.revision_id, "repo", rA.revision_id, "c2", now + 1))
        assert store.latest_revision_id("repo") == rB.revision_id
        # Revert: A reappears, new ingest, latest moves back to A.
        store.insert_ingest(Ingest("i3", rA.revision_id, "repo", rB.revision_id, "c3", now + 2))
        assert store.latest_revision_id("repo") == rA.revision_id
    finally:
        store.close()


# --- live end-to-end -------------------------------------------------------

def _fresh(tmp_path):
    repo = tmp_path / "demo"
    shutil.copytree("samples/test-repo", repo)
    run_init(str(repo))
    return str(repo)


def _revision_rows(db):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            "SELECT revision_id, parent_revision_id, commit_id FROM revisions").fetchall()
    finally:
        conn.close()


def _ingest_rows(db):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            "SELECT revision_id, parent_ingest_id, commit_id FROM ingests ORDER BY timestamp").fetchall()
    finally:
        conn.close()


def test_reingest_same_state_no_new_revision_row(tmp_path):
    repo = _fresh(tmp_path)
    db = os.path.join(repo, ".verifyci", "verifyci.db")
    a = run_ingest(repo)["revision_id"]
    b = run_ingest(repo)["revision_id"]
    assert a == b
    assert len(_revision_rows(db)) == 1
    assert len(_ingest_rows(db)) == 2


def test_different_commit_same_tree_one_revision(tmp_path):
    repo = _fresh(tmp_path)
    db = os.path.join(repo, ".verifyci", "verifyci.db")
    r1 = run_ingest(repo, commit_id="c1")["revision_id"]
    r2 = run_ingest(repo, commit_id="c2")["revision_id"]
    assert r1 == r2
    assert len(_revision_rows(db)) == 1
    commits = {row[2] for row in _ingest_rows(db)}
    assert commits == {"c1", "c2"}


def test_revert_has_no_parent_cycle(tmp_path):
    repo = _fresh(tmp_path)
    db = os.path.join(repo, ".verifyci", "verifyci.db")
    app = os.path.join(repo, "src", "app.py")
    orig = open(app, encoding="utf-8").read()

    a = run_ingest(repo)["revision_id"]
    open(app, "w", encoding="utf-8").write(orig + "\n# state B\n")
    b = run_ingest(repo)["revision_id"]
    open(app, "w", encoding="utf-8").write(orig)
    a2 = run_ingest(repo)["revision_id"]

    assert a2 == a and b != a
    parents = {row[0]: row[1] for row in _revision_rows(db)}
    # No self/cycle in the stored revision graph.
    for start in parents:
        seen, node, steps = set(), start, 0
        while node and node in parents and steps < 50:
            assert node not in seen, "parent cycle"
            seen.add(node)
            node = parents[node]
            steps += 1
    # Stored content rows stay immutable: the first A row keeps parent None.
    first_a = [row for row in _revision_rows(db) if row[0] == a]
    assert len(first_a) == 1 and first_a[0][1] is None
    # Latest follows the revert.
    conn = sqlite3.connect(db)
    try:
        from verifyci.storage.graph_store import latest_revision_id
        assert latest_revision_id(conn, "demo") == a
    finally:
        conn.close()


def test_ingest_rows_form_a_chain(tmp_path):
    repo = _fresh(tmp_path)
    db = os.path.join(repo, ".verifyci", "verifyci.db")
    app = os.path.join(repo, "src", "app.py")
    orig = open(app, encoding="utf-8").read()
    run_ingest(repo)
    open(app, "w", encoding="utf-8").write(orig + "\n# B\n")
    run_ingest(repo)
    open(app, "w", encoding="utf-8").write(orig)
    run_ingest(repo)
    rows = _ingest_rows(db)
    assert len(rows) == 3
    assert rows[0][1] is None
    conn = sqlite3.connect(db)
    try:
        chain = conn.execute(
            "SELECT ingest_id, parent_ingest_id FROM ingests ORDER BY timestamp"
        ).fetchall()
    finally:
        conn.close()
    assert chain[0][1] is None
    assert chain[1][1] == chain[0][0]
    assert chain[2][1] == chain[1][0]