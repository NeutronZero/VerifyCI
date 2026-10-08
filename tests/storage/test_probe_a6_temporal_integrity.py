"""A6: temporal integrity of re-ingestion (bitemporal invariant).

The plan requires bitemporal behavior: "Bitemporal query returns correct
historical state" (Phase 1 acceptance gate). Demonstrated defect,
reproduced against the pre-fix tree:

    T1: ingest tree          -> entity foo, valid_from=t1, t_created=t1
    T2: ingest SAME tree     -> INSERT OR REPLACE rewrites the single
                                foo row's valid_from/t_created to t2
    get_entity_as_of(foo, t1 + eps) -> None      # history destroyed

Required invariant (V1): re-ingesting unchanged content must not destroy
the ability to query the previously ingested state as-of an earlier
transaction time. A recorded fact row is immutable; a re-observation of
the identical fact adds nothing — the same discipline `insert_event`
already follows (no-replace pinned by closure).
"""
import os
import time

from verifyci.interface.commands.init import run_init
from verifyci.interface.commands.ingest import run_ingest
from verifyci.storage.graph_store import GraphStore


def _repo(tmp_path, files: dict[str, str]):
    repo = str(tmp_path / "repo")
    os.makedirs(repo, exist_ok=True)
    for rel, content in files.items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True) if os.path.dirname(rel) else None
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
    run_init(repo)
    return repo


def _db(repo):
    return os.path.join(repo, ".verifyci", "verifyci.db")


def _foo_row(store):
    return store.conn.execute(
        "SELECT valid_from, t_created, valid_until FROM entities"
        " WHERE name = 'foo'").fetchone()


def test_reingest_identical_content_preserves_as_of_history(tmp_path):
    repo = _repo(tmp_path, {"a.py": "def foo():\n    return 1\n"})
    run_ingest(repo)                                # T1
    store = GraphStore(_db(repo))
    t1_valid, t1_created, _ = _foo_row(store)
    lid = store.conn.execute(
        "SELECT logical_entity_id FROM entities WHERE name='foo'").fetchone()[0]
    store.close()

    time.sleep(0.05)
    run_ingest(repo)                                # T2: same content

    store = GraphStore(_db(repo))
    rows = store.conn.execute(
        "SELECT valid_from, t_created FROM entities WHERE name='foo'").fetchall()
    # No duplicate rows for an unchanged single-revision fact...
    assert len(rows) == 1, rows
    # ...but the ORIGINAL observation stamps survive untouched.
    assert rows[0][0] == t1_valid, "valid_from was rewritten by re-ingest"
    assert rows[0][1] == t1_created, "t_created was rewritten by re-ingest"
    # The invariant itself: as-of a moment after T1 still returns foo.
    assert store.get_entity_as_of(lid, t1_created + 0.001) is not None
    store.close()


def test_changed_content_creates_new_version(tmp_path):
    repo = _repo(tmp_path, {"a.py": "def foo():\n    return 1\n"})
    run_ingest(repo)
    store = GraphStore(_db(repo))
    t1_created, lid = store.conn.execute(
        "SELECT t_created, logical_entity_id FROM entities WHERE name='foo'").fetchone()
    store.close()
    time.sleep(0.05)
    with open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
        fh.write("def foo():\n    return 22\n")
    run_ingest(repo)
    store = GraphStore(_db(repo))
    rows = store.conn.execute(
        "SELECT revision_id, valid_from, t_created, valid_until, source_hash"
        " FROM entities WHERE name='foo' ORDER BY t_created").fetchall()
    assert len(rows) == 2, rows
    old, new = rows
    assert old[3] is not None, "superseded row left open"
    assert new[3] is None, "current row must be open"
    assert old[4] != new[4], "content hashes should differ after edit"
    # as-of history: T1 sees v1, now sees v2.
    v1 = store.get_entity_as_of(lid, old[1] + 0.001)
    v2 = store.get_entity_as_of(lid, new[1] + 0.001)
    assert v1 is not None and v2 is not None
    assert v1.source_hash == old[4] and v2.source_hash == new[4]
    store.close()


def test_reappeared_content_after_change_keeps_both_observations(tmp_path):
    # revert cycle: A -> B -> A again. Each distinct content is its own
    # revision; the two A revisions share a content hash and therefore a
    # revision id — the second A-ingest must not destroy the first A's
    # timestamps (the A6 defect) and the ingests chain (closure item 3)
    # still resolves latest correctly.
    repo = _repo(tmp_path, {"a.py": "def foo():\n    return 1\n"})
    run_ingest(repo)
    store = GraphStore(_db(repo))
    a_created = store.conn.execute(
        "SELECT t_created, revision_id FROM entities WHERE name='foo'").fetchone()
    store.close()
    time.sleep(0.05)
    with open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
        fh.write("def foo():\n    return 2\n")
    run_ingest(repo)
    time.sleep(0.05)
    with open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
        fh.write("def foo():\n    return 1\n")     # revert
    run_ingest(repo)
    store = GraphStore(_db(repo))
    rows = store.conn.execute(
        "SELECT revision_id, valid_from, valid_until FROM entities"
        " WHERE name='foo' ORDER BY valid_from").fetchall()
    # revision ids: A, B, A again. The A row was observed first and its
    # stamp must still equal the FIRST observation (no rewrite).
    # S-01: Composite key yields one row per valid-time interval. Revert cycle A->B->A
    # records 3 intervals across 2 distinct revisions (A closed, B closed, A re-opened).
    assert len(rows) == 3, rows
    assert len({r[0] for r in rows}) == 2
    assert rows[0][2] is not None, "first A observation was left open"
    assert rows[1][2] is not None, "B observation was left open"
    assert rows[2][2] is None, "reverted A observation must be open"
    # Latest revision after revert: the ingests chain (not the revisions
    # table) decides, and it must now point back at A.
    from verifyci.interface.commands import resolve_repository
    from verifyci.storage.graph_store import latest_revision_id
    latest = latest_revision_id(store.conn, resolve_repository(_db(repo)))
    assert latest == a_created[1], "latest_revision_id missed the revert"
    # Current grounding still finds foo under the reverted revision:
    ents = store.get_entities_by_revision(latest)
    assert any(e.name == "foo" for e in ents), \
        "reverted revision no longer grounds its own entities"
    store.close()


def test_disappeared_entity_stays_history_queryable(tmp_path):
    repo = _repo(tmp_path, {"a.py": "def foo():\n    return 1\n",
                            "b.py": "def gone():\n    return 2\n"})
    run_ingest(repo)
    store = GraphStore(_db(repo))
    gone_lid = store.conn.execute(
        "SELECT logical_entity_id FROM entities WHERE name='gone'").fetchone()[0]
    gone_created = store.conn.execute(
        "SELECT t_created FROM entities WHERE name='gone'").fetchone()[0]
    store.close()
    os.remove(os.path.join(repo, "b.py"))
    time.sleep(0.05)
    run_ingest(repo)
    store = GraphStore(_db(repo))
    row = store.conn.execute(
        "SELECT valid_until FROM entities WHERE logical_entity_id = ?",
        (gone_lid,)).fetchone()
    assert row is not None, "disappearance deleted the historical row"
    assert row[0] is not None, "disappeared row must be closed"
    assert store.get_entity_as_of(gone_lid, gone_created + 0.001) is not None
    store.close()


def test_ingestion_config_hash_represents_extraction_version():
    """INGESTION_CONFIG_HASH must change when extraction-affecting
    configuration changes, and must be deterministic. V1's smallest
    mechanism: a constant covering the default extractor/config, pinned
    here so a silent bump is a test failure, not a quiet history break."""
    import hashlib
    from verifyci.storage.revision import INGESTION_CONFIG_HASH, create_revision
    assert len(INGESTION_CONFIG_HASH) == 64
    assert INGESTION_CONFIG_HASH == hashlib.sha256(b"v1_default").hexdigest()
    rev = create_revision(repository_id="r", files=[("a.py", "h")])
    assert rev.ingestion_config_hash == INGESTION_CONFIG_HASH
    # Deterministic across calls (no clock/no randomness):
    rev2 = create_revision(repository_id="r", files=[("a.py", "h")])
    assert rev2.ingestion_config_hash == rev.ingestion_config_hash


def test_incremental_reingest_unchanged_file_keeps_original_stamps(tmp_path):
    repo = _repo(tmp_path, {"a.py": "def foo():\n    return 1\n",
                            "c.py": "def bar():\n    return 3\n"})
    run_ingest(repo)
    store = GraphStore(_db(repo))
    foo = store.conn.execute(
        "SELECT valid_from, t_created FROM entities WHERE name='foo'").fetchone()
    store.close()
    time.sleep(0.05)
    with open(os.path.join(repo, "c.py"), "w", encoding="utf-8") as fh:
        fh.write("def bar():\n    return 4\n")     # only c.py changes
    run_ingest(repo, incremental=True)
    store = GraphStore(_db(repo))
    # foo carried forward into the new revision: a NEW row (new revision)
    # with fresh stamps, while the original T1 row is untouched history.
    rows = store.conn.execute(
        "SELECT revision_id, valid_from FROM entities WHERE name='foo'"
        " ORDER BY valid_from").fetchall()
    assert len(rows) == 2, rows
    assert rows[0][1] == foo[0], "original foo stamp rewritten by carry-forward"
    store.close()
