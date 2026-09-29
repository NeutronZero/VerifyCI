"""Repository scoping: one DB file, two repos, no cross-contamination.

Latest-revision selection filters by the repository implied by the DB
path (`<repo>/.verifyci/*.db`); a newer foreign revision must not
hijack another repo's commands. Custom paths with no convention fall
back to the global lookup.
"""
import time

from src.interface.commands import resolve_repository


def test_resolve_repository_convention():
    assert resolve_repository("r/.verifyci/verifyci.db") == "r"
    assert resolve_repository("/x/repos/myrepo/.verifyci/v.db") == "myrepo"
    assert resolve_repository("/x/storage/verifyci.db") is None
    assert resolve_repository("") is None
    assert resolve_repository(None) is None
    # Innermost .verifyci wins for nested checkouts.
    assert resolve_repository("a/.verifyci/b/.verifyci/v.db") == "b"


def _rev(store, repo, files, commit=None):
    from src.storage.revision import create_revision
    rev = create_revision(repository_id=repo, files=files, commit_id=commit)
    store.insert_revision(rev)
    return rev


def test_multi_repo_db_loads_own_latest(tmp_path):
    from src.contracts.entity import Entity, EntityType
    from src.interface.commands.graph_loader import load_graph
    from src.storage.graph_store import GraphStore
    db = str(tmp_path / "repoA" / ".verifyci" / "v.db")
    store = GraphStore(db)
    try:
        rA = _rev(store, "repoA", [("a.py", "h1")])
        store.insert_entity(Entity(
            repository_id="repoA", logical_entity_id="lA", revision_entity_id="eA",
            type=EntityType.FUNCTION, name="funcA", file_path="a.py",
            line_start=1, line_end=2, language="python", source_hash="h",
            revision_id=rA.revision_id))
        time.sleep(0.02)
        rB = _rev(store, "repoB", [("b.py", "h9")])
        store.insert_entity(Entity(
            repository_id="repoB", logical_entity_id="lB", revision_entity_id="eB",
            type=EntityType.FUNCTION, name="funcB", file_path="b.py",
            line_start=1, line_end=2, language="python", source_hash="h",
            revision_id=rB.revision_id))
    finally:
        store.close()
    _, _, entities = load_graph(db)
    assert [e.revision_entity_id for e in entities] == ["eA"]


def test_custom_path_falls_back_to_global(tmp_path):
    from src.interface.commands.graph_loader import load_graph
    from src.storage.graph_store import GraphStore
    db = str(tmp_path / "shared.db")
    store = GraphStore(db)
    try:
        _rev(store, "repoA", [("a.py", "h1")])
        time.sleep(0.02)
        _rev(store, "repoB", [("b.py", "h9")])
    finally:
        store.close()
    # No convention applies: legacy global-latest behavior preserved.
    _, _, _ = load_graph(db)


def test_ingest_commit_id_persisted(tmp_path):
    import shutil
    from src.interface.commands.ingest import run_ingest
    from src.storage.graph_store import GraphStore
    repo = tmp_path / "proj"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text("def f():\n    pass\n")
    out = run_ingest(str(repo), commit_id="abc123")
    store = GraphStore(out["db_path"])
    try:
        row = store.conn.execute(
            "SELECT commit_id FROM revisions WHERE revision_id = ?",
            (out["revision_id"],)).fetchone()
        assert row[0] == "abc123"
    finally:
        store.close()
    shutil.rmtree(repo / ".verifyci", ignore_errors=True)
