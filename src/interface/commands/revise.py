from src.interface.commands import resolve_db
from src.storage.graph_store import GraphStore
from src.storage.revision import create_revision


def run_revise(commit_id: str = "", repository_id: str = "default", db_path: str | None = None) -> dict:
    rev = create_revision(repository_id=repository_id, commit_id=commit_id or None)
    db = resolve_db(db_path)
    store = GraphStore(db)
    try:
        latest = store.get_latest_revision(repository_id)
        if latest is not None and latest.revision_id != rev.revision_id:
            import dataclasses
            rev = dataclasses.replace(rev, parent_revision_id=latest.revision_id)
        store.insert_revision(rev)
        return {"revision_id": rev.revision_id, "commit_id": commit_id,
                "parent_revision_id": rev.parent_revision_id, "db_path": db}
    finally:
        store.close()
