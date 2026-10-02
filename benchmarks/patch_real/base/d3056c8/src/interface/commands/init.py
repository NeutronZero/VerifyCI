from pathlib import Path

from src.storage.graph_store import GraphStore


def run_init(path: str) -> str:
    db_path = str(Path(path) / ".verifyci" / "verifyci.db")
    store = GraphStore(db_path)
    store.close()
    return db_path
