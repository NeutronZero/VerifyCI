"""Ingest a Python repo end-to-end into SQLite."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ingestion.parser import TreeSitterParser, compute_source_hash
from src.ingestion.extractor import extract_entities, extract_edges
from src.ingestion.dependency import extract_dependencies
from src.storage.graph_store import GraphStore
from src.storage.revision import create_revision


def ingest(repo_path: str, db_path: str):
    repo = Path(repo_path)

    py_files = sorted(repo.rglob("*.py"))
    manifest = [(str(f.relative_to(repo)), compute_source_hash(f.read_bytes())) for f in py_files]

    store = GraphStore(db_path)

    revision = create_revision(repository_id=repo.name, files=manifest)
    store.insert_revision(revision)
    print(f"Revision: {revision.revision_id}")

    parser = TreeSitterParser()
    total_entities = 0
    total_edges = 0

    for py_file in py_files:
        source = py_file.read_bytes()
        rel_path = str(py_file.relative_to(repo))

        parsed = parser.parse(str(py_file), source, "python")
        entities = extract_entities(parsed, repo.name, revision.revision_id)
        edges = extract_edges(parsed, entities, revision.revision_id)

        for e in entities:
            store.insert_entity(e)
        for edge in edges:
            store.insert_edge(edge)

        total_entities += len(entities)
        total_edges += len(edges)
        print(f"  {rel_path}: {len(entities)} entities, {len(edges)} edges")

    print(f"\nTotal: {total_entities} entities, {total_edges} edges")
    print(f"DB: {db_path}")
    store.close()


if __name__ == "__main__":
    ingest("samples/test-repo", "storage/verifyci.db")
