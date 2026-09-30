"""Ingest a sample repo end-to-end into SQLite (Python + C + Markdown)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from verifyci.ingestion.parser import TreeSitterParser, compute_source_hash, ParsedFile
from verifyci.ingestion.extractor import extract_entities, extract_edges
from verifyci.ingestion.language import INGESTIBLE_EXTENSIONS, detect_language
from verifyci.storage.graph_store import GraphStore
from verifyci.storage.revision import create_revision

SOURCE_EXTS = INGESTIBLE_EXTENSIONS


def ingest(repo_path: str, db_path: str):
    repo = Path(repo_path)

    files = sorted(f for f in repo.rglob("*")
                   if f.is_file() and f.suffix in SOURCE_EXTS
                   and ".verifyci" not in f.parts)
    manifest = [(str(f.relative_to(repo)), compute_source_hash(f.read_bytes())) for f in files]

    store = GraphStore(db_path)

    revision = create_revision(repository_id=repo.name, files=manifest)
    store.insert_revision(revision)
    print(f"Revision: {revision.revision_id}")

    parser = TreeSitterParser()
    total_entities = 0
    total_edges = 0

    with store.batch():
        for path in files:
            source = path.read_bytes()
            rel_path = str(path.relative_to(repo))
            language = detect_language(str(path))

            try:
                parsed = parser.parse(str(path), source, language)
            except ValueError:
                digest = compute_source_hash(source)
                parsed = ParsedFile(file_path=rel_path, source=source,
                                    source_hash=digest, language=language, tree=None)
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
