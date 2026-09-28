"""Extraction benchmark: ingest sample repo, measure precision/recall."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ingestion.parser import TreeSitterParser
from src.ingestion.extractor import extract_entities, extract_edges
from src.contracts.entity import EntityType

REPO_PATH = Path(__file__).parent.parent / "samples" / "test-repo"

GROUND_TRUTH = {
    "src/auth.py": [
        ("authenticate", EntityType.FUNCTION),
        ("logout", EntityType.FUNCTION),
        ("AuthService", EntityType.CLASS),
        ("login", EntityType.METHOD),
        ("validate_token", EntityType.METHOD),
    ],
    "src/database.py": [
        ("connect", EntityType.FUNCTION),
        ("query", EntityType.FUNCTION),
        ("Database", EntityType.CLASS),
        ("__init__", EntityType.METHOD),
        ("execute", EntityType.METHOD),
    ],
    "src/app.py": [
        ("main", EntityType.FUNCTION),
    ],
}


SCORED_TYPES = {EntityType.FUNCTION, EntityType.METHOD, EntityType.CLASS}


def run_benchmark():
    parser = TreeSitterParser()
    tp = fp = fn = 0
    extracted = {}
    totals = {"entities": 0, "files": 0}

    for py_file in REPO_PATH.rglob("*.py"):
        source = py_file.read_bytes()
        rel_path = str(py_file.relative_to(REPO_PATH)).replace("\\", "/")
        parsed = parser.parse(str(py_file), source, "python")
        entities = extract_entities(parsed, "test-repo", "rev1")
        totals["entities"] += len(entities)
        totals["files"] += 1
        extracted[rel_path] = [(e.name, e.type) for e in entities
                               if e.type in SCORED_TYPES]

    for rel_path, truth in GROUND_TRUTH.items():
        found = extracted.get(rel_path, [])
        found_pairs = {(name, etype) for name, etype in found}
        truth_pairs = set(truth)

        for name, etype in truth:
            if (name, etype) in found_pairs:
                tp += 1
            else:
                fn += 1
                print(f"  FN: {rel_path}:{name} ({etype.value})")

        for name, etype in found:
            if (name, etype) not in truth_pairs:
                fp += 1
                print(f"  FP: {rel_path}:{name} ({etype.value})")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    print(f"\nResults: TP={tp} FP={fp} FN={fn}")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")
    print(f"Scored {totals['entities']} raw entities across {totals['files']} files "
          f"(MODULE/IMPORT/PARAMETER out of ground-truth scope)")
    return precision, recall


if __name__ == "__main__":
    run_benchmark()
