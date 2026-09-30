"""Probe: decorator call attribution must not depend on id(node) stability.

py-tree-sitter wrapper objects are recreated per access (``node.parent`` /
``node.child(i)`` return distinct objects for the same underlying node), so
``id(node)`` keys are unstable and recyclable. ``parents`` /
``decorated_sites`` must key on ``(type, start_byte, end_byte)`` instead.
"""
import re
from pathlib import Path

from verifyci.contracts.edge import EdgeType
from verifyci.contracts.entity import EntityType
from verifyci.ingestion.extractor import extract_edges, extract_entities
from verifyci.ingestion.parser import TreeSitterParser


def _ingest(src: bytes):
    parsed = TreeSitterParser().parse("t.py", src, "python")
    entities = extract_entities(parsed, "r", "rev")
    return entities, extract_edges(parsed, entities, "rev")


def test_decorator_call_attributed_once_to_function():
    entities, edges = _ingest(b'@app.route("/x")\ndef f():\n    pass\n')
    by_rev = {e.revision_entity_id: e for e in entities}
    route_edges = [
        e for e in edges
        if e.type == EdgeType.CALLS_UNRESOLVED
        and (e.metadata or {}).get("callee") == "route"
    ]
    # Exactly one decorator edge: no double-count via module-level fallback.
    assert len(route_edges) == 1
    # Attributed to the decorated function, not the module.
    caller = by_rev.get(route_edges[0].src_entity_id)
    assert caller is not None and caller.name == "f"
    assert caller.type == EntityType.FUNCTION


def test_extractor_uses_no_id_object_keys():
    src = Path(__file__).resolve().parents[2] / "verifyci" / "ingestion" / "extractor.py"
    text = src.read_text(encoding="utf-8")
    assert not re.search(r"(?<![\w])id\s*\(", text), "extractor still keys nodes by id()"
