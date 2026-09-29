import pytest

from src.ingestion.language import detect_language
from src.ingestion.parser import TreeSitterParser, compute_source_hash
from src.ingestion.extractor import extract_entities, extract_edges
from src.contracts.identity import compute_logical_entity_id, compute_revision_entity_id
from src.contracts.entity import EntityType


def test_detect_language():
    assert detect_language("test.py") == "python"
    assert detect_language("test.c") == "c"
    assert detect_language("test.cpp") == "cpp"
    assert detect_language("test.md") == "markdown"
    assert detect_language("test.txt") == "txt"
    assert detect_language("test.unknown") == "unknown"


def test_compute_source_hash():
    source = b"print('hello')"
    hash1 = compute_source_hash(source)
    hash2 = compute_source_hash(source)
    assert hash1 == hash2
    assert len(hash1) == 64


def test_parser_creates_parsed_file():
    parser = TreeSitterParser()
    source = b"def hello():\n    pass\n"
    parsed = parser.parse("test.py", source, "python")
    assert parsed.file_path == "test.py"
    assert parsed.source == source
    assert parsed.language == "python"
    assert len(parsed.source_hash) == 64


def test_extract_entities_python():
    parser = TreeSitterParser()
    source = b"def hello():\n    pass\n\nclass World:\n    pass\n"
    parsed = parser.parse("test.py", source, "python")
    entities = extract_entities(parsed, "repo1", "rev1")

    names = [e.name for e in entities]
    assert "hello" in names
    assert "World" in names

    for e in entities:
        assert e.repository_id == "repo1"
        assert e.revision_id == "rev1"
        assert len(e.logical_entity_id) == 64
        assert len(e.revision_entity_id) == 64


def test_extract_edges_python():
    parser = TreeSitterParser()
    source = b"def caller():\n    callee()\n\ndef callee():\n    pass\n"
    parsed = parser.parse("test.py", source, "python")
    entities = extract_entities(parsed, "repo1", "rev1")
    edges = extract_edges(parsed, entities, "rev1")

    assert len(edges) > 0
    edge_types = [e.type.value for e in edges]
    assert "CALLS" in edge_types


def test_collect_excludes_venv_and_cache_dirs(tmp_path):
    from src.interface.commands.ingest import _collect
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "junk.py").write_text("x = 1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.py").write_text("x = 1\n")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "junk.py").write_text("x = 1\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "real.py").write_text("x = 1\n")
    sources, _, _ = _collect(tmp_path)
    rels = [rel for rel, _, _ in sources]
    assert any("real.py" in r for r in rels)
    assert not any("venv" in r for r in rels)
    assert not any("node_modules" in r for r in rels)
    assert not any("__pycache__" in r for r in rels)
