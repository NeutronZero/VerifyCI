
from verifyci.ingestion.language import detect_language
from verifyci.ingestion.parser import TreeSitterParser, compute_source_hash
from verifyci.ingestion.extractor import extract_entities, extract_edges


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
    from verifyci.interface.commands.ingest import _collect
    (tmp_path / "venv").mkdir()
    # A real virtualenv carries pyvenv.cfg; detection is marker-based now,
    # not name-based (a source dir merely *named* venv is not a venv).
    (tmp_path / "venv" / "pyvenv.cfg").write_text("home = /usr\n")
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


def test_collect_includes_markerless_venv_named_dir(tmp_path):
    # Deliberate: a directory named `venv` without pyvenv.cfg is ordinary
    # source, not a virtualenv, and is ingested.
    from verifyci.interface.commands.ingest import _collect
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "junk.py").write_text("x = 1\n")
    sources, _, _ = _collect(tmp_path)
    assert any("venv" in rel for rel, _, _ in sources)


def test_pathological_nesting_falls_back_to_module(tmp_path):
    # 2000-deep nesting exhausts the recursive walker (tree-sitter caps
    # with ERROR nodes first, then extraction blows the Python stack):
    # one hostile file must be recorded and skipped, never abort the run.
    import pytest
    from verifyci.interface.commands.ingest import run_ingest
    lines = []
    for i in range(2000):
        lines.append("    " * i + f"def f{i}():")
    lines.append("    " * 2000 + "pass")
    (tmp_path / "deep.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    totals = run_ingest(str(tmp_path))
    assert any("deep.py" in p for p in totals["parse_errors"])
    assert totals["files"] == 2
    with pytest.raises(RecursionError):
        from verifyci.ingestion.extractor import extract_entities
        from verifyci.ingestion.parser import TreeSitterParser
        src = ("\n".join(lines) + "\n").encode()
        extract_entities(TreeSitterParser().parse("deep.py", src, "python"),
                         "r", "rev")
