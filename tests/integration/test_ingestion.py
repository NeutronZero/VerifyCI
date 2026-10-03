
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


def test_c_has_error_alone_is_not_a_parse_error(tmp_path):
    """tree-sitter-c emits ERROR nodes on idiomatic kernel C.

    kernel/sched/core.c carries 263 error-or-missing nodes (195 ERROR +
    68 MISSING) — one ERROR span covering the entire file — and still extracts 426 functions at full recall. Reporting
    `has_error` as a parse error made a healthy file look broken, so for
    C/C++ only `has_error AND zero entities` counts as a parse error.
    """
    from verifyci.interface.commands.ingest import run_ingest

    # `asmlinkage` in declaration position is an ERROR for tree-sitter-c
    # but the function is still recovered.
    (tmp_path / "kern.c").write_text(
        "asmlinkage void baz(struct pt_regs *regs)\n{\n}\n"
        "int main(void)\n{\n\treturn 0;\n}\n", encoding="utf-8")
    totals = run_ingest(str(tmp_path))
    assert totals["files"] == 1
    assert totals["entities"] > 0
    assert "kern.c" not in totals["parse_errors"]
    # the raw signal is still recorded, as data
    assert "kern.c" in totals["partial_parses"]
    assert totals["zero_entity_files"] == 0


def test_c_has_error_with_zero_entities_is_a_parse_error(tmp_path):
    """The gate must still fire when an imperfect parse yields nothing."""
    from verifyci.interface.commands.ingest import run_ingest

    # A stray type-like macro makes the whole translation unit an ERROR
    # span with nothing recoverable inside it.
    (tmp_path / "junk.c").write_text(
        "__read_mostly __read_mostly __read_mostly\n", encoding="utf-8")
    totals = run_ingest(str(tmp_path))
    assert "junk.c" in totals["parse_errors"]
    assert "junk.c" in totals["partial_parses"]
    assert totals["zero_entity_files"] == 1


def test_python_has_error_remains_a_parse_error(tmp_path):
    """The C gating must not weaken Python, whose grammar does not emit
    whole-file ERROR spans on valid input."""
    from verifyci.interface.commands.ingest import run_ingest

    (tmp_path / "broken.py").write_text(
        "def bad(:\n    x = = 1\n  ][\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("def ok():\n    return 1\n", encoding="utf-8")
    totals = run_ingest(str(tmp_path))
    assert any("broken.py" in p for p in totals["parse_errors"])
    assert not any("ok.py" in p for p in totals["parse_errors"])
