from src.ingestion.extractor import extract_edges, extract_entities
from src.ingestion.parser import TreeSitterParser

BANNED = {"calls_indirect", "controls", "flows_to", "sequential", "reaches", "uses", "defines"}
REQUIRED = {"contains", "has_name", "calls_direct", "imports", "inherits", "references"}


def _parse(source: bytes):
    parser = TreeSitterParser()
    parsed = parser.parse("test.py", source, "python")
    entities = extract_entities(parsed, "repo1", "rev1")
    edges = extract_edges(parsed, entities, "rev1")
    return entities, edges


def test_v1_emits_required_subtypes():
    source = (
        b"import os\n\ndef caller():\n    callee()\n\ndef callee():\n    pass\n\n"
        b"class Child(Base):\n    pass\n\nclass Base:\n    pass\n"
    )
    entities, edges = _parse(source)
    subtypes = {e.subtype.value for e in edges if e.subtype}
    assert {"calls_direct", "references", "imports", "has_name"} <= subtypes
    assert "inherits" in subtypes


def test_v1_never_emits_banned_subtypes():
    source = b"def a():\n    b()\n\ndef b():\n    a()\n"
    _, edges = _parse(source)
    subtypes = {e.subtype.value for e in edges if e.subtype}
    assert not (subtypes & BANNED)


def test_module_and_import_entities():
    entities, _ = _parse(b"import os\n\ndef f():\n    pass\n")
    types = {e.type.value for e in entities}
    assert "MODULE" in types
    assert "IMPORT" in types


def test_self_recursion_uses_recursive_subtype():
    entities, edges = _parse(b"def f():\n    f()\n")
    subtypes = {e.subtype.value for e in edges if e.subtype}
    assert "calls_recursive" in subtypes


def test_entities_carry_source_snippet():
    from src.ingestion.extractor import extract_entities
    from src.ingestion.parser import TreeSitterParser
    parsed = TreeSitterParser().parse("t.py", b"def f():\n    return 42\n", "python")
    entities = [e for e in extract_entities(parsed, "r", "rev") if e.name == "f"]
    assert entities and "return 42" in (entities[0].metadata or {}).get("snippet", "")


def test_relative_import_records_module_not_symbol():
    # `from ..config import Config` must attribute the edge to the module
    # (`..config`), never the imported symbol — otherwise forbid_import
    # rules silently miss relative imports.
    from src.contracts.entity import EntityType
    from src.ingestion.extractor import extract_entities
    from src.ingestion.parser import TreeSitterParser
    src = (
        "from ..config import Config\n"
        "from .scaffold import Scaffold\n"
        "from flask import Flask\n"
        "import os\n"
    )
    parsed = TreeSitterParser().parse("x.py", src.encode(), "python")
    imports = sorted(
        e.name for e in extract_entities(parsed, "r", "rev") if e.type == EntityType.IMPORT)
    assert imports == ["..config", ".scaffold", "flask", "os"]


def test_docstring_code_examples_are_not_entities():
    # A regex ground truth would count `ghost`; the AST correctly ignores it.
    # Ground-truth annotation must be AST-aware (or human-read), not regex.
    from src.ingestion.extractor import extract_entities
    from src.ingestion.parser import TreeSitterParser
    src = (
        "def f():\n"
        '    """Example:\n'
        "\n"
        "    .. code-block:: python\n"
        "\n"
        "        def ghost():\n"
        "            pass\n"
        '    """\n'
        "    return 1\n"
    )
    parsed = TreeSitterParser().parse("t.py", src.encode(), "python")
    names = {e.name for e in extract_entities(parsed, "r", "rev")}
    assert "f" in names
    assert "ghost" not in names
