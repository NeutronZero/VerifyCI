from verifyci.ingestion.extractor import extract_edges, extract_entities
from verifyci.ingestion.parser import TreeSitterParser

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
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    parsed = TreeSitterParser().parse("t.py", b"def f():\n    return 42\n", "python")
    entities = [e for e in extract_entities(parsed, "r", "rev") if e.name == "f"]
    assert entities and "return 42" in (entities[0].metadata or {}).get("snippet", "")


def test_relative_import_records_module_not_symbol():
    # `from ..config import Config` must attribute the edge to the module
    # (`..config`), never the imported symbol — otherwise forbid_import
    # rules silently miss relative imports.
    from verifyci.contracts.entity import EntityType
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
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


def test_bare_relative_import_pinned():
    # `from . import thing`: no module name exists in the statement, so the
    # bare level (".") is recorded rather than inventing package resolution.
    from verifyci.contracts.entity import EntityType
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    parsed = TreeSitterParser().parse("x.py", b"from . import thing\n", "python")
    imports = sorted(
        e.name for e in extract_entities(parsed, "r", "rev") if e.type == EntityType.IMPORT)
    assert imports == ["."]


def test_struct_reference_is_not_an_entity():
    # `struct Point *p;` mentions the type without defining it: elaborated
    # type specifiers and forward declarations emit nothing. Only a body
    # (field_declaration_list) makes a CLASS.
    from verifyci.contracts.entity import EntityType
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    src = (b"struct Point { int x; };\n"
           b"struct Point *p;\n"
           b"struct Empty;\n")
    parsed = TreeSitterParser().parse("x.c", src, "c")
    classes = sorted(
        e.name for e in extract_entities(parsed, "r", "rev") if e.type == EntityType.CLASS)
    assert classes == ["Point"]


def test_enum_class_in_c_grammar_is_not_a_function():
    # tree-sitter-c has no `class` keyword, so `enum class X {}` in a .h
    # file (parsed as C) misparses as function_definition with a bare
    # identifier name and no declarator. C/C++ names must come from the
    # declarator, so this emits nothing instead of a phantom FUNCTION.
    from verifyci.contracts.entity import EntityType
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    src = (b"enum class TripReason {\n"
           b"    OVERCURRENT,\n"
           b"    NONE\n"
           b"};\n")
    parsed = TreeSitterParser().parse("x.h", src, "c")
    funcs = [e for e in extract_entities(parsed, "r", "rev")
             if e.type in (EntityType.FUNCTION, EntityType.METHOD)]
    assert funcs == []


def test_overload_definitions_collapse_to_one_entity():
    # Two `write` overloads share (file, name, type, scope) and therefore
    # one logical id; storage keeps first-wins. Documented, not blessed:
    # overloads are invisible to identity, same as same-name redefinitions.
    from verifyci.contracts.entity import EntityType
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    src = (b"void write(uint8_t v) { (void)v; }\n"
           b"void write(const char *s) { (void)s; }\n")
    parsed = TreeSitterParser().parse("x.cpp", src, "cpp")
    funcs = [e for e in extract_entities(parsed, "r", "rev")
             if e.type == EntityType.FUNCTION and e.name == "write"]
    assert len(funcs) == 2  # both emitted...
    assert funcs[0].logical_entity_id == funcs[1].logical_entity_id  # ...one identity


def test_pointer_and_reference_returns_emit_entities():
    # `char *f()` / `T& f()` nest the declarator inside pointer/reference
    # wrappers; the old trio missed them and whole functions vanished.
    from verifyci.contracts.entity import EntityType
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    src = (b"char *getbuf(void) { return 0; }\n"
           b"int &counter(int &c) { return c; }\n")
    parsed = TreeSitterParser().parse("x.cpp", src, "cpp")
    funcs = {e.name: e for e in extract_entities(parsed, "r", "rev")
             if e.type == EntityType.FUNCTION}
    assert set(funcs) == {"getbuf", "counter"}
    params = [e.name for e in extract_entities(parsed, "r", "rev")
              if e.type == EntityType.PARAMETER]
    assert "c" in params


def test_destructor_and_operator_names():
    from verifyci.contracts.entity import EntityType
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    src = (b"class W {\n public:\n  ~W() {}\n"
           b"  bool operator==(const W &o) { return true; }\n};\n")
    parsed = TreeSitterParser().parse("x.cpp", src, "cpp")
    methods = {e.name for e in extract_entities(parsed, "r", "rev")
               if e.type == EntityType.METHOD}
    assert "~W" in methods
    assert "operator==" in methods


def test_multi_import_statement_emits_all_modules():
    from verifyci.contracts.entity import EntityType
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    parsed = TreeSitterParser().parse("x.py", b"import os, sys\n", "python")
    imports = sorted(
        e.name for e in extract_entities(parsed, "r", "rev") if e.type == EntityType.IMPORT)
    assert imports == ["os", "sys"]


def test_splat_params_are_a_known_gap():
    # `*args` / `**kwargs` names live in splat-pattern nodes, not bare
    # identifiers, so variadics emit no PARAMETER entities. Documented,
    # not fixed: PARAMETER rows never seed traversal or gate anything,
    # and extractor.py is frozen-pinned by the latency guard — a repair
    # would go through the dated-exception process with a re-measure
    # decision. Revisit only with evidence that params matter.
    from verifyci.contracts.entity import EntityType
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    parsed = TreeSitterParser().parse(
        "x.py", b"def f(a, *args, b=1, **kwargs):\n    pass\n", "python")
    params = [e.name for e in extract_entities(parsed, "r", "rev")
              if e.type == EntityType.PARAMETER]
    assert params == ["a", "b"]


def test_typedef_names_new_type():
    from verifyci.contracts.entity import EntityType
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    parsed = TreeSitterParser().parse("x.c", b"typedef Bar Baz;\n", "c")
    types = [e.name for e in extract_entities(parsed, "r", "rev")
             if e.type == EntityType.TYPE]
    assert types == ["Baz"]


def test_struct_methods_are_methods():
    from verifyci.contracts.entity import EntityType
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    parsed = TreeSitterParser().parse(
        "x.cpp", b"struct S {\n void m() {}\n};\n", "cpp")
    methods = [e.name for e in extract_entities(parsed, "r", "rev")
               if e.type == EntityType.METHOD]
    assert methods == ["m"]


def test_c_include_emits_import():
    from verifyci.contracts.entity import EntityType
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    parsed = TreeSitterParser().parse(
        "x.c", b'#include <stdio.h>\n#include "util.h"\n', "c")
    imports = sorted(
        e.name for e in extract_entities(parsed, "r", "rev") if e.type == EntityType.IMPORT)
    assert imports == ["stdio.h", "util.h"]


def test_docstring_code_examples_are_not_entities():
    # A regex ground truth would count `ghost`; the AST correctly ignores it.
    # Ground-truth annotation must be AST-aware (or human-read), not regex.
    from verifyci.ingestion.extractor import extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
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
