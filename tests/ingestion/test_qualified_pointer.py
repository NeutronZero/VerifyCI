"""Probe: pointer/reference-returning qualified definitions must emit entities.

``Foo* Foo::create() {}`` nests the ``qualified_identifier`` under a
``pointer_declarator`` (likewise ``reference_declarator`` /
``function_declarator`` wrappers); only inspecting direct children of the
top declarator drops the entity entirely.
"""
from verifyci.contracts.entity import EntityType
from verifyci.ingestion.extractor import extract_entities
from verifyci.ingestion.parser import TreeSitterParser


def _funcs(src: bytes):
    parsed = TreeSitterParser().parse("x.cpp", src, "cpp")
    return [e for e in extract_entities(parsed, "r", "rev")
            if e.type in (EntityType.FUNCTION, EntityType.METHOD)]


def test_pointer_return_qualified_definition():
    funcs = _funcs(b"Foo* Foo::create() { return 0; }\n")
    assert [(e.name, (e.metadata or {}).get("scope")) for e in funcs] == [("create", "Foo")]


def test_reference_return_qualified_definition():
    funcs = _funcs(b"Foo& Foo::create() { return *this; }\n")
    assert [(e.name, (e.metadata or {}).get("scope")) for e in funcs] == [("create", "Foo")]
