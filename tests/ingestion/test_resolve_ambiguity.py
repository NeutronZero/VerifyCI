"""Intra-file call resolution must not guess.

Several same-named candidates with no scope match and no unique
top-level fallback emit CALLS_UNRESOLVED (the post-build resolver links
only globally-unique names); a wrong link invents impact, a missing one
merely undercounts it.
"""
from verifyci.contracts.edge import EdgeType
from verifyci.ingestion.extractor import extract_edges, extract_entities
from verifyci.ingestion.parser import TreeSitterParser


def _edges(source: bytes):
    parsed = TreeSitterParser().parse("a.py", source, "python")
    ents = extract_entities(parsed, "repo", "rev1")
    return extract_edges(parsed, ents, "rev1")


def test_ambiguous_scoped_names_are_unresolved():
    src = (b"class App:\n    def load(self):\n        pass\n"
           b"class Util:\n    def load(self):\n        pass\n"
           b"def worker():\n    load()\n")
    edges = _edges(src)
    assert any(e.type == EdgeType.CALLS_UNRESOLVED
               and (e.metadata or {}).get("callee") == "load" for e in edges)
    assert not [e for e in edges if e.type == EdgeType.CALLS]


def test_single_candidate_still_resolves():
    src = b"def helper():\n    pass\ndef user():\n    helper()\n"
    edges = _edges(src)
    assert len([e for e in edges if e.type == EdgeType.CALLS]) == 1
    assert not [e for e in edges if e.type == EdgeType.CALLS_UNRESOLVED]


def test_unique_top_level_fallback_still_resolves():
    src = (b"def load():\n    pass\n"
           b"class App:\n    def load(self):\n        pass\n"
           b"def worker():\n    load()\n")
    edges = _edges(src)
    assert len([e for e in edges if e.type == EdgeType.CALLS]) == 1
    assert not [e for e in edges if e.type == EdgeType.CALLS_UNRESOLVED]
