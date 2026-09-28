"""Wiring tests for IncrementalParser. No tree-sitter dependency needed:
fake parsers stand in for the real binding and assert old_tree passthrough.
"""
from src.ingestion.incremental import IncrementalParser


class FakeTree:
    def __init__(self):
        self.edits = []

    def edit(self, *args):
        self.edits.append(args)


class FakeRawParser:
    def __init__(self):
        self.calls = []
        self._next = FakeTree()

    def parse(self, source, old_tree=None):
        self.calls.append((source, old_tree))
        tree = FakeTree()
        return tree


class FakeTreeSitterParser:
    def __init__(self, raw):
        self._raw = raw
        self.requested_languages = []

    def raw_parser(self, language):
        self.requested_languages.append(language)
        return self._raw


def _wired(language="python"):
    inc = IncrementalParser(language)
    raw = FakeRawParser()
    inc._parser = FakeTreeSitterParser(raw)
    return inc, raw


def test_first_parse_passes_no_old_tree():
    inc, raw = _wired()
    tree = inc.parse(b"def f(): pass")
    assert tree is inc.old_tree
    assert raw.calls == [(b"def f(): pass", None)]


def test_second_parse_reuses_old_tree():
    inc, raw = _wired()
    first = inc.parse(b"def f(): pass")
    second = inc.parse(b"def f(): pass\n")
    assert second is inc.old_tree
    assert raw.calls[1] == (b"def f(): pass\n", first)


def test_uses_configured_language():
    inc, raw = _wired(language="c")
    inc.parse(b"int x;")
    assert inc._parser.requested_languages == ["c"]


def test_edit_forwarded_to_current_tree():
    inc, raw = _wired()
    inc.parse(b"abc")
    inc.edit(0, 1, 2, (0, 0), (0, 1), (0, 2))
    assert inc.old_tree.edits == [(0, 1, 2, (0, 0), (0, 1), (0, 2))]


def test_edit_without_tree_is_noop():
    inc, _ = _wired()
    inc.edit(0, 1, 2, (0, 0), (0, 1), (0, 2))
