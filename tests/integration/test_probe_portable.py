"""PROBES item 4: portability (posix ids, LF-normalised hashing, utf-8 stdin)."""


def test_probe_collect_uses_posix_separators(tmp_path):
    from verifyci.interface.commands.ingest import _collect
    d = tmp_path / "sub"
    d.mkdir()
    (d / "mod.py").write_text("x = 1\n")
    sources, texts, manifest = _collect(tmp_path)
    rels = [r for r, _, _ in sources] + [r for r, _ in texts] + [p for p, _ in manifest]
    assert rels
    assert all("\\" not in r for r in rels), rels
    assert "sub/mod.py" in rels, rels


def test_probe_source_hash_crlf_insensitive():
    from verifyci.ingestion.parser import compute_source_hash
    assert compute_source_hash(b"a\r\nb\r\n") == compute_source_hash(b"a\nb\n")
    assert compute_source_hash(b"a\rb\r") == compute_source_hash(b"a\nb\n")


def test_probe_read_diff_stdin_utf8(monkeypatch):
    import io
    import sys
    from types import SimpleNamespace
    from verifyci.interface import cli as climod

    def _boom():
        raise AssertionError("locale stdin read used")

    fake = SimpleNamespace(buffer=io.BytesIO(b"\xff\xfe+bad\n"), read=_boom)
    monkeypatch.setattr(sys, "stdin", fake)
    out = climod._read_diff("", "-")
    assert "bad" in out
