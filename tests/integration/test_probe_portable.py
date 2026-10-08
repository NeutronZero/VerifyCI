"""PROBES item 4: portability (posix ids, LF-normalised hashing, utf-8 stdin)."""


def test_probe_collect_uses_posix_separators(tmp_path):
    from verifyci.interface.commands.ingest import _collect
    d = tmp_path / "sub"
    d.mkdir()
    (d / "mod.py").write_text("x = 1\n")
    sources, texts, manifest, _oversize, _truncated = _collect(tmp_path)
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

    # Real UTF-8 payload (non-ASCII too): must survive the explicit
    # decode. (The A8 contract change moved BOM-prefixed bytes to
    # BOM-aware decoding, so the utf-8 case is pinned with utf-8 bytes.)
    fake = SimpleNamespace(buffer=io.BytesIO("x = 'café'\n".encode("utf-8")),
                           read=_boom)
    monkeypatch.setattr(sys, "stdin", fake)
    out = climod._read_diff("", "-")
    assert "caf\u00e9" in out


def test_probe_read_diff_powershell_utf16_file(tmp_path):
    """`git diff > patch.txt` under PowerShell writes UTF-16 LE with a
    BOM. Decoded as UTF-8 that is NUL-interleaved garbage grounding
    nothing (fail-closed but unreadable). BOM sniffing keeps the real
    patch real."""
    from verifyci.interface import cli as climod
    patch = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n"
             "@@ -1,1 +1,1 @@\n-x\n+y\n")
    f16 = tmp_path / "patch16.txt"
    f16.write_bytes(b"\xff\xfe" + patch.encode("utf-16-le"))
    got = climod._read_diff("", str(f16))
    assert "+y" in got
    from verifyci.verification.diffmap import parse_diff_files, iter_added_lines
    assert parse_diff_files(got) == ["x.py"]
    assert ("x.py", "y") in iter_added_lines(got)
    # UTF-16 BE BOM as well:
    f16b = tmp_path / "patch16be.txt"
    f16b.write_bytes(b"\xfe\xff" + patch.encode("utf-16-be"))
    assert "+y" in climod._read_diff("", str(f16b))


def test_probe_read_diff_utf8_bom_file(tmp_path):
    from verifyci.interface import cli as climod
    from verifyci.verification.diffmap import parse_diff_files
    patch = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n"
             "@@ -1,1 +1,1 @@\n-x\n+y\n")
    f = tmp_path / "patch.txt"
    f.write_bytes(b"\xef\xbb\xbf" + patch.encode("utf-8"))
    got = climod._read_diff("", str(f))
    assert got.lstrip("\ufeff").startswith("diff --git")
    assert parse_diff_files(got) == ["x.py"]


def test_probe_foreign_bytes_still_garble_not_hallucinate(tmp_path):
    # BOM-less UTF-16 (not the documented PowerShell shape) decodes as
    # utf-8-with-replace: NUL-interleaved garbage that names no files —
    # the pre-existing fail-closed contract, unchanged.
    from verifyci.interface import cli as climod
    from verifyci.verification.diffmap import parse_diff_files
    f = tmp_path / "odd.txt"
    f.write_bytes("+++ b/x.py\n".encode("utf-16-le"))  # no BOM
    got = climod._read_diff("", str(f))
    assert "\x00" in got
    assert parse_diff_files(got) == []
