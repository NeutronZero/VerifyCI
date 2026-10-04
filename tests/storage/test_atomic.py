import json
from pathlib import Path

from verifyci.storage.atomic import (
    write_bytes_atomic,
    write_json_atomic,
    write_text_atomic,
)


def test_write_bytes_atomic(tmp_path: Path):
    target = tmp_path / "sub" / "data.bin"
    data = b"\x00\x01\x02\xffhello"
    write_bytes_atomic(target, data, sync=True)

    assert target.exists()
    assert target.read_bytes() == data

    # Overwrite atomically
    new_data = b"replaced"
    write_bytes_atomic(target, new_data, sync=True)
    assert target.read_bytes() == new_data


def test_write_text_atomic(tmp_path: Path):
    target = tmp_path / "file.txt"
    text = "hello world\nline 2\n"
    write_text_atomic(target, text, sync=False)

    assert target.read_text(encoding="utf-8") == text


def test_write_json_atomic(tmp_path: Path):
    target = tmp_path / "data.json"
    obj = {"key": "value", "numbers": [1, 2, 3]}
    write_json_atomic(target, obj, indent=2)

    loaded = json.loads(target.read_text(encoding="utf-8"))
    assert loaded == obj
