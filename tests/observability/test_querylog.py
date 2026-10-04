import json
from pathlib import Path
import pytest

from verifyci.observability.querylog import QueryLogger


def test_querylog_basic(tmp_path: Path):
    log_file = tmp_path / "sub" / "querylog.jsonl"
    logger = QueryLogger(log_file)

    logger.log_query("where is auth?", caller="cli", duration_ms=12.5, results_count=3)
    logger.log_query("who calls login?", caller="mcp", duration_ms=5.1, results_count=1)

    assert log_file.exists()
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2

    entry0 = json.loads(lines[0])
    assert entry0["query"] == "where is auth?"
    assert entry0["caller"] == "cli"
    assert entry0["duration_ms"] == 12.5
    assert entry0["results_count"] == 3
    assert entry0["status"] == "ok"


def test_querylog_rotation(tmp_path: Path):
    log_file = tmp_path / "querylog.jsonl"
    # Set a tiny max_bytes to trigger rotation
    logger = QueryLogger(log_file, max_bytes=100)

    # First entry will be written (~80 bytes)
    logger.log_query("first small query")
    assert log_file.exists()
    backup_file = tmp_path / "querylog.jsonl.1"
    assert not backup_file.exists()

    # Second entry exceeds 100 bytes -> triggers rotation
    logger.log_query("second query that triggers rotation")
    assert backup_file.exists()
    assert log_file.exists()

    # Backup should contain first query
    backup_text = backup_file.read_text(encoding="utf-8")
    assert "first small query" in backup_text

    # Current log should contain second query
    current_text = log_file.read_text(encoding="utf-8")
    assert "second query that triggers rotation" in current_text
