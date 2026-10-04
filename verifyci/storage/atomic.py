"""Crash-safe atomic file operations.

Provides atomic write routines using same-directory temporary file staging
and atomic replacement (os.replace). Features optional fsync durability
and exponential-backoff retries for transient Windows file-locking conditions.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any

_WINDOWS_RETRY_DELAYS = (0.01, 0.05, 0.2)


def _atomic_replace(tmp_path: str, target_path: str) -> None:
    """Replace target_path with tmp_path, retrying on transient Windows locks."""
    for delay in _WINDOWS_RETRY_DELAYS:
        try:
            os.replace(tmp_path, target_path)
            return
        except (PermissionError, FileExistsError):
            time.sleep(delay)
    # Final attempt (raises if still locked)
    os.replace(tmp_path, target_path)


def write_bytes_atomic(target_path: str | Path, data: bytes, sync: bool = True) -> None:
    """Atomically write binary data to target_path."""
    target = Path(target_path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=target.parent, prefix=".tmp_atomic_")
    try:
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(data)
            f.flush()
            if sync:
                os.fsync(f.fileno())
        _atomic_replace(tmp_path, str(target))
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass
        raise


def write_text_atomic(target_path: str | Path, text: str, encoding: str = "utf-8", sync: bool = False) -> None:
    """Atomically write text data to target_path."""
    write_bytes_atomic(target_path, text.encode(encoding), sync=sync)


def write_json_atomic(target_path: str | Path, obj: Any, indent: int = 2, sync: bool = True) -> None:
    """Atomically serialize and write an object to a formatted JSON file."""
    data = json.dumps(obj, indent=indent, ensure_ascii=False) + "\n"
    write_bytes_atomic(target_path, data.encode("utf-8"), sync=sync)
