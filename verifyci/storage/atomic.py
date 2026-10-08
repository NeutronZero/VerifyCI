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


def _fsync_dir(dir_path: str) -> None:
    """Persist the directory entry itself (POSIX crash safety).

    fsync on the file guarantees content; without fsync on the parent
    directory, a crash can still lose the rename. Best-effort on
    platforms without directory fsync (Windows raises) — the atomic
    replace itself is unaffected.
    """
    try:
        fd = os.open(dir_path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_bytes_atomic(target_path: str | Path, data: bytes, sync: bool = True) -> None:
    """Atomically write binary data to target_path.

    P3: uses absolute() rather than resolve() so a symlinked target path
    is replaced itself instead of writing through the link; preserves the
    existing target's permission bits (mkstemp creates 0600, which used to
    leak through the replace); fsyncs the parent directory after replace.
    """
    target = Path(target_path).absolute()
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing_mode = target.stat().st_mode & 0o777 if target.exists() else None
    except OSError:
        existing_mode = None
    tmp_fd, tmp_path = tempfile.mkstemp(dir=target.parent, prefix=".tmp_atomic_")
    try:
        if existing_mode is not None:
            try:
                os.chmod(tmp_path, existing_mode)
            except OSError:
                pass
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(data)
            f.flush()
            if sync:
                os.fsync(f.fileno())
        _atomic_replace(tmp_path, str(target))
        if sync:
            _fsync_dir(str(target.parent))
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass
        raise


def write_text_atomic(target_path: str | Path, text: str, encoding: str = "utf-8", sync: bool = True) -> None:
    """Atomically write text data to target_path (durability on by default,
    matching the bytes/JSON variants)."""
    write_bytes_atomic(target_path, text.encode(encoding), sync=sync)


def write_json_atomic(target_path: str | Path, obj: Any, indent: int = 2, sync: bool = True) -> None:
    """Atomically serialize and write an object to a formatted JSON file."""
    data = json.dumps(obj, indent=indent, ensure_ascii=False) + "\n"
    write_bytes_atomic(target_path, data.encode("utf-8"), sync=sync)
