"""Structured JSONL query and performance logger.

Records query operations, latency, result counts, and caller context with
size-capped atomic rotation to prevent unbounded log growth.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import time
from typing import Any

DEFAULT_MAX_LOG_BYTES = 10 * 1024 * 1024  # 10 MB

#: Queries are operator-typed code search: they routinely contain pasted
#: secrets and proprietary snippets. The log is an operational record, not
#: an evidence bundle, so entries carry a truncated query plus an explicit
#: flag — never unbounded verbatim text. (Full secret scrubbing at this
#: boundary would couple observability to the secrets engine; truncation
#: plus owner-only file mode bounds the exposure instead.)
MAX_LOGGED_QUERY_CHARS = 500


class QueryLogger:
    """Thread-safe append-only structured query logger with single-generation rotation."""

    def __init__(self, log_path: str | Path, max_bytes: int = DEFAULT_MAX_LOG_BYTES):
        self.log_path = Path(log_path).resolve()
        self.max_bytes = max_bytes

    def _maybe_rotate(self) -> None:
        """Rotate querylog.jsonl to querylog.jsonl.1 if size exceeds max_bytes."""
        try:
            if self.log_path.exists() and self.log_path.stat().st_size >= self.max_bytes:
                backup = self.log_path.with_name(self.log_path.name + ".1")
                # os.replace handles atomic overwrite on POSIX and modern Windows
                os.replace(str(self.log_path), str(backup))
        except OSError:
            # Tolerant of concurrent file operations
            pass

    def log_query(
        self,
        query: str,
        caller: str = "cli",
        duration_ms: float = 0.0,
        results_count: int = 0,
        status: str = "ok",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Append a query log entry in structured JSONL format."""
        truncated = len(query) > MAX_LOGGED_QUERY_CHARS
        entry = {
            "ts": time.time(),
            "query": query[:MAX_LOGGED_QUERY_CHARS],
            "query_truncated": truncated,
            "caller": caller,
            "duration_ms": round(duration_ms, 3),
            "results_count": results_count,
            "status": status,
        }
        if metadata:
            entry["metadata"] = metadata

        line = json.dumps(entry, ensure_ascii=False) + "\n"
        self._maybe_rotate()

        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            fresh = not self.log_path.exists()
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)
            if fresh:
                # Owner-only on creation: the log routinely holds code
                # snippets. Best-effort on platforms without POSIX modes.
                try:
                    os.chmod(self.log_path, 0o600)
                except OSError:
                    pass
        except OSError:
            pass
