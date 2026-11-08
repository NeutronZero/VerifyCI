"""Sandboxed execution boundary for running untrusted parsing and solving in isolated child processes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any


class SandboxError(RuntimeError):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def run_sandboxed(
    worker_module: str,
    payload: dict[str, Any],
    *,
    timeout_seconds: float = 10.0,
    max_memory_mb: int = 512,
) -> dict[str, Any]:
    """Execute a task in a clean isolated child python process exchanging length-prefixed JSON."""
    clean_env = {
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
        "PYTHONHASHSEED": "0",
    }
    input_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    cmd = [sys.executable, "-m", worker_module]

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=clean_env,
        )
        stdout, stderr = proc.communicate(input=input_bytes, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        raise SandboxError("watchdog_interrupted", f"worker timed out after {timeout_seconds}s")
    except Exception as exc:
        raise SandboxError("internal_fault", str(exc))

    if proc.returncode != 0:
        err_msg = stderr.decode("utf-8", "replace").strip()
        raise SandboxError("internal_fault", f"worker exited with code {proc.returncode}: {err_msg}")

    try:
        return json.loads(stdout.decode("utf-8"))
    except Exception as exc:
        raise SandboxError("internal_fault", f"invalid worker output JSON: {exc}")
