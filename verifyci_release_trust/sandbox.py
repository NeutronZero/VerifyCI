"""Docker Worker Sandbox and Container Lifecycle Management (§15.10 Component C).

Enforces kernel-namespace and filesystem isolation for untrusted candidate execution:
- Read-only root and candidate mounts
- Private PID and IPC namespaces
- Dropped capabilities, no-new-privileges, seccomp, AppArmor
- Local bounded daemon logging
- Monotonic deadline with continuous drain and immediate overflow termination
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import threading
import time
from typing import NamedTuple
import uuid

from verifyci_release_trust.ipc import (
    MAX_IPC_BYTES,
    IPCParseResult,
    parse_strict_ipc_payload,
)

STDOUT_LIMIT = MAX_IPC_BYTES  # 1 MB
STDERR_LIMIT = 262_144        # 256 KB
DEFAULT_TIMEOUT = 120.0       # 2 minutes


class ContainerRunResult(NamedTuple):
    data: dict | None
    verdict: str  # PASS, FAIL, INCONCLUSIVE, ERROR
    error: str | None
    exit_code: int | None
    stdout_bytes: bytes
    stderr_bytes: bytes


class StreamDrainer:
    """Threaded stream reader that records retained bytes and detects overflow."""

    def __init__(self, stream, limit: int):
        self.stream = stream
        self.limit = limit
        self.retained = bytearray()
        self.total_received = 0
        self.overflow = False
        self.error: Exception | None = None
        self.finished = threading.Event()

    def run(self) -> None:
        try:
            while True:
                chunk = self.stream.read(4096)
                if not chunk:
                    break
                self.total_received += len(chunk)
                if len(self.retained) < self.limit:
                    take = min(len(chunk), self.limit - len(self.retained))
                    self.retained.extend(chunk[:take])
                # Strict: overflow occurs ONLY when total bytes exceed limit
                if self.total_received > self.limit:
                    self.overflow = True
        except Exception as exc:
            self.error = exc
        finally:
            try:
                self.stream.close()
            except Exception:
                pass
            self.finished.set()


def verify_active_container_security(cid: str) -> tuple[bool, str | None]:
    """Inspect active container to confirm security controls were applied by the Docker daemon."""
    try:
        proc = subprocess.run(
            ["docker", "inspect", cid, "--format", "{{json .HostConfig}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        cfg = json.loads(proc.stdout)
        if cfg.get("PidMode") not in ("private", ""):
            return False, f"untrusted PidMode: {cfg.get('PidMode')!r}"
        if cfg.get("IpcMode") != "private":
            return False, f"untrusted IpcMode: {cfg.get('IpcMode')!r}"
        if cfg.get("NetworkMode") != "none":
            return False, f"untrusted NetworkMode: {cfg.get('NetworkMode')!r}"
        if not cfg.get("ReadonlyRootfs"):
            return False, "container root filesystem is not read-only"

        sec_opts = cfg.get("SecurityOpt") or []
        if not any("no-new-privileges" in s for s in sec_opts):
            return False, "no-new-privileges security option not active"

        cap_drop = cfg.get("CapDrop") or []
        if not ("ALL" in cap_drop or "all" in cap_drop):
            return False, f"capabilities not fully dropped: {cap_drop}"

        return True, None
    except Exception as exc:
        return False, f"failed to inspect container security profiles: {exc}"


def run_candidate_in_docker(
    candidate_staging: Path,
    case_repo: Path,
    image_digest: str,
    worker_args: list[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> ContainerRunResult:
    """Execute candidate worker inside hardened Docker container with bounded IPC."""
    cid = f"vc-worker-{uuid.uuid4().hex[:12]}"
    create_cmd = [
        "docker", "create",
        "--name", cid,
        "--read-only",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--security-opt=seccomp=builtin",
        "--security-opt=apparmor=docker-default",
        "--pid=private",
        "--ipc=private",
        "--user=10001:10001",
        "--pids-limit=64",
        "--memory=1g",
        "--memory-swap=1g",
        "--cpus=2",
        "--log-driver=local",
        "--log-opt", "max-size=1m",
        "--log-opt", "max-file=1",
        "--init",
        "--mount", f"type=bind,src={candidate_staging.resolve()},dst=/candidate,readonly",
        "--mount", f"type=bind,src={case_repo.resolve()},dst=/repo,readonly",
        "--mount", "type=tmpfs,dst=/scratch,tmpfs-size=268435456,tmpfs-mode=1777",
        "--mount", "type=tmpfs,dst=/tmp,tmpfs-size=268435456,tmpfs-mode=1777",
        image_digest,
        *worker_args,
    ]

    try:
        subprocess.run(create_cmd, capture_output=True, timeout=15, check=True)
    except Exception as exc:
        return ContainerRunResult(None, "ERROR", f"docker create failed: {exc}", None, b"", b"")

    sec_ok, sec_err = verify_active_container_security(cid)
    if not sec_ok:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=10)
        return ContainerRunResult(None, "ERROR", f"security profile check failed: {sec_err}", None, b"", b"")

    proc = None
    out_drainer = None
    err_drainer = None

    try:
        # Establish monotonic deadline immediately BEFORE starting container
        deadline = time.monotonic() + timeout

        proc = subprocess.Popen(
            ["docker", "start", "--attach", cid],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        out_drainer = StreamDrainer(proc.stdout, STDOUT_LIMIT)
        err_drainer = StreamDrainer(proc.stderr, STDERR_LIMIT)
        out_thread = threading.Thread(target=out_drainer.run, daemon=True)
        err_thread = threading.Thread(target=err_drainer.run, daemon=True)
        out_thread.start()
        err_thread.start()

        timed_out = False
        while time.monotonic() < deadline:
            ret = proc.poll()
            if ret is not None:
                break
            if out_drainer.overflow or err_drainer.overflow:
                break
            time.sleep(0.05)
        else:
            timed_out = True

        if timed_out or out_drainer.overflow or err_drainer.overflow:
            # Terminate container immediately
            subprocess.run(["docker", "kill", cid], capture_output=True, timeout=10)
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass
            out_thread.join(timeout=2)
            err_thread.join(timeout=2)
            reason = "worker execution timeout exceeded" if timed_out else "worker output quota exceeded"
            return ContainerRunResult(
                None, "INCONCLUSIVE", reason, -1, bytes(out_drainer.retained), bytes(err_drainer.retained)
            )

        out_thread.join(timeout=5)
        err_thread.join(timeout=5)

        if out_thread.is_alive() or err_thread.is_alive():
            return ContainerRunResult(
                None, "ERROR", "stream reader thread failed to terminate cleanly", None, b"", b""
            )
        if out_drainer.error:
            return ContainerRunResult(
                None, "ERROR", f"stdout read exception: {out_drainer.error}", None, b"", b""
            )
        if err_drainer.error:
            return ContainerRunResult(
                None, "ERROR", f"stderr read exception: {err_drainer.error}", None, b"", b""
            )

        exit_code = proc.returncode
        stdout_raw = bytes(out_drainer.retained)
        stderr_raw = bytes(err_drainer.retained)

        ipc_res: IPCParseResult = parse_strict_ipc_payload(stdout_raw, exit_code)
        if ipc_res.error or not ipc_res.data:
            return ContainerRunResult(
                None, ipc_res.outcome, ipc_res.error, exit_code, stdout_raw, stderr_raw
            )

        return ContainerRunResult(
            ipc_res.data, ipc_res.outcome, None, exit_code, stdout_raw, stderr_raw
        )

    finally:
        # Unconditional fail-safe cleanup: kill if still alive, reap, remove
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=15)
