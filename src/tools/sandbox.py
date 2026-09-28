import subprocess


def run_sandboxed(command: list[str], timeout: int = 30) -> dict:
    """Run a subprocess with a timeout. Despite the name this performs NO
    isolation (no chroot, namespace, or allowlist): callers must treat it
    as local execution with the current process's privileges."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout": "", "stderr": "timeout"}
