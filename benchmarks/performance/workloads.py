"""Deterministic workload fixtures for VerifyCI v3 performance benchmarks.

Provides 4 repeatable diff configurations:
1. empty_diff: 0 changed files (clean base vs clean head)
2. small_diff: 1 changed file
3. typical_diff: 4 changed files across modules
4. large_diff: 52 changed files (> 50 changed files)
"""

from __future__ import annotations

from pathlib import Path
import random
import subprocess

POLICY_CONTENT = """[gate]
target_drift = "record"
"""


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed in {repo}: {result.stderr or result.stdout}")
    return result.stdout.strip()


def _init_repo(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "VerifyCI Benchmark")
    _git(root, "config", "user.email", "benchmark@verifyci.local")
    _git(root, "config", "core.autocrlf", "false")
    policy_dir = root / ".verifyci"
    policy_dir.mkdir(parents=True, exist_ok=True)
    (policy_dir / "policy.toml").write_text(POLICY_CONTENT, encoding="utf-8", newline="\n")


def setup_empty_diff(root: Path) -> tuple[Path, str, str]:
    """Workload 1: Clean target base with 0 changed files."""
    repo = root / "empty_diff"
    _init_repo(repo)
    src = repo / "src"
    src.mkdir(parents=True, exist_ok=True)

    for i in range(5):
        (src / f"module_{i:02d}.py").write_text(
            f"def compute_{i}(x: int) -> int:\n    return x * {i + 1}\n",
            encoding="utf-8",
            newline="\n",
        )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    # Head is identical
    head = base
    return repo, base, head


def setup_small_diff(root: Path) -> tuple[Path, str, str]:
    """Workload 2: Single-file localized modification."""
    repo = root / "small_diff"
    _init_repo(repo)
    src = repo / "src"
    src.mkdir(parents=True, exist_ok=True)

    for i in range(5):
        (src / f"module_{i:02d}.py").write_text(
            f"def compute_{i}(x: int) -> int:\n    return x + {i}\n",
            encoding="utf-8",
            newline="\n",
        )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    # Modify module_00.py
    (src / "module_00.py").write_text(
        "def compute_0(x: int) -> int:\n    return (x + 1) * 2\n\ndef helper_0(y: int) -> int:\n    return compute_0(y) + 1\n",
        encoding="utf-8",
        newline="\n",
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")
    return repo, base, head


def setup_typical_diff(root: Path) -> tuple[Path, str, str]:
    """Workload 3: Multi-file diff across 4 modules with cross-references."""
    repo = root / "typical_diff"
    _init_repo(repo)
    src = repo / "src"
    src.mkdir(parents=True, exist_ok=True)

    files = {
        "core.py": "def process_data(data: list[int]) -> int:\n    return sum(data)\n",
        "api.py": "from src.core import process_data\n\ndef handle_request(items: list[int]) -> dict:\n    val = process_data(items)\n    return {'result': val}\n",
        "utils.py": "def sanitize(value: str) -> str:\n    return value.strip()\n",
        "models.py": "class Payload:\n    def __init__(self, name: str):\n        self.name = name\n",
        "extra.py": "def unused_helper() -> None:\n    pass\n",
    }
    for name, content in files.items():
        (src / name).write_text(content, encoding="utf-8", newline="\n")

    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    # Modify 4 files
    (src / "core.py").write_text(
        "def process_data(data: list[int], scale: int = 1) -> int:\n    return sum(data) * scale\n",
        encoding="utf-8",
        newline="\n",
    )
    (src / "api.py").write_text(
        "from src.core import process_data\n\ndef handle_request(items: list[int]) -> dict:\n    val = process_data(items, scale=2)\n    return {'result': val, 'status': 'ok'}\n",
        encoding="utf-8",
        newline="\n",
    )
    (src / "utils.py").write_text(
        "def sanitize(value: str) -> str:\n    return value.strip().lower()\n\ndef format_output(n: int) -> str:\n    return f'val: {n}'\n",
        encoding="utf-8",
        newline="\n",
    )
    (src / "models.py").write_text(
        "class Payload:\n    def __init__(self, name: str, version: int = 1):\n        self.name = name\n        self.version = version\n",
        encoding="utf-8",
        newline="\n",
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")
    return repo, base, head


def setup_large_diff(root: Path, file_count: int = 52) -> tuple[Path, str, str]:
    """Workload 4: Large diff modifying 52 files deterministically."""
    repo = root / "large_diff"
    _init_repo(repo)
    src = repo / "src"
    src.mkdir(parents=True, exist_ok=True)

    rng = random.Random(20261108)
    total_files = max(60, file_count + 8)

    for i in range(total_files):
        num_funcs = rng.randint(2, 4)
        funcs = "\n".join(
            f"def func_{i}_{j}(x: int) -> int:\n    return x + {j}\n"
            for j in range(num_funcs)
        )
        (src / f"module_{i:02d}.py").write_text(funcs, encoding="utf-8", newline="\n")

    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    # Modify exactly file_count files
    for i in range(file_count):
        new_content = (
            f"def func_{i}_0(x: int) -> int:\n    return (x + 1) * 2\n\n"
            f"def added_func_{i}(y: int) -> int:\n    return func_{i}_0(y) + 10\n"
        )
        (src / f"module_{i:02d}.py").write_text(new_content, encoding="utf-8", newline="\n")

    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")
    return repo, base, head
