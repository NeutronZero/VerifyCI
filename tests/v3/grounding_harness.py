"""Grounding test harness: builds reproducible small bare/working Git repositories from corpus fixtures."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Tuple

from verifyci.scm.git import GitRepo


def build_case_repo(
    case_dir: Path,
    target_dir: Path,
    *,
    corrupt_int: bool = False,
) -> Tuple[GitRepo, str, str, str]:
    """Build a reproducible Git repository with base, merge-base, head, and policy."""
    target_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(target_dir)], check=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "core.autocrlf", "false"], check=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "core.safecrlf", "false"], check=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "user.name", "VerifyCI Tester"], check=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "user.email", "test@verifyci.dev"], check=True)

    # 1. Authoritative base policy
    pol_file = case_dir / "policy.toml"
    if pol_file.exists():
        pol_dest = target_dir / ".verifyci" / "policy.toml"
        pol_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(pol_file, pol_dest)

    # 2. Base tree
    base_dir = case_dir / "base"
    if base_dir.exists():
        for f in base_dir.rglob("*"):
            if f.is_file():
                rel = f.relative_to(base_dir)
                dest = target_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest)

    subprocess.run(["git", "-C", str(target_dir), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(target_dir), "commit", "-q", "-m", "base"], check=True)
    base_commit = subprocess.check_output(
        ["git", "-C", str(target_dir), "rev-parse", "HEAD"], text=True
    ).strip()
    merge_base = base_commit

    # Ensure timestamp resolution difference between commits
    time.sleep(0.05)

    # 3. Head tree
    # Clear previous working tree (except .git and .verifyci)
    for item in target_dir.iterdir():
        if item.name not in (".git", ".verifyci"):
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

    head_dir = case_dir / "head"
    future_time = time.time() + 10
    if head_dir.exists():
        for f in head_dir.rglob("*"):
            if f.is_file():
                rel = f.relative_to(head_dir)
                dest = target_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest)
                os.utime(dest, (future_time, future_time))

    subprocess.run(["git", "-C", str(target_dir), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(target_dir), "commit", "-q", "-m", "head"], check=True)
    head_commit = subprocess.check_output(
        ["git", "-C", str(target_dir), "rev-parse", "HEAD"], text=True
    ).strip()

    repo = GitRepo(target_dir)

    # 4. If integrity corruption requested (for GRD-INT-001 scenario)
    if corrupt_int:
        entries, _ = repo.diff_entries(base_commit, head_commit)
        if entries and entries[0].base_blob:
            b_blob = entries[0].base_blob
            prefix = b_blob[:2]
            suffix = b_blob[2:]
            obj_path = target_dir / ".git" / "objects" / prefix / suffix
            if obj_path.exists():
                os.chmod(obj_path, 0o777)
                obj_path.unlink()

    return repo, base_commit, merge_base, head_commit
