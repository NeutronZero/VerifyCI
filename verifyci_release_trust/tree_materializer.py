"""Trusted Git-Tree Materializer and Candidate Source Fingerprinter (§15.10 Component B).

Materializes candidate source directly from immutable Git blob objects, bypassing
git-archive and working-tree extraction to prevent .gitattributes or untracked file tampering.
Enforces strict tree policies against path traversal, escaping symlinks, and special files.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
from typing import NamedTuple


class TreeEntry(NamedTuple):
    mode: str
    entry_type: str
    object_sha: str
    rel_path: str


class MaterializedManifest(NamedTuple):
    commit_sha: str
    tree_sha: str
    manifest_digest: str
    fingerprint: str
    file_count: int


def _validate_commit_sha(sha: str) -> str:
    s = sha.strip().lower()
    if len(s) != 40 or any(c not in "0123456789abcdef" for c in s):
        raise ValueError(f"invalid candidate commit SHA: {sha!r}")
    return s


def resolve_commit_tree(repo_root: Path, commit_sha: str) -> tuple[str, str]:
    """Verify commit exists and return (commit_sha, tree_sha)."""
    valid_sha = _validate_commit_sha(commit_sha)
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--verify", f"{valid_sha}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ValueError(f"commit {valid_sha} does not exist in repository: {proc.stderr.strip()}")
    commit_resolved = proc.stdout.strip().lower()

    proc_tree = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", f"{valid_sha}^{{tree}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc_tree.returncode != 0:
        raise ValueError(f"failed to resolve tree for commit {valid_sha}: {proc_tree.stderr.strip()}")
    tree_sha = proc_tree.stdout.strip().lower()
    return commit_resolved, tree_sha


def enumerate_tree(repo_root: Path, tree_sha: str) -> list[TreeEntry]:
    """Read all tree entries using Git plumbing (ls-tree -r -z)."""
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "ls-tree", "-r", "-z", "--full-name", tree_sha],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-tree failed for tree {tree_sha}")

    entries: list[TreeEntry] = []
    raw = proc.stdout
    # Entries are null-terminated: "<mode> <type> <object>\t<path>\0"
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            meta, sep, path_bytes = item.partition(b"\t")
            if not sep:
                continue
            meta_str = meta.decode("ascii")
            mode, entry_type, obj_sha = meta_str.split(" ", 2)
            rel_path = path_bytes.decode("utf-8", errors="strict")
            entries.append(TreeEntry(mode=mode, entry_type=entry_type, object_sha=obj_sha.lower(), rel_path=rel_path))
        except Exception as exc:
            raise ValueError(f"malformed git ls-tree record: {item!r} ({exc})") from exc

    return entries


ALLOWED_TYPE_MODES = {
    ("blob", "100644"),
    ("blob", "100755"),
    ("symlink", "120000"),
}

MAX_TREE_ENTRIES = 20_000
MAX_SINGLE_BLOB_SIZE = 50 * 1024 * 1024
MAX_TOTAL_TREE_SIZE = 200 * 1024 * 1024


def validate_tree_paths(entries: list[TreeEntry]) -> None:
    """Enforce strict tree security policy: no absolute paths, no traversal, no .git, no escaping symlinks."""
    if len(entries) > MAX_TREE_ENTRIES:
        raise ValueError(f"tree entry count {len(entries)} exceeds maximum allowed ({MAX_TREE_ENTRIES})")

    for entry in entries:
        p = Path(entry.rel_path)
        if p.is_absolute():
            raise ValueError(f"tree contains forbidden absolute path: {entry.rel_path}")
        parts = p.parts
        if ".." in parts or "." in parts:
            raise ValueError(f"tree contains forbidden traversal path: {entry.rel_path}")
        if any(part == ".git" or part.startswith(".git/") for part in parts):
            raise ValueError(f"tree contains forbidden .git component: {entry.rel_path}")
        if entry.entry_type == "commit":
            raise ValueError(f"unpinned or unauthorized submodule entry: {entry.rel_path}")
        if (entry.entry_type, entry.mode) not in ALLOWED_TYPE_MODES:
            raise ValueError(f"forbidden object type/mode pair: {entry.entry_type} ({entry.mode}) for {entry.rel_path}")


def materialize_tree_to_staging(
    repo_root: Path,
    commit_sha: str,
    staging_dir: Path,
) -> MaterializedManifest:
    """Materialize candidate tree into staging directory safely and return canonical fingerprint."""
    commit_resolved, tree_sha = resolve_commit_tree(repo_root, commit_sha)
    entries = enumerate_tree(repo_root, tree_sha)
    validate_tree_paths(entries)

    staging_dir.mkdir(parents=True, exist_ok=True)
    resolved_staging = staging_dir.resolve()

    # Sort entries by relative posix path for deterministic manifest
    sorted_entries = sorted(entries, key=lambda e: e.rel_path)
    manifest_lines: list[str] = []
    total_tree_size = 0

    # Two-pass extraction: first pass writes regular/executable files; second pass handles symlinks
    regular_entries = [e for e in sorted_entries if e.mode != "120000"]
    symlink_entries = [e for e in sorted_entries if e.mode == "120000"]

    for entry in regular_entries:
        dest_path = resolved_staging / entry.rel_path
        # Defensive check against escaping
        try:
            dest_path.resolve(strict=False).relative_to(resolved_staging)
        except ValueError:
            raise ValueError(f"path escapes staging root: {entry.rel_path}")

        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # Read blob content directly from git object database
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "cat-file", "-p", entry.object_sha],
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"failed to read blob {entry.object_sha} for {entry.rel_path}")

        content = proc.stdout
        if len(content) > MAX_SINGLE_BLOB_SIZE:
            raise ValueError(f"blob {entry.rel_path} exceeds maximum size ({len(content)} > {MAX_SINGLE_BLOB_SIZE})")
        total_tree_size += len(content)
        if total_tree_size > MAX_TOTAL_TREE_SIZE:
            raise ValueError(f"cumulative tree size exceeds limit ({total_tree_size} > {MAX_TOTAL_TREE_SIZE})")

        # Check for Git LFS pointer
        if content.startswith(b"version https://git-lfs.github.com/spec/v1"):
            raise ValueError(f"unresolved Git LFS pointer forbidden in release evaluation: {entry.rel_path}")

        # Write content with no CRLF conversion
        dest_path.write_bytes(content)
        if entry.mode == "100755":
            try:
                dest_path.chmod(0o755)
            except Exception:
                pass
        else:
            try:
                dest_path.chmod(0o644)
            except Exception:
                pass

        content_sha256 = hashlib.sha256(content).hexdigest()
        manifest_lines.append(f"{entry.mode} blob {content_sha256} {entry.rel_path}")

    # Second pass: symlinks
    for entry in symlink_entries:
        dest_path = resolved_staging / entry.rel_path
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        proc = subprocess.run(
            ["git", "-C", str(repo_root), "cat-file", "-p", entry.object_sha],
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"failed to read symlink target {entry.object_sha} for {entry.rel_path}")

        target_str = proc.stdout.decode("utf-8", errors="strict")
        # Validate that symlink does not escape staging root
        target_path = (dest_path.parent / target_str).resolve(strict=False)
        try:
            target_path.relative_to(resolved_staging)
        except ValueError:
            raise ValueError(f"symlink {entry.rel_path} -> {target_str} escapes staging root")

        try:
            os.symlink(target_str, dest_path)
        except OSError as exc:
            raise OSError(f"symlink materialization failed for {entry.rel_path} -> {target_str}: {exc}") from exc

        target_sha256 = hashlib.sha256(target_str.encode("utf-8")).hexdigest()
        manifest_lines.append(f"{entry.mode} symlink {target_sha256} {entry.rel_path}")

    manifest_content = "\n".join(manifest_lines) + "\n"
    manifest_digest = "sha256:" + hashlib.sha256(manifest_content.encode("utf-8")).hexdigest()

    # Canonical candidate implementation fingerprint binds commit, tree, and manifest
    hasher = hashlib.sha256()
    hasher.update(b"VERIFYCI-CANDIDATE-FINGERPRINT-V1\n")
    hasher.update(commit_resolved.encode("ascii") + b"\n")
    hasher.update(tree_sha.encode("ascii") + b"\n")
    hasher.update(manifest_digest.encode("ascii") + b"\n")
    fingerprint = "sha256:" + hasher.hexdigest()

    return MaterializedManifest(
        commit_sha=commit_resolved,
        tree_sha=tree_sha,
        manifest_digest=manifest_digest,
        fingerprint=fingerprint,
        file_count=len(sorted_entries),
    )


def compute_staging_fingerprint(staging_dir: Path, commit_sha: str, tree_sha: str) -> str:
    """Recompute fingerprint over an existing staging directory to verify immutability."""
    resolved_staging = staging_dir.resolve()
    manifest_lines: list[str] = []

    all_files = sorted(
        [p for p in resolved_staging.rglob("*") if not p.is_dir()],
        key=lambda p: p.relative_to(resolved_staging).as_posix(),
    )

    for p in all_files:
        rel_posix = p.relative_to(resolved_staging).as_posix()
        if p.is_symlink():
            target = os.readlink(p)
            # Verify no escape
            dest = (p.parent / target).resolve(strict=False)
            try:
                dest.relative_to(resolved_staging)
            except ValueError:
                raise ValueError(f"symlink {rel_posix} escapes staging root: {target}")
            target_sha256 = hashlib.sha256(target.encode("utf-8")).hexdigest()
            manifest_lines.append(f"120000 symlink {target_sha256} {rel_posix}")
        else:
            content = p.read_bytes()
            mode = "100755" if os.access(p, os.X_OK) else "100644"
            content_sha256 = hashlib.sha256(content).hexdigest()
            manifest_lines.append(f"{mode} blob {content_sha256} {rel_posix}")

    manifest_content = "\n".join(manifest_lines) + "\n"
    manifest_digest = "sha256:" + hashlib.sha256(manifest_content.encode("utf-8")).hexdigest()

    hasher = hashlib.sha256()
    hasher.update(b"VERIFYCI-CANDIDATE-FINGERPRINT-V1\n")
    hasher.update(commit_sha.lower().encode("ascii") + b"\n")
    hasher.update(tree_sha.lower().encode("ascii") + b"\n")
    hasher.update(manifest_digest.encode("ascii") + b"\n")
    return "sha256:" + hasher.hexdigest()


class TreeMaterializer:
    """Helper wrapper for tree materialization and path validation."""

    def __init__(self, dest: Path) -> None:
        self.dest = dest.resolve()

    def _sanitize_and_validate_path(self, rel_path: str) -> Path:
        p = Path(rel_path)
        if p.is_absolute() or rel_path.startswith("/") or rel_path.startswith("\\"):
            raise ValueError(f"escaping destination: absolute path {rel_path}")
        target = (self.dest / rel_path).resolve(strict=False)
        try:
            target.relative_to(self.dest)
        except ValueError:
            raise ValueError(f"escaping destination: {rel_path}")
        return target
