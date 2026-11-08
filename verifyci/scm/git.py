"""Hardened, read-only Git plumbing adapter.

The verification core never reads the working tree for authoritative content.
All blob bytes come from commit-pinned Git objects through this module.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
import subprocess
from pathlib import Path
from typing import Sequence

from verifyci.contracts.model import DiffEntry, Hunk
from verifyci.contracts.names import is_safe_repo_path, normalize_repo_path


class GitError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_LFS_POINTER = b"version https://git-lfs.github.com/spec/v1"
_MAX_BLOB_BYTES = 64 * 1024 * 1024
_BATCH_TIMEOUT_SECONDS = 120


@dataclass(frozen=True, slots=True)
class GitResult:
    stdout: bytes
    stderr: bytes
    returncode: int


class GitRepo:
    def __init__(self, repo: str | Path) -> None:
        self.repo = Path(repo).resolve()
        self._empty_config = os.devnull
        self._blob_cache: dict[str, bytes] = {}
        self._tree_cache: dict[str, dict[str, tuple[str, str, str, str]]] = {}
        self._object_format_cached: str | None = None
        env = os.environ.copy()
        env.update(
            {
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": self._empty_config,
                "GIT_CONFIG_SYSTEM": self._empty_config,
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_PAGER": "cat",
                "LC_ALL": "C",
            }
        )
        self.env = env

    def close(self) -> None:
        """Release adapter state.

        Every Git invocation this adapter makes is one-shot and fully drained
        before it returns (``subprocess.run`` with a bounded timeout), so no
        child process outlives a call and there is no long-lived pipe to shut
        down here.  The method is kept so callers can use ``with`` uniformly.
        """
        return None

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> GitRepo:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Plumbing
    # ------------------------------------------------------------------
    def run(self, args: Sequence[str], *, check: bool = False) -> GitResult:
        command = [
            "git",
            "-C",
            str(self.repo),
            "--no-pager",
            "-c",
            "core.quotepath=false",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.safecrlf=false",
            "-c",
            "core.hooksPath=",
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"core.attributesFile={self._empty_config}",
            *args,
        ]
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                check=False,
                env=self.env,
                timeout=120,
            )
        except FileNotFoundError as exc:
            raise GitError("internal_fault", "git executable was not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise GitError("internal_fault", "git command timed out") from exc
        result = GitResult(proc.stdout, proc.stderr, proc.returncode)
        if check and result.returncode != 0:
            raise self._classify(result)
        return result

    def _classify(self, result: GitResult) -> GitError:
        text = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        lower = text.lower()
        if "shallow" in lower:
            return GitError("shallow_history", text or "shallow history")
        if "ambiguous" in lower and "merge" in lower:
            return GitError("ambiguous_merge_base", text or "ambiguous merge base")
        if "not a git repository" in lower:
            return GitError("internal_fault", text or "not a git repository")
        if "unable to read" in lower or "corrupt" in lower:
            return GitError("provenance_integrity_error", text or "provenance integrity error")
        if "bad object" in lower or "not a valid object" in lower or "unknown revision" in lower:
            return GitError("missing_git_object", text or "missing git object")
        return GitError("missing_git_object", text or f"git exited {result.returncode}")

    def resolve_commit(self, rev: str) -> str:
        if not rev or rev.startswith("-"):
            raise GitError("missing_git_object", f"invalid revision {rev!r}")
        result = self.run(["rev-parse", "--verify", f"{rev}^{{commit}}"])
        if result.returncode != 0:
            raise self._classify(result)
        return result.stdout.decode("ascii", "replace").strip()

    def object_format(self) -> str:
        if self._object_format_cached is not None:
            return self._object_format_cached
        result = self.run(["rev-parse", "--show-object-format"])
        if result.returncode != 0:
            raise self._classify(result)
        value = result.stdout.decode("ascii", "replace").strip()
        self._object_format_cached = value if value in ("sha1", "sha256") else "sha1"
        return self._object_format_cached

    def merge_base(self, base: str, head: str, explicit: str | None = None) -> str:
        if explicit:
            mb = self.resolve_commit(explicit)
            if not self.is_ancestor(mb, base) or not self.is_ancestor(mb, head):
                raise GitError("ambiguous_merge_base", "explicit merge base is not a common ancestor")
            return mb
        result = self.run(["merge-base", "--all", base, head])
        if result.returncode != 0:
            raise self._classify(result)
        lines = [line.strip() for line in result.stdout.decode("ascii", "replace").splitlines() if line.strip()]
        if not lines:
            raise GitError("shallow_history", "no merge base could be established")
        if len(lines) > 1:
            raise GitError("ambiguous_merge_base", "multiple merge bases exist")
        return lines[0]

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        result = self.run(["merge-base", "--is-ancestor", ancestor, descendant])
        return result.returncode == 0

    def read_blobs(self, object_ids: Sequence[str]) -> dict[str, bytes]:
        needed = [oid for oid in object_ids if oid and oid not in self._blob_cache]
        if not needed:
            return {oid: self._blob_cache[oid] for oid in object_ids if oid in self._blob_cache}
        for oid in needed:
            if oid.startswith("-") or "\n" in oid or "\r" in oid:
                raise GitError("missing_git_object", f"invalid blob id {oid!r}")

        input_data = b"".join(f"{oid}\n".encode("utf-8") for oid in needed)
        command = [
            "git",
            "-C",
            str(self.repo),
            "--no-pager",
            "-c",
            "core.quotepath=false",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.safecrlf=false",
            "-c",
            "core.hooksPath=",
            "-c",
            "core.fsmonitor=false",
            "-c",
            f"core.attributesFile={self._empty_config}",
            "cat-file",
            "--batch",
        ]
        # One request/response per call: the process is fully drained and then
        # reaped, so concurrent readers can never interleave reads on a shared
        # pipe.  The timeout bounds a hung or blocked git process and kills it.
        try:
            proc = subprocess.run(
                command,
                input=input_data,
                capture_output=True,
                check=False,
                env=self.env,
                timeout=_BATCH_TIMEOUT_SECONDS,
            )
        except FileNotFoundError as exc:
            raise GitError("internal_fault", "git executable was not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise GitError(
                "internal_fault",
                f"git cat-file --batch timed out after {_BATCH_TIMEOUT_SECONDS}s",
            ) from exc
        except Exception as exc:
            raise GitError("internal_fault", f"cat-file --batch failed: {exc}") from exc
        stdout, stderr, returncode = proc.stdout, proc.stderr, proc.returncode

        if returncode != 0 and not stdout:
            text = stderr.decode("utf-8", "replace").strip()
            raise GitError("missing_git_object", text or "git cat-file --batch failed")

        idx = 0
        total_len = len(stdout)
        for oid in needed:
            if idx >= total_len:
                break
            nl = stdout.find(b"\n", idx)
            if nl == -1:
                break
            header = stdout[idx:nl].decode("ascii", "replace").strip()
            idx = nl + 1
            if header.endswith("missing") or "bad object" in header.lower() or "not a valid object" in header.lower():
                continue
            parts = header.split(" ")
            if len(parts) < 3:
                continue
            obj_sha, obj_type, size_str = parts[0], parts[1], parts[2]
            try:
                size = int(size_str)
            except ValueError:
                raise GitError("internal_fault", f"invalid size in cat-file --batch header: {header!r}")
            if obj_type != "blob":
                idx += size + 1
                continue
            if size > _MAX_BLOB_BYTES:
                raise GitError("parse_resource_limit", f"blob {oid} exceeds the size budget")
            data = stdout[idx : idx + size]
            idx += size + 1
            self._blob_cache[oid] = data
            if obj_sha and obj_sha != oid:
                self._blob_cache[obj_sha] = data
        return {oid: self._blob_cache[oid] for oid in object_ids if oid in self._blob_cache}

    def read_blob(self, object_id: str) -> bytes:
        if not object_id or object_id.startswith("-") or "\n" in object_id or "\r" in object_id:
            raise GitError("missing_git_object", f"invalid blob id {object_id!r}")
        cached = self._blob_cache.get(object_id)
        if cached is not None:
            return cached
        self.read_blobs([object_id])
        cached = self._blob_cache.get(object_id)
        if cached is None:
            raise GitError("missing_git_object", f"blob {object_id!r} not found")
        return cached

    def path_exists_at(self, rev: str, path: str) -> bool:
        path = normalize_repo_path(path)
        if not is_safe_repo_path(path):
            return False
        cached_tree = self._tree_cache.get(rev)
        if cached_tree is not None:
            return path in cached_tree
        return self.read_path_at(rev, path) is not None

    def read_path_at(self, rev: str, path: str) -> bytes | None:
        path = normalize_repo_path(path)
        if not is_safe_repo_path(path):
            return None

        cached_tree = self._tree_cache.get(rev)
        if cached_tree is not None:
            record = cached_tree.get(path)
            if record is None:
                return None
            mode, obj_type, obj_id, _ = record
            if mode == "160000" or obj_type == "commit":
                return None
            if obj_type == "blob":
                return self.read_blob(obj_id)
            return None

        try:
            return self.read_blob(f"{rev}:{path}")
        except GitError as exc:
            if exc.code == "missing_git_object":
                return None
            raise

    def list_tree(self, rev: str, path: str = "") -> list[tuple[str, str, str, str]]:
        """Return (mode, object_type, object_id, path) for a tree."""
        args = ["ls-tree", "-r", "-z", rev]
        if path:
            args.extend(["--", path])
        result = self.run(args)
        if result.returncode != 0:
            raise self._classify(result)
        records: list[tuple[str, str, str, str]] = []
        for raw in result.stdout.split(b"\0"):
            if not raw:
                continue
            try:
                meta, p = raw.split(b"\t", 1)
                mode, obj_type, obj_id = meta.decode("ascii").split(" ")
            except ValueError:
                continue
            records.append((mode, obj_type, obj_id, p.decode("utf-8", "replace")))
        if not path:
            self._tree_cache[rev] = {record[3]: record for record in records}
        return records

    # ------------------------------------------------------------------
    # Diff
    # ------------------------------------------------------------------
    def diff_entries(self, merge_base: str, head: str) -> tuple[list[DiffEntry], bool]:
        combined = self.run(
            [
                "diff-tree",
                "-r",
                "--raw",
                "-p",
                "-z",
                "-U0",
                "--no-commit-id",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                "--find-renames=60%",
                "-l2000",
                merge_base,
                head,
                "--",
            ]
        )
        if combined.returncode != 0:
            raise self._classify(combined)

        if b"\0\0" in combined.stdout:
            raw_bytes, patch_bytes = combined.stdout.split(b"\0\0", 1)
        else:
            raw_bytes = combined.stdout
            patch_bytes = b""

        hunks_by_path = _parse_patch_hunks(patch_bytes)
        records = _parse_raw(raw_bytes)
        add_candidates = sum(1 for r in records if r[6].startswith("A") or not r[4])
        del_candidates = sum(1 for r in records if r[6].startswith("D") or not r[5])
        stderr_text = combined.stderr.decode("utf-8", "replace").lower()
        both_sides_have_candidates = add_candidates > 0 and del_candidates > 0
        rename_limit_exceeded = (
            (both_sides_have_candidates and (add_candidates + del_candidates > 2000))
            or (both_sides_have_candidates and (add_candidates * del_candidates > 2000))
            or ("inexact rename detection was skipped" in stderr_text)
            or ("too many files" in stderr_text)
        )
        # Pre-fetch diff blobs in one cat-file --batch call
        needed_blobs = [
            r[4] for r in records if r[2] != "160000" and r[4]
        ] + [
            r[5] for r in records if r[3] != "160000" and r[5]
        ]
        if needed_blobs:
            self.read_blobs(needed_blobs)

        entries: list[DiffEntry] = []
        for record in records:
            base_path, head_path, base_mode, head_mode, base_blob, head_blob, status = record
            if base_path and not is_safe_repo_path(base_path):
                raise GitError("path_traversal", f"unsafe path in diff: {base_path!r}")
            if head_path and not is_safe_repo_path(head_path):
                raise GitError("path_traversal", f"unsafe path in diff: {head_path!r}")
            is_submodule = base_mode == "160000" or head_mode == "160000"
            is_symlink = base_mode == "120000" or head_mode == "120000"
            if is_submodule:
                base_bytes = b""
                head_bytes = b""
                is_binary = False
                is_lfs = False
            else:
                base_bytes = self.read_blob(base_blob) if base_blob else b""
                head_bytes = self.read_blob(head_blob) if head_blob else b""
                is_binary = b"\0" in base_bytes or b"\0" in head_bytes
                is_lfs = base_bytes.startswith(_LFS_POINTER) or head_bytes.startswith(_LFS_POINTER)
            key = head_path or base_path
            hunks = () if is_submodule else hunks_by_path.get(key, ())
            if not is_submodule and not hunks and base_path != head_path:
                hunks = hunks_by_path.get(base_path, ())
            entries.append(
                DiffEntry(
                    status=status,
                    base_path=base_path,
                    head_path=head_path,
                    base_blob=base_blob,
                    head_blob=head_blob,
                    base_mode=base_mode,
                    head_mode=head_mode,
                    base_source="" if is_binary else base_bytes.decode("utf-8", "replace"),
                    head_source="" if is_binary else head_bytes.decode("utf-8", "replace"),
                    hunks=tuple(hunks),
                    is_binary=is_binary,
                    is_lfs=is_lfs,
                    is_submodule=is_submodule,
                    is_symlink=is_symlink,
                )
            )
        return entries, rename_limit_exceeded


def _parse_raw(data: bytes) -> list[tuple[str, str, str | None, str | None, str | None, str | None, str]]:
    tokens = [t for t in data.split(b"\0") if t]
    out: list[tuple[str, str, str | None, str | None, str | None, str | None, str]] = []
    i = 0
    while i < len(tokens):
        header = tokens[i].decode("ascii", "replace")
        i += 1
        if not header.startswith(":"):
            continue
        parts = header[1:].split(" ")
        if len(parts) < 5:
            continue
        old_mode, new_mode, old_sha, new_sha, status_raw = parts[:5]
        status = status_raw[:1]
        old_sha = None if set(old_sha) == {"0"} else old_sha
        new_sha = None if set(new_sha) == {"0"} else new_sha
        if status in ("R", "C"):
            if i + 1 >= len(tokens):
                break
            old_path = tokens[i].decode("utf-8", "replace")
            new_path = tokens[i + 1].decode("utf-8", "replace")
            i += 2
        else:
            if i >= len(tokens):
                break
            path = tokens[i].decode("utf-8", "replace")
            i += 1
            if status == "D":
                old_path, new_path = path, ""
            elif status == "A":
                old_path, new_path = "", path
            else:
                old_path = new_path = path
        out.append((old_path, new_path, old_mode, new_mode, old_sha, new_sha, status))
    return out


def _parse_patch_hunks(data: bytes) -> dict[str, tuple[Hunk, ...]]:
    text = data.decode("utf-8", "replace")
    out: dict[str, list[Hunk]] = {}
    old_path = ""
    new_path = ""
    current_key = ""
    for line in text.splitlines():
        if line.startswith("diff --git "):
            old_path = new_path = current_key = ""
            continue
        if line.startswith("--- "):
            old_path = _patch_path(line[4:])
            continue
        if line.startswith("+++ "):
            new_path = _patch_path(line[4:])
            current_key = new_path or old_path
            out.setdefault(current_key, [])
            continue
        if line.startswith("@@"):
            m = _HUNK_RE.match(line)
            if not m:
                continue
            key = new_path or old_path or current_key
            if not key:
                continue
            out.setdefault(key, []).append(
                Hunk(
                    old_start=int(m.group(1)),
                    old_count=int(m.group(2) or 1),
                    new_start=int(m.group(3)),
                    new_count=int(m.group(4) or 1),
                )
            )
    return {k: tuple(v) for k, v in out.items()}


def _patch_path(value: str) -> str:
    value = value.strip().split("\t", 1)[0]
    if value == "/dev/null":
        return ""
    if value.startswith(("a/", "b/")):
        value = value[2:]
    return normalize_repo_path(value)


__all__ = ["GitError", "GitRepo", "GitResult"]
