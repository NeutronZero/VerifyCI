"""Unified diff parser and hunk normalizer."""

from __future__ import annotations

import difflib
import re
from typing import Sequence

from verifyci.contracts.attestation import normalize_path

_HUNK_HEADER_RE = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")


class RemovedLine:
    """A line removed in a diff, with its estimated old-side 1-indexed line number."""

    __slots__ = ("content", "line_number")

    def __init__(self, line_number: int, content: str) -> None:
        object.__setattr__(self, "line_number", line_number)
        object.__setattr__(self, "content", content)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("RemovedLine is immutable")

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, RemovedLine):
            return False
        return self.line_number == other.line_number and self.content == other.content


class DiffFileEntry:
    """Structured representation of changes in a single file (high-performance slotted model)."""

    __slots__ = (
        "added_lines",
        "base_source",
        "file_path",
        "head_source",
        "is_binary",
        "is_deletion",
        "is_rename",
        "old_file_path",
        "raw_diff",
        "removed_lines",
    )

    def __init__(
        self,
        file_path: str,
        old_file_path: str = "",
        is_rename: bool = False,
        is_deletion: bool = False,
        is_binary: bool = False,
        base_source: str = "",
        head_source: str = "",
        added_lines: Sequence[str] = (),
        removed_lines: Sequence[RemovedLine] = (),
        raw_diff: str = "",
    ) -> None:
        object.__setattr__(self, "file_path", normalize_path(file_path))
        object.__setattr__(self, "old_file_path", normalize_path(old_file_path or file_path))
        object.__setattr__(self, "is_rename", is_rename)
        object.__setattr__(self, "is_deletion", is_deletion)
        object.__setattr__(self, "is_binary", is_binary)
        object.__setattr__(self, "base_source", base_source)
        object.__setattr__(self, "head_source", head_source)
        object.__setattr__(self, "added_lines", tuple(added_lines))
        object.__setattr__(self, "removed_lines", tuple(removed_lines))
        object.__setattr__(self, "raw_diff", raw_diff)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("DiffFileEntry is immutable")

    @classmethod
    def from_sources(
        cls,
        file_path: str,
        base_source: str,
        head_source: str,
        diff: str = "",
    ) -> DiffFileEntry:
        """Construct entry from full source strings, synthesizing diff if omitted."""
        norm_path = normalize_path(file_path)
        base_lines = base_source.splitlines()
        head_lines = head_source.splitlines()

        if not diff:
            diff_lines = list(
                difflib.unified_diff(
                    base_lines,
                    head_lines,
                    fromfile=f"a/{norm_path}",
                    tofile=f"b/{norm_path}",
                    lineterm="",
                )
            )
            diff = "\n".join(diff_lines)

        parsed = parse_unified_diff(diff)
        if parsed:
            return cls(
                file_path=norm_path,
                old_file_path=norm_path,
                base_source=base_source,
                head_source=head_source,
                added_lines=parsed[0].added_lines,
                removed_lines=parsed[0].removed_lines,
                raw_diff=diff,
            )

        added = tuple(line for line in head_lines if line.strip() and line not in base_lines)
        return cls(
            file_path=norm_path,
            old_file_path=norm_path,
            base_source=base_source,
            head_source=head_source,
            added_lines=added,
            raw_diff=diff,
        )


def parse_unified_diff(diff_text: str) -> list[DiffFileEntry]:
    """Parse unified diff text into normalized DiffFileEntry structures."""
    entries: list[DiffFileEntry] = []
    current_file: str | None = None
    old_file: str | None = None
    is_rename = False
    is_deletion = False
    is_binary = False

    base_lines: list[str] = []
    head_lines: list[str] = []
    added_lines: list[str] = []
    removed_lines: list[RemovedLine] = []
    raw_lines: list[str] = []

    old_line_cursor = 1

    def flush_current() -> None:
        nonlocal current_file, old_file, is_rename, is_deletion, is_binary
        nonlocal base_lines, head_lines, added_lines, removed_lines, raw_lines
        if current_file:
            entries.append(
                DiffFileEntry(
                    file_path=normalize_path(current_file),
                    old_file_path=normalize_path(old_file or current_file),
                    is_rename=is_rename,
                    is_deletion=is_deletion,
                    is_binary=is_binary,
                    base_source="\n".join(base_lines),
                    head_source="\n".join(head_lines),
                    added_lines=tuple(added_lines),
                    removed_lines=tuple(removed_lines),
                    raw_diff="\n".join(raw_lines),
                )
            )
        current_file = None
        old_file = None
        is_rename = False
        is_deletion = False
        is_binary = False
        base_lines = []
        head_lines = []
        added_lines = []
        removed_lines = []
        raw_lines = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            flush_current()
            raw_lines.append(line)
        elif line.startswith("rename from "):
            is_rename = True
            old_file = line[12:].strip()
            raw_lines.append(line)
        elif line.startswith("rename to "):
            is_rename = True
            current_file = line[10:].strip()
            raw_lines.append(line)
        elif line.startswith("deleted file mode "):
            is_deletion = True
            raw_lines.append(line)
        elif line.startswith("Binary files ") or "differ" in line:
            is_binary = True
            raw_lines.append(line)
        elif line.startswith("--- a/") or line.startswith("--- b/"):
            if not old_file:
                old_file = line[6:].strip()
            raw_lines.append(line)
        elif line.startswith("+++ b/") or line.startswith("+++ a/"):
            current_file = line[6:].strip()
            raw_lines.append(line)
        elif line.startswith("@@"):
            raw_lines.append(line)
            match = _HUNK_HEADER_RE.match(line)
            if match:
                old_line_cursor = int(match.group(1))
        elif current_file is not None or old_file is not None:
            raw_lines.append(line)
            if line.startswith("+") and not line.startswith("+++"):
                content = line[1:]
                added_lines.append(content)
                head_lines.append(content)
            elif line.startswith("-") and not line.startswith("---"):
                content = line[1:]
                removed_lines.append(RemovedLine(line_number=old_line_cursor, content=content))
                base_lines.append(content)
                old_line_cursor += 1
            elif line.startswith(" ") or line == "":
                content = line[1:] if line else ""
                base_lines.append(content)
                head_lines.append(content)
                old_line_cursor += 1

    flush_current()
    return entries
