"""Contract 1: Diff Path Partitioning (C1).

Implements deterministic path classification and immutable diff partitioning:
- Typed FilePartition model
- Deterministic path classification rules
- Fail-closed CODE_CORE default for unknown/ambiguous paths
- Canonical path normalization
- Single-pass immutable PartitionedDiff model
- Access to partition-specific hunks and file diffs without reparsing
"""
from dataclasses import dataclass
from enum import Enum
import re
from types import MappingProxyType
from typing import Mapping

from verifyci.verification.diffmap import (
    FileDiff,
    Hunk,
    normalize_path,
    parse_unified_diff,
)


class FilePartition(str, Enum):
    """Semantic partition for a file in a unified diff."""
    CODE_CORE = "code_core"          # Application production source (e.g. verifyci/, src/)
    TEST_SUITE = "test_suite"        # Tests, test utilities, probes, mocks (e.g. tests/, */test_*.py)
    DOCUMENTATION = "documentation"  # Markdown, text, licenses (e.g. *.md, docs/, LICENSE)
    CONFIGURATION = "configuration"  # Packaging, lockfiles, CI configs (e.g. pyproject.toml, .github/)
    ANCILLARY = "ancillary"          # Scripts, benchmarks, scratch tools (e.g. benchmarks/, scripts/)


_TEST_FILE_RE = re.compile(
    r"(^|/)(test_[^/]+\.py|[^/]+_test\.py|[^/]+\.(?:test|spec)\.(?:[jt]sx?|[mc]js|[mc]ts))$"
)
_TEST_DIR_RE = re.compile(r"(^|/)(?:tests?|__tests__)/")
_DOC_EXT_RE = re.compile(r"\.(md|rst|txt)$", re.IGNORECASE)
_CONFIG_NAME_RE = re.compile(
    r"(?:^|/)(pyproject\.toml|setup\.(?:py|cfg)|requirements.*\.txt|"
    r"package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|"
    r"tsconfig(?:\..*)?\.json|\.eslintrc.*|eslint\.config\..*|\.prettierrc.*|"
    r"\.editorconfig|\.babelrc.*|babel\.config\..*|jest\.config\..*|vitest\.config\..*|"
    r"Cargo\.(?:toml|lock)|pom\.xml|go\.(?:mod|sum))$|^\.github/"
)
_ANCILLARY_DIR_RE = re.compile(r"^(benchmarks/|scripts/|scratch/)")
_CODE_DIR_RE = re.compile(r"^(verifyci/|src/)")


def _strip_git_prefix(path: str) -> str:
    """Strip standard git diff prefixes ('a/' or 'b/') if present."""
    if path.startswith(("a/", "b/")) and len(path) > 2:
        return path[2:]
    return path


def classify_path(path: str | None) -> FilePartition:
    r"""Deterministically classify a file path into its FilePartition.

    Enforces frozen C1 rules:
    - Path normalization (backslashes, './', 'a/' and 'b/' git prefixes)
    - CONFIGURATION: pyproject.toml, setup.py, setup.cfg, requirements*.txt, .github/,
      plus manifest dependency files (Cargo.toml, package.json, pom.xml, go.mod)
    - DOCUMENTATION: .md, .rst, .txt, docs/, LICENSE*
    - TEST_SUITE: ^tests/, ^test/, (^|/)test_[^/]+\.py$, (^|/)[^/]+_test\.py$
    - ANCILLARY: ^benchmarks/, ^scripts/, ^scratch/
    - CODE_CORE: ^verifyci/, ^src/
    - Fail-closed: Any unknown, empty, or ambiguous path MUST default to CODE_CORE.
    """
    if not path:
        return FilePartition.CODE_CORE

    norm = normalize_path(str(path).strip())
    norm = _strip_git_prefix(norm)

    if not norm:
        return FilePartition.CODE_CORE

    # 1. Configuration (must precede generic .txt documentation matching)
    if _CONFIG_NAME_RE.search(norm):
        return FilePartition.CONFIGURATION

    # 2. Documentation
    if _DOC_EXT_RE.search(norm):
        return FilePartition.DOCUMENTATION
    if norm.startswith("docs/"):
        return FilePartition.DOCUMENTATION
    if norm.upper().startswith("LICENSE"):
        return FilePartition.DOCUMENTATION

    # 3. Test Suite
    if _TEST_DIR_RE.search(norm) or _TEST_FILE_RE.search(norm):
        return FilePartition.TEST_SUITE

    # 4. Ancillary (benchmarks, scripts, scratch)
    if _ANCILLARY_DIR_RE.search(norm):
        return FilePartition.ANCILLARY

    # 5. Core production code
    if _CODE_DIR_RE.search(norm):
        return FilePartition.CODE_CORE

    # 6. Fail-closed default: unknown or ambiguous paths are treated as CODE_CORE
    return FilePartition.CODE_CORE


@dataclass(frozen=True)
class PartitionedDiff:
    """Immutable, single-pass partitioning of a unified diff.

    Preserves original raw diff string, file diffs, and hunks grouped
    by FilePartition. All internal collections are immutable tuples and
    mapping proxies.
    """
    raw_diff: str
    partitions: Mapping[FilePartition, tuple[str, ...]]
    hunks_by_partition: Mapping[FilePartition, tuple[Hunk, ...]]
    file_diffs_by_partition: Mapping[FilePartition, tuple[FileDiff, ...]]
    raw_diff_by_partition: Mapping[FilePartition, str]

    def files_for_partition(self, partition: FilePartition) -> tuple[str, ...]:
        """Return the tuple of file paths belonging to the partition."""
        return self.partitions.get(partition, ())

    def hunks_for_partition(self, partition: FilePartition) -> tuple[Hunk, ...]:
        """Return the tuple of Hunk objects belonging to the partition without reparsing."""
        return self.hunks_by_partition.get(partition, ())

    def file_diffs_for_partition(self, partition: FilePartition) -> tuple[FileDiff, ...]:
        """Return the tuple of FileDiff objects belonging to the partition without reparsing."""
        return self.file_diffs_by_partition.get(partition, ())

    def raw_diff_for_partition(self, partition: FilePartition) -> str:
        """Return the verbatim diff text for files in this partition."""
        return self.raw_diff_by_partition.get(partition, "")

    def raw_diff_for_partitions(self, partitions: set[FilePartition] | tuple[FilePartition, ...] | list[FilePartition]) -> str:
        """Return the verbatim diff text for files across the specified partitions."""
        return "".join(self.raw_diff_by_partition.get(p, "") for p in sorted(partitions, key=lambda x: x.value))


def _extract_file_diff_texts(raw: str, parsed_files: list[FileDiff]) -> list[str]:
    """Extract the verbatim diff lines belonging to each FileDiff block."""
    if not parsed_files or not raw:
        return []
    from verifyci.verification.diffmap import _diff_lines, _header_path, _is_header
    lines = _diff_lines(raw)
    starts = []
    line_idx = 0
    for i, f in enumerate(parsed_files):
        if f.git_index is not None:
            starts.append(f.git_index)
            line_idx = f.git_index + 1
        elif i == 0 and f.old_path is None and f.new_path is None:
            # Preamble block: starts at line 0, do not search headers
            starts.append(0)
            line_idx = 0
        else:
            found = None
            if f.old_path is not None:
                for idx in range(line_idx, len(lines)):
                    if _is_header(lines[idx], "---") and _header_path(lines[idx], "---") == f.old_path:
                        found = idx
                        break
            if found is None and f.new_path is not None:
                for idx in range(line_idx, len(lines)):
                    if _is_header(lines[idx], "+++") and _header_path(lines[idx], "+++") == f.new_path:
                        # Include previous --- line if present (e.g. --- /dev/null)
                        if idx > 0 and _is_header(lines[idx - 1], "---"):
                            found = idx - 1
                        else:
                            found = idx
                        break
            if found is None:
                found = line_idx
            starts.append(found)
            line_idx = found + 1
    starts.append(len(lines))
    return [
        "\n".join(lines[starts[i]:starts[i + 1]]) + ("\n" if starts[i + 1] > starts[i] else "")
        for i in range(len(parsed_files))
    ]


def partition_diff(diff: str | None) -> PartitionedDiff:
    """Parse and partition a unified diff exactly once into an immutable PartitionedDiff."""
    raw = str(diff) if diff is not None else ""
    parsed_files = parse_unified_diff(raw)

    files_acc: dict[FilePartition, list[str]] = {p: [] for p in FilePartition}
    hunks_acc: dict[FilePartition, list[Hunk]] = {p: [] for p in FilePartition}
    file_diffs_acc: dict[FilePartition, list[FileDiff]] = {p: [] for p in FilePartition}
    diff_texts_acc: dict[FilePartition, list[str]] = {p: [] for p in FilePartition}

    seen_files: dict[FilePartition, set[str]] = {p: set() for p in FilePartition}

    file_texts = _extract_file_diff_texts(raw, parsed_files)

    for i, f in enumerate(parsed_files):
        canonical_path = f.path or ""
        part = classify_path(canonical_path)

        file_diffs_acc[part].append(f)
        if i < len(file_texts):
            diff_texts_acc[part].append(file_texts[i])

        if canonical_path and canonical_path not in seen_files[part]:
            seen_files[part].add(canonical_path)
            files_acc[part].append(canonical_path)

        for h in f.hunks:
            hunks_acc[part].append(h)

    # Freeze into immutable structures
    frozen_partitions = MappingProxyType({
        p: tuple(files_acc[p]) for p in FilePartition
    })
    frozen_hunks = MappingProxyType({
        p: tuple(hunks_acc[p]) for p in FilePartition
    })
    frozen_file_diffs = MappingProxyType({
        p: tuple(file_diffs_acc[p]) for p in FilePartition
    })
    frozen_raw_diffs = MappingProxyType({
        p: "".join(diff_texts_acc[p]) for p in FilePartition
    })

    return PartitionedDiff(
        raw_diff=raw,
        partitions=frozen_partitions,
        hunks_by_partition=frozen_hunks,
        file_diffs_by_partition=frozen_file_diffs,
        raw_diff_by_partition=frozen_raw_diffs,
    )
