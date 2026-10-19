"""Single owner of VerifyCI's verification verdict.

Both entry points - the CLI (`vc2 verify-diff`) and the FastMCP daemon
(`vc_prove_diff`) - used to carry their own copy of this logic. They drifted:
the same defect was reported at two severities depending on which one ran, and
the MCP path was missing the new-module, deletion, and secret checks entirely,
so an agent driving the daemon got a weaker gate than CI.

This module is the only place that decides what a diff's findings are, what
their identifiers are, and what the resulting verdict is. Entry points parse
their inputs into `DiffFileEntry`, call `VerificationPipeline.verify_files`, and
format the result. They do not construct findings.

Fail-closed throughout: an unrunnable check yields an INCONCLUSIVE finding
rather than an omission, and verdict precedence is FAIL > INCONCLUSIVE/UNGROUNDED
> PASS, so uncertainty can never become a pass.
"""

from __future__ import annotations

import ast
import difflib
import importlib.util
import re
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from verifyci_v2.contracts.attestation import GateExecutionReceipt, GateStatus, VerificationFinding
from verifyci_v2.contracts.canonical import content_digest_hex
from verifyci_v2.ingestion.removal_provenance import (
    analyze_removal_provenance,
    entities_from_source,
)
from verifyci_v2.ingestion.ssa_lower import lower_module_to_ussa
from verifyci_v2.ingestion.compile_context import AddedLineRecord, CompiledFilePair, IndexedAST, compile_file_pair
from verifyci_v2.symbolic.dangerous_calls import scan_dangerous_calls
from verifyci_v2.symbolic.egglog_engine import EgglogEquivalenceEngine
from verifyci_v2.symbolic.secrets_taint import TaintTrackedSecretEngine
from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver

# Domain separator for every finding identifier. Named once so the identity of
# a finding cannot drift between call sites or between releases.
_FINDING_DOMAIN = "verifyci.v2.finding"

# Default prover budget. Callers that construct a pipeline for interactive use
# may lower it; the gate default is deliberately generous relative to the 2s
# spec budget so a slow solve degrades to INCONCLUSIVE rather than a false PASS.
_DEFAULT_SMT_TIMEOUT_MS = 3000

# Credentials matched directly in added lines of non-Python files, where no
# AST-based taint scan applies.
_NON_PYTHON_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9_]{36}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


def finding_id(kind: str, *parts: str) -> str:
    """Stable 16-hex identifier for a finding.

    Deterministic for a given (kind, subject) pair, so the same defect keeps the
    same id across runs, processes, and entry points.
    """
    return content_digest_hex(":".join((kind, *parts)), domain=_FINDING_DOMAIN)[:16]


@dataclass(frozen=True)
class DiffFileEntry:
    """One file's diff plus source-completeness and precise addition metadata."""
    file_path: str
    base_source: str
    head_source: str
    added_lines: tuple[str, ...] = ()
    diff: str = ""
    is_complete_source: bool = False
    added_line_records: tuple[AddedLineRecord, ...] = ()
    diff_is_synthetic: bool = False

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    @classmethod
    def from_sources(
        cls, file_path: str, base_source: str, head_source: str, diff: str = ""
    ) -> "DiffFileEntry":
        diff_is_synthetic = not bool(diff)
        diff_text = diff or _synthetic_diff(file_path, base_source, head_source)
        records = _added_line_records_from_diff(diff_text)
        return cls(
            file_path=file_path, base_source=base_source, head_source=head_source,
            added_lines=tuple(r.content for r in records), diff=diff_text,
            is_complete_source=True, added_line_records=records,
            diff_is_synthetic=diff_is_synthetic,
        )


def _added_line_records_from_diff(diff_text: str) -> tuple[AddedLineRecord, ...]:
    """Collect additions using hunk coordinates; duplicate source lines are retained."""
    hunk_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    records: list[AddedLineRecord] = []
    head_lineno = 1
    hunk_index = -1
    seen_old = seen_new = 0
    old_count = new_count = 0
    in_hunk = False
    for raw in diff_text.splitlines():
        m = hunk_re.match(raw)
        if m:
            hunk_index += 1
            old_count = int(m.group(2)) if m.group(2) is not None else 1
            new_count = int(m.group(4)) if m.group(4) is not None else 1
            head_lineno = int(m.group(3)) if new_count or int(m.group(3)) else 1
            seen_old = seen_new = 0
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if seen_old >= old_count and seen_new >= new_count:
            in_hunk = False
            continue
        if raw.startswith("+"):
            # While hunk counts are outstanding, +++ can be a literal addition
            # whose source text begins with two plus signs.
            records.append(AddedLineRecord(head_lineno=head_lineno, hunk_index=hunk_index, content=raw[1:]))
            head_lineno += 1
            seen_new += 1
        elif raw.startswith("-"):
            seen_old += 1
        elif raw.startswith(" "):
            head_lineno += 1
            seen_old += 1
            seen_new += 1
        elif raw.startswith("\\ No newline at end of file"):
            continue
        else:
            in_hunk = False
    return tuple(records)


@dataclass(frozen=True)
class PipelineResult:
    """Findings plus the single verdict derived from them."""

    findings: tuple[VerificationFinding, ...]
    status: str
    rationale: str
    diff_bytes: int = 0
    gate_receipts: tuple[GateExecutionReceipt, ...] = ()
    required_gates_by_file: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def fail_findings(self) -> tuple[VerificationFinding, ...]:
        return tuple(f for f in self.findings if f.verdict == "FAIL")

    @property
    def inconclusive_findings(self) -> tuple[VerificationFinding, ...]:
        return tuple(
            f for f in self.findings if f.verdict in ("INCONCLUSIVE", "UNGROUNDED")
        )


def _synthetic_diff(file_path: str, base_source: str, head_source: str) -> str:
    """Unified diff for callers that supply complete sources rather than a diff.

    Removal provenance and the net-deletion check both read the diff text, so an
    entry built from raw sources still needs one. It is produced with
    `difflib.unified_diff` rather than by hand: a hand-rolled version that emitted
    only removals would make every ordinary edit look like a net deletion and fire
    a spurious ungrounded-removal finding.
    """
    if base_source == head_source:
        return ""
    lines = difflib.unified_diff(
        base_source.splitlines(),
        head_source.splitlines(),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    )
    return "\n".join(lines)


def _split_source_lines_preserve_endings(text: str) -> tuple[list[tuple[str, str]], str]:
    """Split source into (content, exact terminator) records and a dominant EOL."""
    records: list[tuple[str, str]] = []
    for raw in text.splitlines(keepends=True):
        if raw.endswith("\r\n"):
            records.append((raw[:-2], "\r\n"))
        elif raw.endswith("\n"):
            records.append((raw[:-1], "\n"))
        else:
            records.append((raw, ""))
    if not records and text:
        records.append((text, ""))
    counts = {"\n": sum(eol == "\n" for _, eol in records), "\r\n": sum(eol == "\r\n" for _, eol in records)}
    dominant = "\r\n" if counts["\r\n"] > counts["\n"] else "\n"
    return records, dominant


def _strip_patch_record_ending(raw: str) -> tuple[str, str]:
    if raw.endswith("\r\n"):
        return raw[:-2], "\r\n"
    if raw.endswith("\n"):
        return raw[:-1], "\n"
    return raw, ""


def apply_unified_diff_to_source(base_src: str, diff_text: str) -> str | None:
    """Apply a unified diff only when coordinates and old-side content match.

    The patch's own record terminators are transport formatting, not reliable
    source-file EOL metadata. Existing lines retain their exact terminators;
    added lines use the base file's dominant EOL (or LF for a new empty file).
    Git's explicit no-newline marker is validated and preserved.
    """
    hunk_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")
    patch_records: list[tuple[str, str]] = []
    for raw in diff_text.splitlines(keepends=True):
        content, patch_eol = _strip_patch_record_ending(raw)
        patch_records.append((content, patch_eol))

    base_lines, dominant_eol = _split_source_lines_preserve_endings(base_src)
    added_eol = dominant_eol if base_lines else "\n"
    hunks: list[dict[str, Any]] = []
    idx = 0
    while idx < len(patch_records):
        content, _ = patch_records[idx]
        match = hunk_re.match(content)
        if not match:
            # File metadata is legal only outside a hunk body.
            if content.startswith((
                "diff --git ", "index ", "--- ", "+++ ", "new file mode ",
                "deleted file mode ", "similarity index ", "rename from ",
                "rename to ", "old mode ", "new mode ", "copy from ", "copy to ",
            )):
                idx += 1
                continue
            if content == "\\ No newline at end of file":
                if not hunks or not hunks[-1]["lines"]:
                    return None
                line = hunks[-1]["lines"][-1]
                if line["op"] in ("-", " "):
                    line["old_no_eol"] = True
                if line["op"] in ("+", " "):
                    line["new_no_eol"] = True
                idx += 1
                continue
            return None

        old_start = int(match.group(1))
        old_count = int(match.group(2)) if match.group(2) is not None else 1
        new_start = int(match.group(3))
        new_count = int(match.group(4)) if match.group(4) is not None else 1
        hunk: dict[str, Any] = {
            "old_start": old_start, "old_count": old_count,
            "new_start": new_start, "new_count": new_count,
            "lines": [], "start_idx": -1,
        }
        hunks.append(hunk)
        idx += 1
        seen_old = seen_new = 0
        while seen_old < old_count or seen_new < new_count:
            if idx >= len(patch_records):
                return None
            body, _patch_eol = patch_records[idx]
            if body == "\\ No newline at end of file":
                if not hunk["lines"]:
                    return None
                line = hunk["lines"][-1]
                if line["op"] in ("-", " "):
                    line["old_no_eol"] = True
                if line["op"] in ("+", " "):
                    line["new_no_eol"] = True
                idx += 1
                continue
            # No unprefixed blank lines are valid hunk records. A source line
            # beginning with + or - still has its one required diff prefix.
            if not body or body[0] not in "+- ":
                return None
            op, line_content = body[0], body[1:]
            record = {"op": op, "content": line_content,
                      "old_no_eol": False, "new_no_eol": False}
            hunk["lines"].append(record)
            if op in ("-", " "):
                seen_old += 1
            if op in ("+", " "):
                seen_new += 1
            idx += 1
        if seen_old != old_count or seen_new != new_count:
            return None

    if not hunks:
        return None

    prev_old_end = 0
    cumulative_delta = 0
    seen_insertions: set[int] = set()
    old_pos_by_hunk: list[list[int]] = []
    for hunk in hunks:
        old_start, old_count = hunk["old_start"], hunk["old_count"]
        new_start, new_count = hunk["new_start"], hunk["new_count"]
        if old_count == 0:
            if old_start < 0 or old_start > len(base_lines):
                return None
            start_idx = old_start  # -0,0 inserts before the first line.
            if start_idx in seen_insertions or start_idx < prev_old_end:
                return None
            seen_insertions.add(start_idx)
        else:
            if old_start < 1:
                return None
            start_idx = old_start - 1
            if start_idx < prev_old_end or start_idx + old_count > len(base_lines):
                return None

        expected_new_start = (start_idx + cumulative_delta) if new_count == 0 else (start_idx + cumulative_delta + 1)
        if new_start != expected_new_start:
            return None

        old_side = [line for line in hunk["lines"] if line["op"] in ("-", " ")]
        new_side_count = sum(1 for line in hunk["lines"] if line["op"] in ("+", " "))
        if len(old_side) != old_count or new_side_count != new_count:
            return None
        actual_old = base_lines[start_idx:start_idx + old_count]
        if [line["content"] for line in old_side] != [content for content, _eol in actual_old]:
            return None

        # The marker is part of the patch's old/new source semantics, not just
        # formatting. Reject stale patches that omit or forge it for affected
        # EOF lines.
        for old_i, patch_line in enumerate(old_side):
            content, eol = actual_old[old_i]
            if patch_line["old_no_eol"] != (eol == ""):
                return None
            if eol == "" and start_idx + old_i != len(base_lines) - 1:
                return None

        hunk["start_idx"] = start_idx
        old_pos_by_hunk.append(list(range(start_idx, start_idx + old_count)))
        prev_old_end = start_idx + old_count
        cumulative_delta += new_count - old_count

    result = list(base_lines)
    for hunk in reversed(hunks):
        start_idx = hunk["start_idx"]
        old_count = hunk["old_count"]
        cursor = start_idx
        replacement: list[tuple[str, str]] = []
        for line in hunk["lines"]:
            op, content = line["op"], line["content"]
            if op == "-":
                cursor += 1
            elif op == " ":
                old_content, old_eol = base_lines[cursor]
                if old_content != content:
                    return None
                replacement.append((old_content, "" if line["new_no_eol"] else old_eol))
                cursor += 1
            else:
                eol = "" if line["new_no_eol"] else added_eol
                replacement.append((content, eol))
        result[start_idx:start_idx + old_count] = replacement

    # A missing line terminator may appear only on the final output line.
    # Store that fact on the line record itself so earlier hunks shifting line
    # positions cannot invalidate a legitimate EOF marker.
    for pos, (content, eol) in enumerate(result[:-1]):
        if not eol:
            return None
    if not result:
        return ""
    return "".join(content + eol for content, eol in result)


def unresolvable_added_imports(
    added_lines: Sequence[str],
    *,
    head_ast: IndexedAST | None = None,
    added_line_numbers: frozenset[int] | None = None,
) -> list[str]:
    """Return unresolved imports using indexed imports when compilation exists.

    The line-by-line parser remains only as a compatibility fallback for a
    diff-local reconstruction-failure path where no complete AST exists.
    """
    modules: set[str] = set()
    if head_ast is not None:
        line_filter = added_line_numbers
        for node in head_ast.imports:
            if line_filter is not None and getattr(node, "lineno", -1) not in line_filter:
                continue
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue
                if node.module:
                    modules.add(node.module.split(".")[0])
    else:
        for line in added_lines:
            text = line.strip()
            if not (text.startswith("import ") or text.startswith("from ")):
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    if not node.level and node.module:
                        modules.add(node.module.split(".")[0])

    unresolved: list[str] = []
    for module in sorted(modules):
        if not module or module in sys.stdlib_module_names:
            continue
        try:
            found = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError, ModuleNotFoundError):
            found = False
        if not found:
            unresolved.append(module)
    return unresolved


def repair_empty_bodies(source: str) -> str:
    """Gives a body to a ``def`` that a partial diff hunk left bodiless.

    A hunk can end immediately after a ``def`` header, producing
    ``def f(x):`` with no indented block - a syntax error that says nothing
    about the patch. Synthesising ``pass`` keeps the declaration parseable so
    the real checks run, instead of reporting a false syntax failure.
    """
    lines = source.splitlines()
    out: list[str] = []
    for idx, line in enumerate(lines):
        out.append(line)
        stripped = line.strip()
        is_block_header = (
            stripped.startswith("def ") or stripped.startswith("class ")
        ) and stripped.endswith(":")
        if not is_block_header:
            continue
        following = lines[idx + 1] if idx + 1 < len(lines) else ""
        if following.strip() and following[:1].isspace():
            continue  # an indented next line means this block already has a body
        indent = line[: len(line) - len(line.lstrip())]
        out.append(f"{indent}    pass")
    return "\n".join(out) + "\n"


def parse_unified_diff(diff_text: str) -> list[DiffFileEntry]:
    """Parse a unified diff into duplicate-safe, location-aware file entries.

    Existing-file patches are marked as fragments: callers must supply the
    content-verified base snapshot before treating them as whole source files.
    A complete new-file patch consists entirely of its added lines and can be
    compiled as a complete source revision.
    """
    file_chunks: list[list[str]] = []
    current: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if current:
                file_chunks.append(current)
            current = [line]
        elif not current and line.startswith("--- "):
            current = [line]
        else:
            current.append(line)
    if current:
        file_chunks.append(current)

    out: list[DiffFileEntry] = []
    hunk_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

    def path_from_header(line: str, prefix: str) -> str | None:
        if not line.startswith(prefix):
            return None
        value = line[len(prefix):].split("\t", 1)[0].strip()
        if value == "/dev/null":
            return value
        if value.startswith(("a/", "b/")):
            value = value[2:]
        return value

    for chunk in file_chunks:
        from_path: str | None = None
        to_path: str | None = None
        for line in chunk:
            if line.startswith("@@"):
                break
            if line.startswith("--- "):
                from_path = path_from_header(line, "--- ")
            elif line.startswith("+++ "):
                to_path = path_from_header(line, "+++ ")
        file_path = to_path if to_path not in (None, "/dev/null") else from_path
        if file_path in (None, "/dev/null"):
            # Fall back to git's `diff --git a/x b/x` header.
            header = next((line for line in chunk if line.startswith("diff --git ")), "")
            parts = header.split()
            if len(parts) >= 4:
                candidate = parts[3]
                file_path = candidate[2:] if candidate.startswith("b/") else candidate
        if not file_path or file_path == "/dev/null":
            continue

        base_lines: list[str] = []
        head_lines: list[str] = []
        records: list[AddedLineRecord] = []
        saw_hunks = False
        all_added_new_file = from_path == "/dev/null" and to_path not in (None, "/dev/null")
        all_deleted = to_path == "/dev/null"
        hunk_index = -1
        i = 0
        while i < len(chunk):
            line = chunk[i]
            m = hunk_re.match(line)
            if not m:
                i += 1
                continue
            saw_hunks = True
            hunk_index += 1
            old_count = int(m.group(2)) if m.group(2) is not None else 1
            new_count = int(m.group(4)) if m.group(4) is not None else 1
            new_lineno = int(m.group(3)) if int(m.group(4) or "1") else int(m.group(3)) + 1
            if new_count == 0 and int(m.group(3)) == 0:
                new_lineno = 1
            seen_old = seen_new = 0
            i += 1
            while i < len(chunk) and (seen_old < old_count or seen_new < new_count):
                body = chunk[i]
                if body.startswith("\\ No newline at end of file"):
                    i += 1
                    continue
                if not body or body[0] not in "+- ":
                    break
                op, content = body[0], body[1:]
                if op == "+":
                    head_lines.append(content)
                    records.append(AddedLineRecord(head_lineno=max(new_lineno, 1), hunk_index=hunk_index, content=content))
                    new_lineno += 1
                    seen_new += 1
                elif op == "-":
                    base_lines.append(content)
                    seen_old += 1
                else:
                    base_lines.append(content)
                    head_lines.append(content)
                    new_lineno += 1
                    seen_old += 1
                    seen_new += 1
                i += 1
            if seen_old != old_count or seen_new != new_count:
                # Preserve a non-complete fragment, but make reconstruction
                # fail closed when a real base snapshot is supplied.
                all_added_new_file = False
                break
        raw_diff = "\n".join(chunk)
        complete = all_added_new_file and saw_hunks and all(
            re.match(r"^@@ -(\d+),(\d+) \+(\d+),(\d+) @@", line)
            and int(re.match(r"^@@ -(\d+),(\d+) \+(\d+),(\d+) @@", line).group(2)) == 0
            for line in chunk if line.startswith("@@")
        )
        if all_deleted and saw_hunks:
            # The removed diff contains the whole deleted file only if the
            # hunk accounts for every old line; still retain fragment status
            # unless an external complete source is explicitly provided.
            complete = False
        out.append(DiffFileEntry(
            file_path=file_path,
            base_source="\n".join(base_lines),
            head_source="\n".join(head_lines),
            added_lines=tuple(r.content for r in records),
            diff=raw_diff,
            is_complete_source=complete,
            added_line_records=tuple(records),
        ))
    return out


_PASS_VERDICTS = frozenset({"PASS"})
_REQUIRED_PYTHON_GATES = (
    "RECONSTRUCTION_AND_SYNTAX", "NEW_MODULE_GATE", "REMOVAL_PROVENANCE",
    "UNRESOLVED_IMPORTS", "DANGEROUS_CALLS", "SECRETS_TAINT",
    "SYMBOLIC_PROVER", "CONCURRENCY_DATALOG",
)


def verdict_from_findings(
    findings: Sequence[VerificationFinding],
    gate_receipts: Sequence[GateExecutionReceipt] = (),
    required_gates_by_file: Mapping[str, tuple[str, ...]] | None = None,
) -> tuple[str, str]:
    """Closed fail-closed lattice with mandatory-gate completion verification."""
    fail_findings = [f for f in findings if getattr(f, "verdict", None) == "FAIL"]
    if fail_findings:
        return ("FAIL", f"Blocking invariant violations ({len(fail_findings)}): " + "; ".join(f.message for f in fail_findings[:3]))

    non_pass_findings = [f for f in findings if getattr(f, "verdict", None) not in _PASS_VERDICTS]
    if non_pass_findings:
        return ("INCONCLUSIVE", f"Verification inconclusive ({len(non_pass_findings)} non-passing/undecided checks): " + "; ".join(f.message for f in non_pass_findings[:3]))

    required = required_gates_by_file or {}
    receipts = {(r.file_path, r.gate_id): r.status for r in gate_receipts}
    for file_path, gate_ids in required.items():
        for gate_id in gate_ids:
            status = receipts.get((file_path, gate_id))
            if status not in ("COMPLETED", "SKIPPED_CACHE_HIT"):
                detail = f" (status={status})" if status else " (receipt missing)"
                return ("INCONCLUSIVE", f"Mandatory verification gate '{gate_id}' on '{file_path}' did not complete{detail}.")
    return "PASS", "All mandatory verification gates completed and no non-passing findings were emitted"


@dataclass
class VerificationPipeline:
    """Single execution owner for source reconstruction, compilation, and findings."""
    repo_id: str = "default-repo"
    smt_timeout_ms: int = _DEFAULT_SMT_TIMEOUT_MS
    base_sources: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.prover = Z3SymbolicProver(timeout_ms=self.smt_timeout_ms)
        self.secret_engine = TaintTrackedSecretEngine()
        self.egglog = EgglogEquivalenceEngine()

    def verify_files(self, entries: Sequence[DiffFileEntry]) -> PipelineResult:
        findings: list[VerificationFinding] = []
        receipts: list[GateExecutionReceipt] = []
        required: dict[str, tuple[str, ...]] = {}
        for entry in entries:
            findings.extend(self._verify_file(entry, gate_receipts=receipts, required_gates_by_file=required))
        if entries and not required:
            # A missing gate plan is an orchestration defect, not a clean run.
            findings.append(VerificationFinding(
                finding_id=finding_id("GATE_LEDGER_MISSING", *(e.file_path for e in entries)),
                rule_id="VC2-MANDATORY-GATE-LEDGER-MISSING",
                severity="HIGH", verdict="INCONCLUSIVE", file_path=entries[0].file_path,
                start_line=1, end_line=1,
                message="No mandatory-gate plan was recorded for a non-empty verification request.",
            ))
        status, rationale = verdict_from_findings(findings, receipts, required)
        return PipelineResult(
            findings=tuple(findings), status=status, rationale=rationale,
            diff_bytes=sum(len(e.diff.encode("utf-8")) for e in entries),
            gate_receipts=tuple(receipts), required_gates_by_file=MappingProxyType(dict(required)),
        )

    def _verify_file(
        self,
        entry: DiffFileEntry,
        *,
        gate_receipts: list[GateExecutionReceipt] | None = None,
        required_gates_by_file: dict[str, tuple[str, ...]] | None = None,
    ) -> list[VerificationFinding]:
        findings: list[VerificationFinding] = []
        path = entry.file_path
        receipt_sink = gate_receipts
        required_sink = required_gates_by_file

        def receipt(gate_id: str, status: GateStatus = "COMPLETED", detail: str = "") -> None:
            if receipt_sink is not None:
                receipt_sink.append(GateExecutionReceipt(gate_id=gate_id, file_path=path, status=status, detail=detail))

        if not path.endswith(".py"):
            if required_sink is not None:
                required_sink[path] = ("NON_PYTHON_SECRET_SCAN",)
            findings.extend(self._scan_non_python_added_lines(entry))
            receipt("NON_PYTHON_SECRET_SCAN")
            return findings

        if required_sink is not None:
            required_sink[path] = _REQUIRED_PYTHON_GATES

        added_records = entry.added_line_records or _added_line_records_from_diff(entry.diff)
        added_lines = tuple(r.content for r in added_records) if added_records else entry.added_lines
        diff_changed_lines = [ln.strip() for ln in added_lines if ln.strip()]
        is_comment_only = bool(diff_changed_lines) and all(ln.startswith("#") for ln in diff_changed_lines)
        if is_comment_only:
            from verifyci_v2.symbolic.secrets_taint import _SECRET_PATTERNS
            secret_findings: list[VerificationFinding] = []
            for rec in (added_records or tuple(AddedLineRecord(head_lineno=i, hunk_index=0, content=line) for i, line in enumerate(added_lines, 1))):
                for rule_name, pat in _SECRET_PATTERNS:
                    if pat.search(rec.content):
                        secret_findings.append(self._finding(
                            "SECRET_REGEX", path, str(rec.head_lineno), rule_id=f"VC2-SECRET-{rule_name}",
                            severity="CRITICAL", verdict="FAIL",
                            message=f"Credential pattern ({rule_name}) detected in comment of '{path}'.",
                            start_line=rec.head_lineno, end_line=rec.head_lineno,
                        ))
            if required_sink is not None:
                required_sink[path] = ("COMMENT_ONLY_SECRET_SCAN",)
            findings.extend(secret_findings)
            receipt("COMMENT_ONLY_SECRET_SCAN")
            return findings

        stored_present = path in self.base_sources
        stored_source = self.base_sources[path] if stored_present else None
        compiled = compile_file_pair(entry, stored_source=stored_source, repo_id=self.repo_id)

        if compiled.reconstruction_failed:
            findings.append(self._finding(
                "DIFF_RECONSTRUCTION", path, rule_id="VC2-DIFF-RECONSTRUCTION-FAILED",
                severity="HIGH", verdict="INCONCLUSIVE",
                message=f"Unified diff for '{path}' could not be applied exactly to its stored base snapshot; whole-file analysis was aborted.",
            ))
            receipt("RECONSTRUCTION_AND_SYNTAX", "ABSTAINED_RECONSTRUCTION_FAILED")
            if stored_source is not None:
                findings.extend(self._check_removal_provenance(entry, stored_source))
            # Keep independent, diff-local detection alive: the invalid context
            # cannot suppress a clear danger/secret pattern in an added line.
            findings.extend(self._scan_added_line_secrets(path, added_records or tuple(AddedLineRecord(head_lineno=i, hunk_index=0, content=line) for i, line in enumerate(added_lines, 1))))
            findings.extend(self._scan_diff_local_dangerous(path, added_records or tuple(AddedLineRecord(head_lineno=i, hunk_index=0, content=line) for i, line in enumerate(added_lines, 1))))
            for gate_id in _REQUIRED_PYTHON_GATES[1:]:
                receipt(gate_id, "ABSTAINED_RECONSTRUCTION_FAILED", "full-source artifact unavailable")
            return findings

        if compiled.syntax_error is not None:
            findings.append(compiled.syntax_error)
            receipt("RECONSTRUCTION_AND_SYNTAX", "COMPLETED")
            # A complete-source syntax error is itself a FAIL. Remaining source
            # dependent gates are explicitly marked incomplete, not silently skipped.
            for gate_id in _REQUIRED_PYTHON_GATES[1:]:
                receipt(gate_id, "FAILED_CLOSED_ERROR", "AST/U-SSA artifact unavailable")
            # Diff-local checks still add independent findings for malformed source.
            findings.extend(self._scan_added_line_secrets(path, added_records or tuple(AddedLineRecord(head_lineno=i, hunk_index=0, content=line) for i, line in enumerate(added_lines, 1))))
            findings.extend(self._scan_diff_local_dangerous(path, added_records or tuple(AddedLineRecord(head_lineno=i, hunk_index=0, content=line) for i, line in enumerate(added_lines, 1))))
            return findings

        # Successful content reconstruction and compilation own all downstream input.
        base_src, head_src = compiled.base_source, compiled.head_source
        base_tree = compiled.base_ast.tree if compiled.base_ast is not None else None
        head_tree = compiled.head_ast.tree if compiled.head_ast is not None else None
        receipt("RECONSTRUCTION_AND_SYNTAX")

        if not base_src.strip():
            findings.append(self._finding(
                "NEWFILE", path, rule_id="VC2-NEW-MODULE-UNVERIFIED", severity="MEDIUM",
                verdict="INCONCLUSIVE", message=f"New module '{path}' has no baseline to verify against; failing closed.",
            ))
        receipt("NEW_MODULE_GATE")

        if compiled.has_stored_base or compiled.is_complete_source:
            # A complete explicit base/head pair is valid baseline evidence even
            # when it did not originate in the persistent snapshot store.
            findings.extend(self._check_removal_provenance(
                entry, base_src, prelowered_funcs=tuple(compiled.base_ussa.values())
            ))
        else:
            removed = [ln for ln in entry.diff.splitlines() if ln.startswith("-") and not ln.startswith("---")]
            added = [ln for ln in entry.diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
            if len(removed) > len(added):
                findings.append(self._finding(
                    "REM_UNGROUNDED", path, rule_id="VC2-REMOVAL-NO-BASE-RECORD", severity="MEDIUM",
                    verdict="INCONCLUSIVE", message=f"Diff removes {len(removed)} line(s) from '{path}' but no complete base revision is available; the removal cannot be verified.",
                ))
        receipt("REMOVAL_PROVENANCE")

        added_numbers = frozenset(r.head_lineno for r in added_records)
        for module in unresolvable_added_imports(added_lines, head_ast=compiled.head_ast, added_line_numbers=added_numbers):
            findings.append(self._finding(
                "UNRESOLVED", path, module, rule_id="VC2-UNRESOLVED-IMPORT", severity="MEDIUM",
                verdict="INCONCLUSIVE", message=f"Patch adds an import of '{module}', which does not resolve in this environment. Failing closed.",
            ))
        receipt("UNRESOLVED_IMPORTS")

        findings.extend(self._scan_dangerous_calls(path, head_src, preparsed_tree=head_tree))
        receipt("DANGEROUS_CALLS")
        try:
            findings.extend(self.secret_engine.scan_python_source(
                path, head_src, preparsed_tree=head_tree,
                prelowered_funcs=tuple(compiled.head_ussa.values()),
            ))
        except Exception as exc:
            findings.append(self._finding("SEC_ERR", path, rule_id="VC2-SECRET-ENGINE-ERROR", severity="HIGH", verdict="INCONCLUSIVE", message=f"Secret taint engine failed closed on '{path}': {exc}"))
        receipt("SECRETS_TAINT")

        prove_f = self._prove_functions(path, base_src, head_src, added_lines, compiled=compiled)
        findings.extend(prove_f)
        receipt("SYMBOLIC_PROVER")
        findings.extend(self._check_concurrency(path, head_src, preparsed_tree=head_tree))
        receipt("CONCURRENCY_DATALOG")

        # Detect accidental mutation of retained AST nodes by any pass.
        for index in (compiled.base_ast, compiled.head_ast):
            if index is not None and not index.verify_unmutated():
                findings.append(self._finding(
                    "AST_MUTATION", path, rule_id="VC2-AST-ARTIFACT-MUTATED", severity="HIGH",
                    verdict="INCONCLUSIVE", message=f"A verification pass mutated the retained AST for '{path}'.",
                ))
        return findings

    def _scan_added_line_secrets(self, file_path: str, records: Sequence[AddedLineRecord]) -> list[VerificationFinding]:
        """Detect high-confidence secrets in untrusted added lines after failed reconstruction.

        This check intentionally does not pretend a partial diff is a complete
        Python module. It combines the engine's lexical credential rules with
        its config-style high-entropy credential-name rule, preserving the real
        head line number for each added line.
        """
        from verifyci_v2.symbolic.secrets_taint import _SECRET_PATTERNS
        out: list[VerificationFinding] = []
        for rec in records:
            for rule_name, pattern in _SECRET_PATTERNS:
                if pattern.search(rec.content):
                    out.append(self._finding(
                        "SECRET_REGEX", file_path, str(rec.head_lineno),
                        rule_id=f"VC2-SECRET-{rule_name}", severity="CRITICAL",
                        verdict="FAIL",
                        message=f"Credential pattern ({rule_name}) detected in added line {rec.head_lineno} of '{file_path}'.",
                        start_line=rec.head_lineno, end_line=rec.head_lineno,
                    ))
            try:
                config_findings = self.secret_engine.scan_config_lines(file_path, [rec.content])
            except Exception as exc:
                out.append(self._finding(
                    "DIFF_SECRET_SCAN_ERROR", file_path, str(rec.head_lineno),
                    rule_id="VC2-DIFF-LOCAL-SECRET-SCAN-ERROR", severity="HIGH",
                    verdict="INCONCLUSIVE",
                    message=f"Diff-local credential scanner failed at {file_path}:{rec.head_lineno}: {type(exc).__name__}: {exc}",
                    start_line=rec.head_lineno, end_line=rec.head_lineno,
                ))
                continue
            for finding in config_findings:
                # The config helper sees a one-line fragment as line 1; rebind
                # both identity and location to the original hunk coordinate.
                out.append(self._finding(
                    "DIFF_CONFIG_SECRET", file_path, str(rec.head_lineno), finding.rule_id,
                    rule_id=finding.rule_id, severity=finding.severity,
                    verdict="FAIL", message=finding.message,
                    start_line=rec.head_lineno, end_line=rec.head_lineno,
                ))
        # Deduplicate findings that can be discovered by both direct pattern and
        # config-style detection without losing repeated source-line locations.
        seen: set[tuple[str, int, str]] = set()
        unique: list[VerificationFinding] = []
        for finding in out:
            key = (finding.rule_id, finding.start_line, finding.message)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique

    def _scan_diff_local_dangerous(self, file_path: str, records: Sequence[AddedLineRecord]) -> list[VerificationFinding]:
        # Parse only added fragments, never pretending that a partial hunk is a
        # complete module. A wrapper is attempted once for an indented fragment.
        out: list[VerificationFinding] = []
        for rec in records:
            text = textwrap.dedent(rec.content)
            source = text
            offset = 0
            try:
                tree = ast.parse(source, filename=file_path)
            except (SyntaxError, ValueError, IndentationError):
                source = "def __vc2_fragment__():\n" + textwrap.indent(text, "    ") + "\n"
                offset = 1
                try:
                    tree = ast.parse(source, filename=file_path)
                except (SyntaxError, ValueError, IndentationError):
                    continue
            for finding in scan_dangerous_calls(file_path, source, preparsed_tree=tree):
                line = max(1, rec.head_lineno + finding.start_line - offset - 1)
                out.append(self._finding("DIFF_DANGER", file_path, str(line), finding.rule_id, rule_id=finding.rule_id, severity=finding.severity, verdict="FAIL", message=finding.message, start_line=line, end_line=line))
        return out

    def _scan_non_python_added_lines(
        self, entry: DiffFileEntry
    ) -> list[VerificationFinding]:
        out: list[VerificationFinding] = []
        for line_idx, line in enumerate(entry.added_lines, start=1):
            if any(pat.search(line) for pat in _NON_PYTHON_SECRET_PATTERNS):
                out.append(
                    self._finding(
                        "SECRET_REGEX",
                        entry.file_path,
                        str(line_idx),
                        rule_id="VC2-SECRET-LEAK",
                        severity="CRITICAL",
                        verdict="FAIL",
                        message=(
                            "Critical secret or credential token detected in added "
                            f"lines of '{entry.file_path}'."
                        ),
                    )
                )
        return out

    def _scan_secrets(self, file_path: str, head_src: str) -> list[VerificationFinding]:
        # Fail closed: a checker crash is never a silent pass.
        try:
            return list(self.secret_engine.scan_python_source(file_path, head_src))
        except Exception as exc:
            return [
                self._finding(
                    "SEC_ERR",
                    file_path,
                    rule_id="VC2-SECRET-ENGINE-ERROR",
                    severity="HIGH",
                    verdict="INCONCLUSIVE",
                    message=(
                        f"Secret taint engine failed closed on '{file_path}': {exc}"
                    ),
                )
            ]

    def _check_removal_provenance(
        self,
        entry: DiffFileEntry,
        stored_source: str,
        *,
        prelowered_funcs: tuple[Any, ...] | None = None,
    ) -> list[VerificationFinding]:
        file_path = entry.file_path
        try:
            provenance = analyze_removal_provenance(
                entry.diff,
                entities_from_source(file_path, stored_source, prelowered_funcs=prelowered_funcs),
            )
        except Exception as exc:
            return [
                self._finding(
                    "REM_ERR",
                    file_path,
                    rule_id="VC2-CAP003A-ENGINE-ERROR",
                    severity="HIGH",
                    verdict="INCONCLUSIVE",
                    message=(
                        f"Removal provenance checker failed closed on "
                        f"'{file_path}': {exc}"
                    ),
                )
            ]

        if provenance.verdict == "FABRICATED":
            return [
                self._finding(
                    "FABRICATED",
                    file_path,
                    rule_id="VC2-CAP003A-FABRICATED-REMOVAL",
                    severity="CRITICAL",
                    verdict="FAIL",
                    message=(
                        "Diff removes code that was not present at the claimed "
                        f"offsets in the stored base revision of '{file_path}' "
                        f"({provenance.fabricated_lines} line(s)); the diff is "
                        "stale or forged."
                    ),
                )
            ]
        if provenance.verdict == "INCONCLUSIVE" or (
            provenance.unverified_lines and not provenance.verified_lines
        ):
            return [
                self._finding(
                    "REM_UNVERIFIED",
                    file_path,
                    rule_id="VC2-CAP003A-REMOVAL-UNVERIFIED",
                    severity="LOW",
                    verdict="INCONCLUSIVE",
                    message=(
                        "No stored entity record covers the lines removed from "
                        f"'{file_path}'; absence of a record is not contradiction."
                    ),
                )
            ]
        return []

    def _scan_dangerous_calls(
        self, file_path: str, head_src: str, *, preparsed_tree: ast.Module | None = None
    ) -> list[VerificationFinding]:
        # Independent of the symbolic prover so a proven-equivalent diff cannot
        # suppress a safety finding.
        try:
            return list(scan_dangerous_calls(file_path, head_src, preparsed_tree=preparsed_tree))
        except Exception as exc:
            return [
                self._finding(
                    "DANGEROUS_ERR",
                    file_path,
                    rule_id="VC2-DANGEROUS-CALL-ERROR",
                    severity="HIGH",
                    verdict="INCONCLUSIVE",
                    message=(
                        f"Dangerous-call checker failed closed on '{file_path}': {exc}"
                    ),
                )
            ]

    def _prove_functions(
        self,
        file_path: str,
        base_src: str,
        head_src: str,
        added_lines: Sequence[str],
        *,
        compiled: CompiledFilePair | None = None,
    ) -> list[VerificationFinding]:
        findings: list[VerificationFinding] = []
        if compiled is None:
            # Compatibility callers still go through the compilation owner. Do
            # not parse/lower independently inside the verification pass.
            compiled = compile_file_pair(
                DiffFileEntry.from_sources(file_path, base_src, head_src),
                repo_id=self.repo_id,
            )
        if compiled.reconstruction_failed:
            return [self._finding(
                "DIFF_RECONSTRUCTION", file_path,
                rule_id="VC2-DIFF-RECONSTRUCTION-FAILED", severity="HIGH",
                verdict="INCONCLUSIVE",
                message=f"Unified diff for '{file_path}' could not be reconstructed exactly.",
            )]
        if compiled.syntax_error is not None:
            return [compiled.syntax_error]
        funcs_b = dict(compiled.base_ussa)
        funcs_h = dict(compiled.head_ussa)

        if not funcs_h:
            # The changed lines are an excerpt from inside a scope the hunk never
            # shows, so no enclosing function could be located and nothing was
            # analysed. Certifying PASS here would vouch for a change that was
            # never examined. A column-zero hunk is module-level code, which the
            # other checks already cover.
            if any(ln[:1].isspace() for ln in added_lines if ln.strip()):
                findings.append(
                    self._finding(
                        "NOSCOPE",
                        file_path,
                        rule_id="VC2-NO-DEFINABLE-SCOPE",
                        severity="MEDIUM",
                        verdict="INCONCLUSIVE",
                        message=(
                            f"Changed lines in '{file_path}' belong to a scope with "
                            "no function definition in the hunk, so no enclosing "
                            "function could be verified. Failing closed."
                        ),
                    )
                )
            return findings

        for qname, fh in funcs_h.items():
            fb = funcs_b.get(qname)
            if fb is None:
                # New functions have no base semantics to compare; fail closed.
                findings.append(self._finding(
                    "NEW_FUNCTION", file_path, qname, rule_id="VC2-NEW-FUNCTION-UNVERIFIED",
                    severity="MEDIUM", verdict="INCONCLUSIVE",
                    start_line=fh.start_line, end_line=fh.end_line,
                    message=f"New function '{qname}' has no base revision for equivalence verification.",
                ))
                continue
            if fb.h_body == fh.h_body and fb.h_interface == fh.h_interface:
                continue
            base_node = compiled.base_ast.functions_by_qname.get(qname) if compiled and compiled.base_ast else None
            head_node = compiled.head_ast.functions_by_qname.get(qname) if compiled and compiled.head_ast else None
            diff_findings = self.prover.prove_function_diff(
                file_path=file_path, base_source=base_src, head_source=head_src,
                func_base=fb, func_head=fh,
                base_fn_node=base_node, head_fn_node=head_node,
            )
            findings.extend(diff_findings)
            if any(f.verdict == "FAIL" for f in diff_findings):
                continue
            proof = self.prover.prove_equivalence(
                base_source=base_src, cand_source=head_src,
                func_base=fb, func_cand=fh,
                base_fn_node=base_node, cand_fn_node=head_node,
            )
            if proof.is_equivalent and proof.smt_status == "UNSAT":
                continue
            if proof.smt_status == "SAT" and proof.witness is not None:
                findings.append(self._finding(
                    "DIVERGE", file_path, qname, rule_id="VC2-Z3-SEMANTIC-DIVERGENCE",
                    severity="HIGH", verdict="FAIL", start_line=fh.start_line,
                    end_line=fh.end_line,
                    message=f"Z3 produced a validated counterexample proving semantic divergence for '{qname}'.",
                ))
            else:
                rule_id = (
                    "VC2-Z3-SOLVER-UNAVAILABLE"
                    if proof.outcome == "INCONCLUSIVE_SOLVER_UNAVAILABLE"
                    else "VC2-Z3-UNDECIDED-DIFF"
                )
                findings.append(self._finding(
                    "UNDECIDED", file_path, qname, rule_id=rule_id,
                    severity="HIGH", verdict="INCONCLUSIVE", start_line=fh.start_line,
                    end_line=fh.end_line,
                    message=f"Z3 could not establish equivalence for '{qname}' (outcome={proof.outcome}, reason={proof.reason}); fail-closed INCONCLUSIVE.",
                ))
        return findings

    def _check_concurrency(
        self, file_path: str, head_src: str, *, preparsed_tree: ast.Module | None = None
    ) -> list[VerificationFinding]:
        try:
            return list(self.egglog.datalog_concurrency_invariants(file_path, head_src, preparsed_tree=preparsed_tree))
        except Exception as exc:
            # Fail closed: an unrunnable concurrency invariant check is not
            # evidence that the invariant holds.
            return [
                self._finding(
                    "CONC_ERR",
                    file_path,
                    rule_id="VC2-CONCURRENCY-ENGINE-ERROR",
                    severity="HIGH",
                    verdict="INCONCLUSIVE",
                    message=(
                        f"Concurrency invariant engine failed closed on "
                        f"'{file_path}': {exc}"
                    ),
                )
            ]

    @staticmethod
    def _finding(
        kind: str,
        file_path: str,
        *parts: str,
        rule_id: str,
        severity: str,
        verdict: str,
        message: str,
        start_line: int = 1,
        end_line: int = 1,
    ) -> VerificationFinding:
        return VerificationFinding(
            finding_id=finding_id(kind, file_path, *parts),
            rule_id=rule_id,
            severity=severity,  # type: ignore[arg-type]
            verdict=verdict,  # type: ignore[arg-type]
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            message=message,
        )


@dataclass(frozen=True)
class _SourceParse:
    """Compatibility result for callers that only need syntax status.

    Core verification must use :func:`compile_file_pair`, which owns AST and
    U-SSA artifacts. This compatibility helper deliberately does not repair or
    reparse fragments: fragment normalization belongs to the compiler owner.
    """

    base_source: str
    head_source: str
    error: VerificationFinding | None = None


def parse_file_sources(
    file_path: str, base_src: str, head_src: str
) -> _SourceParse:
    """Legacy syntax check with at most one parser call per non-empty revision."""
    for source, label in ((base_src, "base"), (head_src, "head")):
        if not source:
            continue
        try:
            ast.parse(source, filename=file_path)
        except (SyntaxError, ValueError, IndentationError) as exc:
            return _SourceParse(
                base_source=base_src,
                head_source=head_src,
                error=VerificationFinding(
                    finding_id=finding_id("SYNTAX", file_path, label, str(exc.lineno or 1)),
                    rule_id="VC2-AST-SYNTAX-ERROR",
                    severity="CRITICAL",
                    verdict="FAIL",
                    file_path=file_path,
                    start_line=exc.lineno or 1,
                    end_line=exc.lineno or 1,
                    message=f"Syntax error in {label} code of '{file_path}': {exc}",
                ),
            )
    return _SourceParse(base_source=base_src, head_source=head_src)
