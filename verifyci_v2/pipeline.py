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
from typing import Sequence

from verifyci_v2.contracts.attestation import VerificationFinding
from verifyci_v2.contracts.canonical import content_digest_hex
from verifyci_v2.ingestion.removal_provenance import (
    analyze_removal_provenance,
    entities_from_source,
)
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
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
    """One file's worth of change, as the pipeline needs it.

    Both entry points normalise into this shape: the CLI builds it from a parsed
    unified diff, the daemon from the explicit `base_source`/`head_source`
    arguments it already receives.
    """

    file_path: str
    base_source: str
    head_source: str
    added_lines: tuple[str, ...] = ()
    # Raw hunk text with original @@ offsets, needed by removal provenance to
    # resolve old-side line numbers.
    diff: str = ""

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    @classmethod
    def from_sources(
        cls,
        file_path: str,
        base_source: str,
        head_source: str,
        diff: str = "",
    ) -> DiffFileEntry:
        """Build an entry directly from sources, deriving `added_lines`.

        Used by entry points that are handed complete sources rather than a diff.
        `diff` still drives removal provenance when the caller has it.
        """
        added = tuple(
            line
            for line in head_source.splitlines()
            if line.strip() and line not in base_source.splitlines()
        )
        return cls(
            file_path=file_path,
            base_source=base_source,
            head_source=head_source,
            added_lines=added,
            diff=diff or _synthetic_diff(file_path, base_source, head_source),
        )


@dataclass(frozen=True)
class PipelineResult:
    """Findings plus the single verdict derived from them."""

    findings: tuple[VerificationFinding, ...]
    status: str
    rationale: str
    diff_bytes: int = 0

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
    lines = difflib.unified_diff(
        base_source.splitlines(),
        head_source.splitlines(),
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    )
    return "\n".join(lines)


def apply_unified_diff_to_source(base_src: str, diff_text: str) -> str | None:
    """Applies a unified diff hunk series to a base source string to reconstruct full head source."""
    hunk_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    hunks = []
    current_hunk = None
    for line in diff_text.splitlines():
        m = hunk_re.match(line)
        if m:
            old_start = int(m.group(1))
            old_count = int(m.group(2)) if m.group(2) else 1
            current_hunk = {
                "old_start": old_start,
                "old_count": old_count,
                "lines": [],
            }
            hunks.append(current_hunk)
        elif current_hunk is not None:
            if line.startswith(("+", "-", " ")):
                current_hunk["lines"].append(line)
    if not hunks:
        return None
    base_lines = base_src.splitlines()
    res = list(base_lines)
    for h in sorted(hunks, key=lambda x: x["old_start"], reverse=True):
        start = h["old_start"] - 1
        count = h["old_count"]
        if start < 0 or start + count > len(res):
            return None
        new_lines = []
        for l in h["lines"]:
            if l.startswith(("+", " ")):
                new_lines.append(l[1:])
        res[start : start + count] = new_lines
    return "\n".join(res)



def unresolvable_added_imports(added_lines: Sequence[str]) -> list[str]:
    """Top-level modules a patch newly imports that do not resolve here.

    A dependency that cannot be resolved is a surface the patch cannot be
    verified against: the code using it cannot be analysed and its origin
    cannot be checked. Relative imports are skipped because they name code
    inside the repository rather than an external dependency.
    """
    modules: set[str] = set()
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
                if node.level and node.level > 0:
                    continue
                if node.module:
                    modules.add(node.module.split(".")[0])

    unresolved: list[str] = []
    for module in sorted(modules):
        if not module or module in sys.stdlib_module_names:
            continue
        try:
            found = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
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
    """Parses a unified diff into per-file `DiffFileEntry` chunks."""
    files: list[DiffFileEntry] = []
    current_file: str | None = None
    base_lines: list[str] = []
    head_lines: list[str] = []
    added_lines: list[str] = []
    raw_lines: list[str] = []

    def flush_current() -> None:
        if current_file:
            files.append(
                DiffFileEntry(
                    file_path=current_file,
                    base_source="\n".join(base_lines),
                    head_source="\n".join(head_lines),
                    added_lines=tuple(added_lines),
                    # Raw hunk text with original @@ offsets, needed by
                    # removal provenance to resolve old-side line numbers.
                    diff="\n".join(raw_lines),
                )
            )

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            # A new file header ends the previous file's chunk. Without this
            # boundary the *next* file's `diff --git` line is appended to the
            # current file's reconstructed source, which then fails to parse
            # and is reported as a syntax error in an unrelated file.
            flush_current()
            current_file = None
            base_lines = []
            head_lines = []
            added_lines = []
            raw_lines = [line]
        elif line.startswith("--- a/") or line.startswith("--- b/"):
            flush_current()
            current_file = line[6:].strip()
            base_lines = []
            head_lines = []
            added_lines = []
            raw_lines = [line]
        elif line.startswith("+++ b/") or line.startswith("+++ a/"):
            current_file = line[6:].strip()
            raw_lines.append(line)
        elif line.startswith("@@"):
            raw_lines.append(line)
        elif current_file is not None:
            raw_lines.append(line)
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])
                head_lines.append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                base_lines.append(line[1:])
            elif line.startswith(" ") or line == "":
                base_lines.append(line[1:] if line else "")
                head_lines.append(line[1:] if line else "")
    flush_current()
    return files


def verdict_from_findings(findings: Sequence[VerificationFinding]) -> tuple[str, str]:
    """The single verdict precedence rule: FAIL > INCONCLUSIVE/UNGROUNDED > PASS.

    Uncertainty never becomes a pass. Every entry point calls this so the same
    findings always produce the same verdict, whatever called them.
    """
    fail_findings = [f for f in findings if f.verdict == "FAIL"]
    inc_findings = [
        f for f in findings if f.verdict in ("INCONCLUSIVE", "UNGROUNDED")
    ]
    if fail_findings:
        return (
            "FAIL",
            f"Blocking invariant violations ({len(fail_findings)}): "
            + "; ".join(f.message for f in fail_findings[:3]),
        )
    if inc_findings:
        return (
            "INCONCLUSIVE",
            f"Verification inconclusive ({len(inc_findings)} checks outside "
            "decidable fragment): "
            + "; ".join(f.message for f in inc_findings[:3]),
        )
    return "PASS", "All verified contracts and invariant gates satisfied in diff"


@dataclass
class VerificationPipeline:
    """Runs every check over a set of changed files and derives the verdict.

    Holds the engines rather than constructing one per call, so repeated calls
    (daemon session, CLI over a multi-file diff) reuse the same prover state.
    """

    repo_id: str = "default-repo"
    smt_timeout_ms: int = _DEFAULT_SMT_TIMEOUT_MS
    base_sources: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.prover = Z3SymbolicProver(timeout_ms=self.smt_timeout_ms)
        self.secret_engine = TaintTrackedSecretEngine()
        self.egglog = EgglogEquivalenceEngine()

    def verify_files(self, entries: Sequence[DiffFileEntry]) -> PipelineResult:
        findings: list[VerificationFinding] = []
        for entry in entries:
            findings.extend(self._verify_file(entry))
        status, rationale = verdict_from_findings(findings)
        return PipelineResult(
            findings=tuple(findings),
            status=status,
            rationale=rationale,
            diff_bytes=sum(len(e.diff.encode("utf-8")) for e in entries),
        )

    # --- per-file checks -------------------------------------------------

    def _verify_file(self, entry: DiffFileEntry) -> list[VerificationFinding]:
        findings: list[VerificationFinding] = []
        file_path = entry.file_path
        base_src = entry.base_source
        head_src = entry.head_source

        if not file_path.endswith(".py"):
            findings.extend(self._scan_non_python_added_lines(entry))
            return findings

        diff_changed_lines = [
            ln[1:].strip()
            for ln in entry.diff.splitlines()
            if ln.startswith(("+", "-")) and not ln.startswith(("+++", "---")) and ln[1:].strip()
        ]
        is_comment_only = bool(diff_changed_lines) and all(
            ln.startswith("#") for ln in diff_changed_lines
        )
        if is_comment_only:
            from verifyci_v2.symbolic.secrets_taint import _SECRET_PATTERNS

            sec_findings = []
            for line_idx, line in enumerate(entry.added_lines, start=1):
                for rule_name, pat in _SECRET_PATTERNS:
                    if pat.search(line):
                        sec_findings.append(
                            self._finding(
                                "SECRET_REGEX",
                                file_path,
                                str(line_idx),
                                rule_id=f"VC2-SECRET-{rule_name}",
                                severity="CRITICAL",
                                verdict="FAIL",
                                message=(
                                    f"Credential pattern ({rule_name}) detected in comment of '{file_path}'."
                                ),
                            )
                        )
            return sec_findings

        if not base_src.strip():
            # A newly added module has no baseline, so equivalence is not
            # decidable. Fail closed rather than reporting PASS on an
            # unverified surface.
            findings.append(
                self._finding(
                    "NEWFILE",
                    file_path,
                    rule_id="VC2-NEW-MODULE-UNVERIFIED",
                    severity="MEDIUM",
                    verdict="INCONCLUSIVE",
                    message=(
                        f"New module '{file_path}' has no baseline to verify "
                        "against; failing closed."
                    ),
                )
            )

        findings.extend(self._scan_secrets(file_path, head_src))

        stored_source = self.base_sources.get(file_path)
        if not stored_source:
            # Fail closed on an ungrounded removal. A removal cannot be
            # verified against nothing: without the base revision there is no
            # record to confirm the removed lines ever existed. Only a NET
            # deletion counts; keying on raw removals would abstain on ordinary
            # equivalence-preserving rewrites.
            removed = [
                ln
                for ln in entry.diff.splitlines()
                if ln.startswith("-") and not ln.startswith("---")
            ]
            added = [
                ln
                for ln in entry.diff.splitlines()
                if ln.startswith("+") and not ln.startswith("+++")
            ]
            if len(removed) > len(added):
                findings.append(
                    self._finding(
                        "REM_UNGROUNDED",
                        file_path,
                        rule_id="VC2-REMOVAL-NO-BASE-RECORD",
                        severity="MEDIUM",
                        verdict="INCONCLUSIVE",
                        message=(
                            f"Diff removes {len(removed)} line(s) from '{file_path}' "
                            "but no stored base revision is available; the removal "
                            "cannot be verified. Failing closed."
                        ),
                    )
                )
        else:
            findings.extend(self._check_removal_provenance(entry, stored_source))

        findings.extend(self._scan_dangerous_calls(file_path, head_src))

        parse = parse_file_sources(file_path, base_src, head_src)
        if parse.error is not None:
            if stored_source:
                recon = apply_unified_diff_to_source(stored_source, entry.diff)
                if recon is not None:
                    parse_full = parse_file_sources(file_path, stored_source, recon)
                    if parse_full.error is None:
                        base_src = parse_full.base_source
                        head_src = parse_full.head_source
                        parse = parse_full
            if parse.error is not None:
                findings.append(parse.error)
                return findings
        else:
            base_src, head_src = parse.base_source, parse.head_source

        for module in unresolvable_added_imports(entry.added_lines):
            findings.append(
                self._finding(
                    "UNRESOLVED",
                    file_path,
                    module,
                    rule_id="VC2-UNRESOLVED-IMPORT",
                    severity="MEDIUM",
                    verdict="INCONCLUSIVE",
                    message=(
                        f"Patch adds an import of '{module}', which does not "
                        "resolve in this environment. The dependency's origin "
                        "and the code using it cannot be verified. Failing closed."
                    ),
                )
            )

        prove_f = self._prove_functions(file_path, base_src, head_src, entry.added_lines)
        if any(f.rule_id == "VC2-NO-DEFINABLE-SCOPE" for f in prove_f) and stored_source:
            recon = apply_unified_diff_to_source(stored_source, entry.diff)
            if recon is not None:
                parse_full = parse_file_sources(file_path, stored_source, recon)
                if parse_full.error is None:
                    prove_f = self._prove_functions(
                        file_path,
                        parse_full.base_source,
                        parse_full.head_source,
                        entry.added_lines,
                    )

        effective_lines = [
            ln.strip()
            for ln in entry.added_lines
            if ln.strip() and not ln.strip().startswith("#") and ln.strip() != "pass"
        ]
        if not effective_lines:
            prove_f = [f for f in prove_f if f.rule_id != "VC2-NO-DEFINABLE-SCOPE"]

        findings.extend(prove_f)
        findings.extend(self._check_concurrency(file_path, head_src))
        return findings

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
        self, entry: DiffFileEntry, stored_source: str
    ) -> list[VerificationFinding]:
        file_path = entry.file_path
        try:
            provenance = analyze_removal_provenance(
                entry.diff,
                entities_from_source(file_path, stored_source),
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
        self, file_path: str, head_src: str
    ) -> list[VerificationFinding]:
        # Independent of the symbolic prover so a proven-equivalent diff cannot
        # suppress a safety finding.
        try:
            return list(scan_dangerous_calls(file_path, head_src))
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
    ) -> list[VerificationFinding]:
        findings: list[VerificationFinding] = []
        try:
            funcs_b = {
                f.qualified_name: f
                for f in lower_file_to_ussa(file_path, base_src, language="python")
            }
            funcs_h = {
                f.qualified_name: f
                for f in lower_file_to_ussa(file_path, head_src, language="python")
            }
        except Exception as exc:
            return [
                self._finding(
                    "SSA_ERROR",
                    file_path,
                    rule_id="VC2-SSA-LOWER-ERROR",
                    severity="HIGH",
                    verdict="INCONCLUSIVE",
                    message=f"SSA lowering error: {exc}",
                )
            ]

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
            if fb is None or fb.h_body == fh.h_body:
                continue
            diff_findings = self.prover.prove_function_diff(
                file_path=file_path,
                base_source=base_src,
                head_source=head_src,
                func_base=fb,
                func_head=fh,
            )
            findings.extend(diff_findings)

            is_eq, smt_st = self.prover.prove_equivalence(
                base_source=base_src,
                cand_source=head_src,
                func_base=fb,
                func_cand=fh,
            )
            if is_eq or diff_findings:
                continue
            if smt_st == "SAT":
                findings.append(
                    self._finding(
                        "DIVERGE",
                        file_path,
                        qname,
                        rule_id="VC2-Z3-SEMANTIC-DIVERGENCE",
                        severity="HIGH",
                        verdict="FAIL",
                        start_line=fh.start_line,
                        end_line=fh.end_line,
                        message=(
                            "Z3 proven semantic divergence between base and head "
                            f"for '{qname}'."
                        ),
                    )
                )
            elif smt_st in ("SOLVER_UNAVAILABLE", "UNKNOWN"):
                # Fail closed: a modified function whose equivalence could not
                # be decided must never fall through to a PASS verdict.
                findings.append(
                    self._finding(
                        "UNDECIDED",
                        file_path,
                        qname,
                        rule_id="VC2-Z3-UNDECIDED-DIFF",
                        severity="HIGH",
                        verdict="INCONCLUSIVE",
                        start_line=fh.start_line,
                        end_line=fh.end_line,
                        message=(
                            f"Z3 could not decide equivalence for '{qname}' "
                            f"(status={smt_st}); fail-closed INCONCLUSIVE."
                        ),
                    )
                )
        return findings

    def _check_concurrency(
        self, file_path: str, head_src: str
    ) -> list[VerificationFinding]:
        try:
            return list(self.egglog.datalog_concurrency_invariants(file_path, head_src))
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


@dataclass
class _SourceParse:
    """Result of making a diff hunk parseable, or the syntax finding if it cannot."""

    base_source: str
    head_source: str
    error: VerificationFinding | None = None


def parse_file_sources(
    file_path: str, base_src: str, head_src: str
) -> _SourceParse:
    """Make a diff hunk parseable, or report the syntax finding that blocks it."""
    base_err: SyntaxError | None = None
    head_err: SyntaxError | None = None
    try:
        ast.parse(head_src, filename=file_path)
    except SyntaxError as exc:
        head_err = exc

    try:
        ast.parse(base_src, filename=file_path)
    except SyntaxError as exc:
        base_err = exc

    if base_err is None and head_err is None:
        return _SourceParse(base_source=base_src, head_source=head_src)

    repaired = _parseable_pair(file_path, base_src, head_src)
    if repaired is not None:
        return _SourceParse(base_source=repaired[0], head_source=repaired[1])

    syntax_error = head_err or base_err or SyntaxError(f"Unparseable fragment in {file_path}")
    return _SourceParse(
        base_source=base_src,
        head_source=head_src,
        error=VerificationFinding(
            finding_id=finding_id("SYNTAX", file_path, str(syntax_error.lineno)),
            rule_id="VC2-AST-SYNTAX-ERROR",
            severity="CRITICAL",
            verdict="FAIL",
            file_path=file_path,
            start_line=syntax_error.lineno or 1,
            end_line=syntax_error.lineno or 1,
            message=(
                f"Syntax error in head code of '{file_path}': {syntax_error}"
            ),
        ),
    )


def _parseable_pair(
    file_path: str, base_src: str, head_src: str
) -> tuple[str, str] | None:
    """Return parseable (base, head), or None if no repair strategy works.

    A diff hunk is a fragment: it may start mid-scope, end right after a `def`
    header, or carry a top-level `return` that is only legal inside a function.
    Each repair below exists because a partial hunk genuinely produces that
    shape; failing closed on the fragment instead would report a syntax error
    that says nothing about the patch.
    """
    disk_path = Path(file_path)
    if disk_path.is_file():
        try:
            disk_src = disk_path.read_text(encoding="utf-8")
            ast.parse(disk_src, filename=file_path)
            head_src = disk_src
        except (OSError, SyntaxError):
            pass
        else:
            if _parses(head_src, file_path):
                return base_src, head_src

    if _parses(head_src, file_path) and _parses(base_src, file_path):
        return base_src, head_src

    dedented_head = textwrap.dedent(head_src)
    dedented_base = textwrap.dedent(base_src)
    if _parses(dedented_head, file_path) and _parses(dedented_base, file_path):
        return dedented_base, dedented_head

    repaired_head = repair_empty_bodies(dedented_head)
    repaired_base = repair_empty_bodies(dedented_base)
    if _parses(repaired_head, file_path) and _parses(repaired_base, file_path):
        return repaired_base, repaired_head

    wrapped_head = (
        "def __vc2_fragment__():\n" + textwrap.indent(dedented_head, "    ") + "\n"
    )
    wrapped_base = (
        "def __vc2_fragment__():\n" + textwrap.indent(dedented_base, "    ") + "\n"
    )
    if _parses(wrapped_head, file_path) and _parses(wrapped_base, file_path):
        return wrapped_base, wrapped_head

    return None


def _parses(source: str, file_path: str) -> bool:
    try:
        ast.parse(source, filename=file_path)
        return True
    except SyntaxError:
        return False
