"""Removal provenance verification against base revisions."""

from __future__ import annotations

import re
from typing import Any, Mapping, Protocol, Sequence

from verifyci.contracts.verdict import (
    FindingReason,
    Severity,
    VerificationFinding,
    VerificationVerdict,
)
from verifyci.core.canonical import content_digest_hex
from verifyci.core.diff_parser import DiffFileEntry


class BaseSourceProvider(Protocol):
    """Protocol providing access to base revision source content."""

    def get_file_content(self, file_path: str) -> str | None:
        """Retrieve source text for a path in the base revision."""
        ...


class DictBaseSourceProvider:
    """In-memory dictionary base source provider."""

    def __init__(self, sources: Mapping[str, str]) -> None:
        self._sources = dict(sources)

    def get_file_content(self, file_path: str) -> str | None:
        norm = file_path.replace("\\", "/").strip()
        while norm.startswith("./"):
            norm = norm[2:]
        return self._sources.get(norm)

_GUARD_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*assert\s+"),
    re.compile(r"^\s*if\s+.*\braise\b"),
    re.compile(r"\b(?:is_authenticated|require_auth|check_permission|bounds_check)\b"),
    re.compile(r"@(?:login_required|auth_required|permission_required)"),
)

_POLICY_FILES: tuple[str, ...] = (
    ".verifyci.toml",
    "verifyci.toml",
    ".verifyci/config.json",
    ".verifyci/policy.json",
    ".verifyci/waivers.yaml",
)


def is_policy_file(file_path: str) -> bool:
    """Detect whether file modifies trusted verification policy."""
    norm = file_path.replace("\\", "/").strip().lower()
    while norm.startswith("./"):
        norm = norm[2:]
    return norm in _POLICY_FILES or norm.startswith(".verifyci/")


def verify_removal_provenance(
    entry: DiffFileEntry,
    base_sources: BaseSourceProvider | Mapping[str, str],
    allow_policy_tampering: bool = False,
) -> list[VerificationFinding]:
    """Verify that code removals in the diff accurately reflect the base revision.

    Fails closed:
    - Tampering with policy files without authorization is POLICY_VIOLATION (FAIL).
    - Removals contradicting the base revision are FABRICATED (FAIL).
    - Removals deleting security guards without replacement are POLICY_VIOLATION (FAIL).
    - Net removals without a verifiable base record are UNGROUNDED (INCONCLUSIVE).
    """
    findings: list[VerificationFinding] = []
    file_path = entry.file_path
    lookup_path = entry.old_file_path or file_path

    # Policy integrity check: an untrusted diff cannot weaken its own verification policy
    if not allow_policy_tampering and is_policy_file(file_path):
        findings.append(
            VerificationFinding(
                finding_id=content_digest_hex(f"policy_tamper:{file_path}")[:16],
                rule_id="VC-POLICY-UNAUTHORIZED-MODIFICATION",
                severity=Severity.CRITICAL,
                verdict=VerificationVerdict.FAIL,
                reason=FindingReason.POLICY_VIOLATION,
                message=(
                    f"Diff modifies trusted verification configuration '{file_path}' "
                    "without independent authorization; rejecting patch."
                ),
                file_path=file_path,
            )
        )
        return findings

    # Binary files cannot undergo text-line provenance
    if entry.is_binary:
        return findings

    provider: BaseSourceProvider
    if isinstance(base_sources, Mapping):
        provider = DictBaseSourceProvider(base_sources)
    else:
        provider = base_sources

    base_source = provider.get_file_content(lookup_path) or provider.get_file_content(file_path)

    # Net deletion without a stored base record
    if not base_source:
        if len(entry.removed_lines) > len(entry.added_lines):
            findings.append(
                VerificationFinding(
                    finding_id=content_digest_hex(f"rem_ungrounded:{file_path}")[:16],
                    rule_id="VC-PROVENANCE-NO-BASE-RECORD",
                    severity=Severity.MEDIUM,
                    verdict=VerificationVerdict.INCONCLUSIVE,
                    reason=FindingReason.UNGROUNDED_REMOVAL,
                    message=(
                        f"Diff removes {len(entry.removed_lines)} line(s) from '{file_path}' "
                        "but no base revision record is available; removal cannot be grounded. Failing closed."
                    ),
                    file_path=file_path,
                )
            )
        return findings

    base_lines = base_source.splitlines()
    base_line_count = len(base_lines)

    fabricated_lines: list[int] = []
    removed_guard_lines: list[str] = []

    for rem in entry.removed_lines:
        line_num = rem.line_number
        target_content = rem.content.strip()

        if not target_content:
            continue

        # Exact offset check
        matched = False
        if 1 <= line_num <= base_line_count:
            if base_lines[line_num - 1].strip() == target_content:
                matched = True

        # Fuzzy window check (+- 10 lines) to account for hunk drift
        if not matched:
            win_start = max(0, line_num - 11)
            win_end = min(base_line_count, line_num + 10)
            for cand in base_lines[win_start:win_end]:
                if cand.strip() == target_content:
                    matched = True
                    break

        if not matched:
            fabricated_lines.append(line_num)

        # Check if removed line was a defensive security guard
        if any(pat.search(rem.content) for pat in _GUARD_PATTERNS):
            removed_guard_lines.append(target_content)

    if fabricated_lines:
        findings.append(
            VerificationFinding(
                finding_id=content_digest_hex(f"rem_fabricated:{file_path}:{fabricated_lines[0]}")[:16],
                rule_id="VC-PROVENANCE-FABRICATED-REMOVAL",
                severity=Severity.CRITICAL,
                verdict=VerificationVerdict.FAIL,
                reason=FindingReason.FABRICATED_REMOVAL,
                message=(
                    f"Diff removes code that was not present in the base revision of '{file_path}' "
                    f"at target lines {fabricated_lines[:3]}; patch is stale or forged."
                ),
                file_path=file_path,
                start_line=fabricated_lines[0],
                end_line=fabricated_lines[-1],
            )
        )

    # Check for unreplaced guard deletions
    head_lines_clean = [ln.strip() for ln in entry.head_source.splitlines()]
    for guard in removed_guard_lines:
        # Require identical or strict preservation in head
        if guard not in head_lines_clean:
            findings.append(
                VerificationFinding(
                    finding_id=content_digest_hex(f"guard_removal:{file_path}:{guard}")[:16],
                    rule_id="VC-SECURITY-GUARD-REMOVAL",
                    severity=Severity.CRITICAL,
                    verdict=VerificationVerdict.FAIL,
                    reason=FindingReason.POLICY_VIOLATION,
                    message=(
                        f"Diff removes defensive security guard '{guard}' from '{file_path}' "
                        "without equivalent replacement."
                    ),
                    file_path=file_path,
                )
            )
            break

    return findings
