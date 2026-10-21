"""Canonical v3.1 contracts.

These models are deliberately small, immutable value objects.  They do not
perform analysis and they do not import Git, policy, or check code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from verifyci.contracts.reason_codes import (
    DEFECT_REASON_CODES,
    EVIDENCE_KINDS_BY_DEFECT,
    ReasonClass,
    is_acceptable_gap,
)


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"
    REVIEW = "REVIEW"


VERDICT_EXIT_CODES: dict[Verdict, int] = {
    Verdict.PASS: 0,
    Verdict.FAIL: 1,
    Verdict.INCONCLUSIVE: 2,
    Verdict.ERROR: 3,
    Verdict.REVIEW: 4,
}


class Coverage(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class Outcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


class Tier(str, Enum):
    BLOCKING = "blocking"
    ADVISORY = "advisory"


class Maturity(str, Enum):
    SHADOW = "shadow"
    PROVISIONAL = "provisional"
    STABLE = "stable"


class Disposition(str, Enum):
    OPEN = "OPEN"
    WAIVED = "WAIVED"


class WitnessLevel(str, Enum):
    IR = "ir"
    SOURCE = "source"
    NONE = "none"


class EvidenceKind(str, Enum):
    SOLVER = "solver"
    PROVENANCE = "provenance"
    REFERENCE = "reference"
    CALL_SITE = "call_site"
    TAINT_PATH = "taint_path"
    SECRET_VALIDATION = "secret_validation"


@dataclass(frozen=True, slots=True)
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int

    def old_end(self) -> int:
        return self.old_start + max(self.old_count, 1) - 1

    def new_end(self) -> int:
        return self.new_start + max(self.new_count, 1) - 1

    def to_dict(self) -> dict[str, int]:
        return {
            "old_start": self.old_start,
            "old_count": self.old_count,
            "new_start": self.new_start,
            "new_count": self.new_count,
        }


@dataclass(frozen=True, slots=True)
class DiffEntry:
    status: str
    base_path: str
    head_path: str
    base_blob: str | None
    head_blob: str | None
    base_mode: str | None
    head_mode: str | None
    base_source: str
    head_source: str
    hunks: tuple[Hunk, ...] = ()
    is_binary: bool = False
    is_lfs: bool = False
    is_submodule: bool = False
    is_symlink: bool = False

    @property
    def path(self) -> str:
        return self.head_path or self.base_path

    @property
    def changed_paths(self) -> tuple[str, ...]:
        return tuple(p for p in (self.base_path, self.head_path) if p)

    @property
    def is_added(self) -> bool:
        return self.base_blob is None and self.head_blob is not None

    @property
    def is_deleted(self) -> bool:
        return self.base_blob is not None and self.head_blob is None

    @property
    def is_renamed(self) -> bool:
        return bool(self.base_path and self.head_path and self.base_path != self.head_path)

    def to_input_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "base_path": self.base_path or None,
            "head_path": self.head_path or None,
            "base_blob": self.base_blob,
            "head_blob": self.head_blob,
            "base_mode": self.base_mode,
            "head_mode": self.head_mode,
        }


@dataclass(frozen=True, slots=True)
class Entity:
    file_path: str
    qname: str
    kind: str
    start_line: int
    end_line: int
    body_digest: str
    is_export: bool = False
    is_async: bool = False
    signature_digest: str = ""
    parameters: tuple[tuple[str, str, bool], ...] = ()
    returns: str = ""

    def overlaps(self, start: int, end: int) -> bool:
        return self.start_line <= end and start <= self.end_line

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file_path,
            "qname": self.qname,
            "kind": self.kind,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "is_export": self.is_export,
            "is_async": self.is_async,
        }


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: EvidenceKind
    payload: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "payload": dict(self.payload)}


@dataclass(frozen=True, slots=True)
class Finding:
    tier: Tier
    defect_id: str
    reason_code: str
    defect_semantics_version: int
    subject: Mapping[str, Any]
    premises: Mapping[str, Any]
    evidence: Evidence
    witness_level: WitnessLevel
    message: str
    remediation: str = ""
    disposition: Disposition = Disposition.OPEN
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if DEFECT_REASON_CODES.get(self.defect_id) != self.reason_code:
            raise ValueError(
                f"finding reason_code {self.reason_code!r} is not the bijection "
                f"for defect {self.defect_id!r}"
            )
        allowed = EVIDENCE_KINDS_BY_DEFECT.get(self.defect_id, frozenset())
        if self.evidence.kind not in allowed:
            raise ValueError(
                f"evidence kind {self.evidence.kind.value!r} is not allowed for "
                f"defect {self.defect_id!r}"
            )

    def with_disposition(self, disposition: Disposition) -> "Finding":
        return Finding(
            tier=self.tier,
            defect_id=self.defect_id,
            reason_code=self.reason_code,
            defect_semantics_version=self.defect_semantics_version,
            subject=self.subject,
            premises=self.premises,
            evidence=self.evidence,
            witness_level=self.witness_level,
            message=self.message,
            remediation=self.remediation,
            disposition=disposition,
            fingerprint=self.fingerprint,
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "tier": self.tier.value,
            "defect_id": self.defect_id,
            "reason_code": self.reason_code,
            "defect_semantics_version": self.defect_semantics_version,
            "subject": dict(self.subject),
            "premises": dict(self.premises),
            "evidence": self.evidence.to_dict(),
            "witness_level": self.witness_level.value,
            "message": self.message,
            "remediation": self.remediation or None,
            "disposition": self.disposition.value,
        }
        if self.fingerprint:
            data["fingerprint"] = self.fingerprint
        return data


@dataclass(frozen=True, slots=True)
class CoverageGap:
    reason_code: str
    subject: Mapping[str, Any]
    accepted: bool = False
    acceptance_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = {
            "reason_code": self.reason_code,
            "subject": dict(self.subject),
            "accepted": self.accepted,
        }
        if self.acceptance_id:
            data["acceptance_id"] = self.acceptance_id
        return data


@dataclass(frozen=True, slots=True)
class CheckResult:
    check_id: str
    check_version: int
    tier: Tier
    maturity: Maturity
    outcome: Outcome
    coverage: Coverage
    evaluated_scope: Mapping[str, Any] = field(default_factory=dict)
    scope_enumeration: Mapping[str, Any] = field(default_factory=dict)
    candidate_discovery: Mapping[str, Any] = field(default_factory=dict)
    applicability_evidence: Mapping[str, Any] = field(default_factory=dict)
    method: str = ""
    method_version: int = 1
    reason_codes: tuple[str, ...] = ()
    coverage_gaps: tuple[CoverageGap, ...] = ()
    findings: tuple[Finding, ...] = ()
    diagnostics: tuple[Mapping[str, Any], ...] = ()
    sub_results: tuple["CheckResult", ...] = ()
    toolchain_fingerprint: str = ""

    def validate(self) -> list[str]:
        errors: list[str] = []
        has_findings = bool(self.findings)
        if self.outcome == Outcome.PASS and self.coverage != Coverage.COMPLETE:
            errors.append("PASS requires COMPLETE coverage")
        if self.outcome == Outcome.PASS and has_findings:
            errors.append("PASS carries findings")
        if self.outcome == Outcome.NOT_APPLICABLE and self.coverage != Coverage.COMPLETE:
            errors.append("NOT_APPLICABLE requires COMPLETE coverage")
        if self.outcome == Outcome.NOT_APPLICABLE and has_findings:
            errors.append("NOT_APPLICABLE carries findings")
        if self.outcome == Outcome.INCONCLUSIVE and has_findings:
            errors.append("INCONCLUSIVE carries findings")
        if self.outcome == Outcome.FAIL and not has_findings:
            errors.append("FAIL requires at least one finding")
        if self.outcome == Outcome.ERROR and not (self.diagnostics or self.reason_codes):
            errors.append("ERROR requires a diagnostic or reason code")
        finding_codes = set(DEFECT_REASON_CODES.values())
        for code in self.reason_codes:
            if code in finding_codes:
                errors.append(f"check reason_codes contains finding code {code}")
        for finding in self.findings:
            if DEFECT_REASON_CODES.get(finding.defect_id) != finding.reason_code:
                errors.append(f"invalid finding reason code {finding.reason_code}")
            allowed = EVIDENCE_KINDS_BY_DEFECT.get(finding.defect_id, frozenset())
            if finding.evidence.kind.value not in allowed:
                errors.append(
                    f"invalid evidence kind {finding.evidence.kind.value} "
                    f"for {finding.defect_id}"
                )
        return errors

    def effective_coverage(self) -> Coverage:
        if self.coverage_gaps and all(g.accepted for g in self.coverage_gaps):
            return Coverage.COMPLETE
        return self.coverage

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_version": self.check_version,
            "tier": self.tier.value,
            "maturity": self.maturity.value,
            "outcome": self.outcome.value,
            "coverage": self.coverage.value,
            "evaluated_scope": dict(self.evaluated_scope),
            "scope_enumeration": dict(self.scope_enumeration),
            "candidate_discovery": dict(self.candidate_discovery),
            "applicability_evidence": dict(self.applicability_evidence),
            "method": self.method,
            "method_version": self.method_version,
            "reason_codes": list(self.reason_codes),
            "coverage_gaps": [g.to_dict() for g in self.coverage_gaps],
            "findings": [f.to_dict() for f in self.findings],
            "diagnostics": [dict(d) for d in self.diagnostics],
            "sub_results": [r.to_dict() for r in self.sub_results],
            "toolchain_fingerprint": self.toolchain_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class WaiverRecord:
    record_id: str
    check: str
    defect_id: str
    fingerprint: str
    reason: str
    approved_by: str
    created: str
    expires: str
    raw: Mapping[str, Any] = field(default_factory=dict)

    def active(self, as_of_date: str) -> bool:
        return self.created <= as_of_date <= self.expires

    def expired(self, as_of_date: str) -> bool:
        return as_of_date > self.expires

    def not_yet_effective(self, as_of_date: str) -> bool:
        return as_of_date < self.created

    def normalized(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "defect_id": self.defect_id,
            "fingerprint": self.fingerprint,
            "reason": self.reason,
            "approved_by": self.approved_by,
            "created": self.created,
            "expires": self.expires,
            **{k: v for k, v in self.raw.items() if k not in {
                "check", "defect_id", "fingerprint", "reason", "approved_by",
                "created", "expires",
            }},
        }


@dataclass(frozen=True, slots=True)
class AcceptanceRecord:
    record_id: str
    check: str
    reason_code: str
    paths: tuple[str, ...]
    symbols: tuple[str, ...]
    reason: str
    approved_by: str
    created: str
    expires: str
    raw: Mapping[str, Any] = field(default_factory=dict)

    def active(self, as_of_date: str) -> bool:
        return self.created <= as_of_date <= self.expires

    def expired(self, as_of_date: str) -> bool:
        return as_of_date > self.expires

    def not_yet_effective(self, as_of_date: str) -> bool:
        return as_of_date < self.created

    def normalized(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "reason_code": self.reason_code,
            "paths": list(self.paths),
            "symbols": list(self.symbols),
            "reason": self.reason,
            "approved_by": self.approved_by,
            "created": self.created,
            "expires": self.expires,
            **{k: v for k, v in self.raw.items() if k not in {
                "check", "reason_code", "paths", "symbols", "reason",
                "approved_by", "created", "expires",
            }},
        }


@dataclass(frozen=True, slots=True)
class Policy:
    raw: Mapping[str, Any]
    blob_hash: str | None
    source: str
    effective_hash: str
    gate: Mapping[str, Any] = field(default_factory=dict)
    path_classes: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    entrypoints: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    public_api: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    deny_changes: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    protected_guards: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    protected_errors: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    taint_sources: tuple[str, ...] = ()
    taint_sinks: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    taint_sanitizers: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    forbidden_calls: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    transparent_decorators: tuple[str, ...] = ()
    call_models: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    secret_allowlist_paths: tuple[str, ...] = ()
    secret_placeholders: tuple[str, ...] = ()
    waivers: Mapping[str, WaiverRecord] = field(default_factory=dict)
    acceptances: Mapping[str, AcceptanceRecord] = field(default_factory=dict)

    def waiver_for(self, finding: Finding) -> WaiverRecord | None:
        for waiver in self.waivers.values():
            if waiver.defect_id != finding.defect_id:
                continue
            if waiver.fingerprint != finding.fingerprint:
                continue
            # Fingerprints already bind the check ID; this guard catches a
            # malformed or manually assembled finding that carries one.
            check_id = finding.subject.get("check_id")
            if check_id is not None and waiver.check != check_id:
                continue
            return waiver
        return None

    def acceptance_for_gap(
        self, check_id: str, gap: CoverageGap
    ) -> AcceptanceRecord | None:
        path = str(gap.subject.get("path") or "")
        symbol = str(gap.subject.get("symbol") or "")
        subject_check = str(gap.subject.get("check_id") or "")
        for acceptance in self.acceptances.values():
            if acceptance.check not in (check_id, subject_check):
                continue
            if acceptance.reason_code != gap.reason_code:
                continue
            path_match = bool(path) and any(
                glob_match(pattern, path, kind="path") for pattern in acceptance.paths
            )
            symbol_match = bool(symbol) and symbol in acceptance.symbols
            if path_match or symbol_match:
                return acceptance
        return None


@dataclass(frozen=True, slots=True)
class VerdictResult:
    status: Verdict
    exit_code: int
    blocking_findings_present: bool
    reason_codes: tuple[str, ...] = ()
    fault_reason_codes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "blocking_findings_present": self.blocking_findings_present,
            "reason_codes": list(self.reason_codes),
            "fault_reason_codes": list(self.fault_reason_codes),
        }


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    payload: Mapping[str, Any]
    envelope: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"payload": dict(self.payload), "envelope": dict(self.envelope)}

    @property
    def verdict(self) -> Verdict:
        return Verdict(str(self.payload["verdict"]["status"]))

    @property
    def exit_code(self) -> int:
        return int(self.payload["verdict"]["exit_code"])


def glob_match(pattern: str, value: str, *, kind: str = "path") -> bool:
    """Match a policy glob without ever treating it as a user regex.

    ``*`` stays within a path segment (or a qualified-name component); ``**``
    crosses separators.  This is intentionally small and deterministic.
    """
    import re

    sep = r"/" if kind == "path" else r"[:.]"
    out: list[str] = ["^"]
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append(f"[^{sep}]*")
        elif ch == "?":
            out.append(f"[^{sep}]")
        else:
            out.append(re.escape(ch))
        i += 1
    out.append("$")
    try:
        return re.match("".join(out), value) is not None
    except re.error:
        return False


__all__ = [
    "AcceptanceRecord",
    "CheckResult",
    "Coverage",
    "CoverageGap",
    "DiffEntry",
    "Disposition",
    "Entity",
    "Evidence",
    "EvidenceBundle",
    "EvidenceKind",
    "Finding",
    "Hunk",
    "Maturity",
    "Outcome",
    "Policy",
    "ReasonClass",
    "Tier",
    "Verdict",
    "VerdictResult",
    "VERDICT_EXIT_CODES",
    "WaiverRecord",
    "WitnessLevel",
    "glob_match",
    "is_acceptable_gap",
]
