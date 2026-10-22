"""Shared check context and result construction helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from verifyci.contracts.manifest import CHECK_SPECS
from verifyci.contracts.model import (
    CheckResult,
    Coverage,
    CoverageGap,
    DiffEntry,
    Disposition,
    Evidence,
    EvidenceKind,
    Finding,
    Outcome,
    Policy,
    WitnessLevel,
)
from verifyci.contracts.names import stable_finding_fingerprint
from verifyci.contracts.reason_codes import (
    DEFECT_REASON_CODES,
    EVIDENCE_KINDS_BY_DEFECT,
    GAPS,
)
from verifyci.scope.entities import ChangedScope
from verifyci.scm.git import GitRepo


@dataclass(frozen=True, slots=True)
class CheckContext:
    git: GitRepo
    policy: Policy
    entries: tuple[DiffEntry, ...]
    scope: ChangedScope
    as_of_date: str
    object_format: str
    target_base_commit: str
    merge_base_commit: str
    head_commit: str
    toolchain_fingerprint: str
    source_roots: tuple[str, ...] = ()
    rename_limit_exceeded: bool = False
    gate_integrity_paths: tuple[str, ...] = ()
    target_drift: bool = False
    release_validated: bool = False


def make_finding(
    *,
    context: CheckContext,
    check_id: str,
    defect_id: str,
    subject: Mapping[str, Any],
    premises: Mapping[str, Any],
    evidence_kind: EvidenceKind,
    evidence_payload: Mapping[str, Any],
    message: str,
    remediation: str = "",
    witness_level: WitnessLevel = WitnessLevel.SOURCE,
) -> Finding:
    reason_code = DEFECT_REASON_CODES.get(defect_id, "")
    if not reason_code:
        raise ValueError(f"unknown defect id {defect_id!r}")
    if evidence_kind.value not in EVIDENCE_KINDS_BY_DEFECT.get(defect_id, frozenset()):
        raise ValueError(f"evidence kind {evidence_kind.value!r} invalid for {defect_id}")
    path = str(subject.get("path") or "")
    symbol = str(subject.get("symbol") or "")
    fingerprint = stable_finding_fingerprint(
        check_id=check_id,
        defect_id=defect_id,
        defect_semantics_version=1,
        path=path,
        symbol=symbol,
        evidence_identity=evidence_payload.get("identity", evidence_payload),
    )
    subject_with_check = dict(subject)
    subject_with_check.setdefault("check_id", check_id)
    subject_with_check.setdefault("file", path)
    subject_with_check.setdefault("entity", symbol)
    subject_with_check.setdefault("base_span", None)
    line = subject_with_check.get("line")
    subject_with_check.setdefault(
        "head_span",
        {"start_line": line, "end_line": line} if isinstance(line, int) else None,
    )
    entry = next(
        (candidate for candidate in context.entries if path in candidate.changed_paths),
        None,
    )
    def object_id(value: str | None) -> str | None:
        return f"{context.object_format}:{value}" if value else None

    required_premises = {
        "target_base_commit": context.target_base_commit,
        "merge_base_commit": context.merge_base_commit,
        "head_commit": context.head_commit,
        "base_blob": object_id(entry.base_blob if entry else None),
        "head_blob": object_id(entry.head_blob if entry else None),
        "authoritative_policy_source": context.policy.source,
        "authoritative_policy_hash": context.policy.effective_hash,
        "check_version": CHECK_SPECS[check_id].check_version,
        "toolchain_fingerprint": context.toolchain_fingerprint,
    }
    return Finding(
        tier=CHECK_SPECS[check_id].tier,
        defect_id=defect_id,
        reason_code=reason_code,
        defect_semantics_version=1,
        subject=subject_with_check,
        premises={**required_premises, **dict(premises)},
        evidence=Evidence(kind=evidence_kind, payload=dict(evidence_payload)),
        witness_level=witness_level,
        message=message,
        remediation=remediation,
        disposition=Disposition.OPEN,
        fingerprint=fingerprint,
    )


def unsupported_scope_gaps(
    context: CheckContext,
    check_id: str,
    *,
    exclude_path: Callable[[str], bool] | None = None,
) -> list[Any]:
    """Return explicit gaps for changed files outside a frontend's subset."""
    by_path = {
        path: entry
        for entry in context.entries
        for path in entry.changed_paths
    }
    paths = sorted(
        {
            path
            for path, entry in by_path.items()
            if not (entry.is_binary or entry.is_submodule or entry.is_lfs)
            and not (exclude_path and exclude_path(path))
        }
    )
    gaps: list[Any] = []
    for path in paths:
        facts = context.scope.head_facts.get(path) or context.scope.base_facts.get(path)
        if facts is None or facts.supported:
            continue
        reason = (
            "parse_error"
            if facts.language in {"python", "typescript", "javascript"}
            else "unsupported_language"
        )
        gaps.append(
            gap(
                reason,
                {
                    "check_id": check_id,
                    "path": path,
                    "language": facts.language,
                    "parse_error": facts.parse_error,
                },
            )
        )
    return gaps


def make_result(
    *,
    context: CheckContext,
    check_id: str,
    outcome: Outcome,
    coverage: Coverage,
    evaluated_scope: Mapping[str, Any],
    scope_enumeration: Mapping[str, Any],
    candidate_discovery: Mapping[str, Any],
    applicability_evidence: Mapping[str, Any],
    method: str = "",
    reason_codes: Sequence[str] = (),
    coverage_gaps: Sequence[CoverageGap] = (),
    findings: Sequence[Finding] = (),
    diagnostics: Sequence[Mapping[str, Any]] = (),
    sub_results: Sequence[CheckResult] = (),
) -> CheckResult:
    spec = CHECK_SPECS[check_id]
    return CheckResult(
        check_id=check_id,
        check_version=spec.check_version,
        tier=spec.tier,
        maturity=spec.maturity,
        outcome=outcome,
        coverage=coverage,
        evaluated_scope=dict(evaluated_scope),
        scope_enumeration=dict(scope_enumeration),
        candidate_discovery=dict(candidate_discovery),
        applicability_evidence=dict(applicability_evidence),
        method=method or spec.method,
        method_version=spec.method_version,
        reason_codes=tuple(reason_codes),
        coverage_gaps=tuple(coverage_gaps),
        findings=tuple(findings),
        diagnostics=tuple(dict(d) for d in diagnostics),
        sub_results=tuple(sub_results),
        toolchain_fingerprint=context.toolchain_fingerprint,
    )


def error_result(
    *,
    context: CheckContext,
    check_id: str,
    detail: str,
    reason_code: str = "not_executed",
    diagnostic_code: str = "internal_fault",
) -> CheckResult:
    return make_result(
        context=context,
        check_id=check_id,
        outcome=Outcome.ERROR,
        coverage=Coverage.UNKNOWN,
        evaluated_scope={},
        scope_enumeration={"complete": False, "reason_code": reason_code},
        candidate_discovery={"complete": False, "reason_code": reason_code},
        applicability_evidence={},
        reason_codes=(reason_code,),
        diagnostics=(
            {
                "code": diagnostic_code,
                "detail": detail,
            },
        ),
    )


def gap(reason_code: str, subject: Mapping[str, Any]) -> CoverageGap:
    if reason_code not in GAPS:
        raise ValueError(f"unknown coverage gap reason code {reason_code!r}")
    return CoverageGap(reason_code=reason_code, subject=dict(subject))


__all__ = [
    "CheckContext",
    "error_result",
    "gap",
    "make_finding",
    "make_result",
]
