"""Waiver/acceptance application and verdict aggregation."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
from typing import Any, Iterable, Mapping, Sequence

from verifyci.contracts.model import (
    CheckResult,
    Coverage,
    CoverageGap,
    Disposition,
    Finding,
    Outcome,
    Policy,
    Tier,
    Verdict,
    VerdictResult,
    VERDICT_EXIT_CODES,
)
from verifyci.contracts.reason_codes import FAULTS, is_fault_code


@dataclass(frozen=True, slots=True)
class Aggregation:
    results: tuple[CheckResult, ...]
    verdict: VerdictResult
    applied_waivers: tuple[Mapping[str, Any], ...]
    accepted_gaps: tuple[Mapping[str, Any], ...]
    diagnostics: tuple[Mapping[str, Any], ...]
    review_reasons: tuple[str, ...]
    blocking_findings: tuple[Finding, ...]


def _finding_key(finding: Finding) -> str:
    return finding.fingerprint or f"{finding.defect_id}:{finding.reason_code}:{dict(finding.subject)}"


def _apply_waiver_result(
    result: CheckResult,
    policy: Policy,
    *,
    as_of_date: str,
    applied: list[dict[str, Any]],
    applied_keys: set[tuple[str, str]],
    review_reasons: set[str],
    diagnostics: list[dict[str, Any]],
    diagnostic_keys: set[tuple[str, str]],
) -> CheckResult:
    if result.tier != Tier.BLOCKING:
        return result
    new_findings: list[Finding] = []
    for finding in result.findings:
        waiver = policy.waiver_for(finding)
        if waiver is None:
            new_findings.append(finding)
            continue
        key = (waiver.record_id, waiver.fingerprint)
        if waiver.active(as_of_date):
            new_findings.append(finding.with_disposition(Disposition.WAIVED))
            if key not in applied_keys:
                applied_keys.add(key)
                applied.append(
                    {
                        "id": waiver.record_id,
                        "check": waiver.check,
                        "defect_id": waiver.defect_id,
                        "fingerprint": waiver.fingerprint,
                        "expires": waiver.expires,
                        "disposition": "WAIVED",
                    }
                )
        else:
            new_findings.append(finding)
            review_reasons.add("waiver_review")
            if key not in diagnostic_keys:
                diagnostic_keys.add(key)
                diagnostics.append(
                    {
                        "code": "stale_waiver_present",
                        "check": result.check_id,
                        "waiver_id": waiver.record_id,
                        "created": waiver.created,
                        "expires": waiver.expires,
                        "fingerprint": waiver.fingerprint,
                    }
                )
    sub_results = tuple(
        _apply_waiver_result(
            sub,
            policy,
            as_of_date=as_of_date,
            applied=applied,
            applied_keys=applied_keys,
            review_reasons=review_reasons,
            diagnostics=diagnostics,
            diagnostic_keys=diagnostic_keys,
        )
        for sub in result.sub_results
    )
    return replace(result, findings=tuple(new_findings), sub_results=sub_results)


def apply_waivers(
    results: Sequence[CheckResult],
    policy: Policy,
    *,
    as_of_date: str,
) -> tuple[tuple[CheckResult, ...], tuple[Mapping[str, Any], ...], set[str], list[Mapping[str, Any]]]:
    applied: list[dict[str, Any]] = []
    applied_keys: set[tuple[str, str]] = set()
    review_reasons: set[str] = set()
    diagnostics: list[dict[str, Any]] = []
    diagnostic_keys: set[tuple[str, str]] = set()
    out = tuple(
        _apply_waiver_result(
            result,
            policy,
            as_of_date=as_of_date,
            applied=applied,
            applied_keys=applied_keys,
            review_reasons=review_reasons,
            diagnostics=diagnostics,
            diagnostic_keys=diagnostic_keys,
        )
        for result in results
    )
    return out, tuple(applied), review_reasons, diagnostics


def _apply_acceptance_result(
    result: CheckResult,
    policy: Policy,
    *,
    as_of_date: str,
    accepted: list[dict[str, Any]],
    accepted_keys: set[tuple[str, str, str]],
    review_reasons: set[str],
    diagnostics: list[dict[str, Any]],
    diagnostic_keys: set[tuple[str, str]],
) -> CheckResult:
    if result.tier != Tier.BLOCKING:
        return result
    new_gaps: list[CoverageGap] = []
    for item in result.coverage_gaps:
        acceptance = policy.acceptance_for_gap(result.check_id, item)
        if acceptance is None:
            new_gaps.append(item)
            continue
        key = (
            acceptance.record_id,
            item.reason_code,
            json.dumps(dict(item.subject), sort_keys=True, default=str),
        )
        if acceptance.active(as_of_date):
            new_gaps.append(replace(item, accepted=True, acceptance_id=acceptance.record_id))
            if key not in accepted_keys:
                accepted_keys.add(key)
                accepted.append(
                    {
                        "id": acceptance.record_id,
                        "check": acceptance.check,
                        "reason_code": acceptance.reason_code,
                        "subject": dict(item.subject),
                        "expires": acceptance.expires,
                        "disposition": "ACCEPTED",
                    }
                )
        else:
            new_gaps.append(item)
            review_reasons.add("coverage_acceptance_review")
            diagnostic_key = (acceptance.record_id, item.reason_code)
            if diagnostic_key not in diagnostic_keys:
                diagnostic_keys.add(diagnostic_key)
                diagnostics.append(
                    {
                        "code": "stale_acceptance_present",
                        "check": result.check_id,
                        "acceptance_id": acceptance.record_id,
                        "created": acceptance.created,
                        "expires": acceptance.expires,
                    }
                )
    gaps = tuple(new_gaps)
    coverage = result.coverage
    outcome = result.outcome
    scope_complete = bool(result.scope_enumeration.get("complete", False))
    candidates_complete = bool(result.candidate_discovery.get("complete", False))
    sub_results = tuple(
        _apply_acceptance_result(
            sub,
            policy,
            as_of_date=as_of_date,
            accepted=accepted,
            accepted_keys=accepted_keys,
            review_reasons=review_reasons,
            diagnostics=diagnostics,
            diagnostic_keys=diagnostic_keys,
        )
        for sub in result.sub_results
    )
    sub_complete = (
        all(sub.effective_coverage() == Coverage.COMPLETE for sub in sub_results)
        if sub_results
        else True
    )
    has_unaccepted = any(not g.accepted for g in gaps)
    if (
        not has_unaccepted
        and scope_complete
        and candidates_complete
        and sub_complete
        and not result.findings
    ):
        coverage = Coverage.COMPLETE
        if outcome == Outcome.INCONCLUSIVE:
            outcome = Outcome.PASS
    elif coverage == Coverage.COMPLETE and (
        not scope_complete
        or not candidates_complete
        or has_unaccepted
        or not sub_complete
    ):
        coverage = Coverage.UNKNOWN if not scope_complete else Coverage.PARTIAL
    return replace(
        result,
        coverage_gaps=gaps,
        coverage=coverage,
        outcome=outcome,
        sub_results=sub_results,
    )


def apply_acceptances(
    results: Sequence[CheckResult],
    policy: Policy,
    *,
    as_of_date: str,
) -> tuple[tuple[CheckResult, ...], tuple[Mapping[str, Any], ...], set[str], list[Mapping[str, Any]]]:
    accepted: list[dict[str, Any]] = []
    accepted_keys: set[tuple[str, str, str]] = set()
    review_reasons: set[str] = set()
    diagnostics: list[dict[str, Any]] = []
    diagnostic_keys: set[tuple[str, str]] = set()
    out = tuple(
        _apply_acceptance_result(
            result,
            policy,
            as_of_date=as_of_date,
            accepted=accepted,
            accepted_keys=accepted_keys,
            review_reasons=review_reasons,
            diagnostics=diagnostics,
            diagnostic_keys=diagnostic_keys,
        )
        for result in results
    )
    return out, tuple(accepted), review_reasons, diagnostics


def _fault_codes(result: CheckResult) -> set[str]:
    codes: set[str] = set()
    for code in result.reason_codes:
        if is_fault_code(code):
            codes.add(code)
    for diagnostic in result.diagnostics:
        code = str(diagnostic.get("code") or "")
        if code in FAULTS:
            codes.add(code)
    return codes


def aggregate(
    results: Sequence[CheckResult],
    *,
    review_reasons: Iterable[str] = (),
    target_drift: bool = False,
    target_drift_mode: str = "record",
    extra_faults: Iterable[str] = (),
) -> VerdictResult:
    """Apply the specified precedence: ERROR > FAIL > INCONCLUSIVE > REVIEW > PASS.

    Review reasons are retained even when a higher-precedence status wins.
    Shadow/advisory results never affect the verdict.
    """
    review = set(review_reasons)
    fault_codes = set(extra_faults)
    blocking = [r for r in results if r.tier == Tier.BLOCKING]

    invalid = False
    for result in blocking:
        if result.validate():
            invalid = True
            fault_codes.add("invalid_check_result")
        if result.outcome == Outcome.ERROR:
            fault_codes.update(_fault_codes(result))
            if not _fault_codes(result):
                fault_codes.add("internal_fault")

    open_findings: list[Finding] = []
    all_blocking_findings: list[Finding] = []
    gap_codes: set[str] = set()
    incomplete = False
    for result in blocking:
        all_blocking_findings.extend(result.findings)
        for finding in result.findings:
            if finding.disposition == Disposition.OPEN:
                open_findings.append(finding)
        unaccepted = [g for g in result.coverage_gaps if not g.accepted]
        gap_codes.update(g.reason_code for g in unaccepted)
        if result.outcome == Outcome.INCONCLUSIVE and (not result.coverage_gaps or unaccepted):
            incomplete = True
        if result.effective_coverage() != Coverage.COMPLETE:
            incomplete = True

    if target_drift and target_drift_mode == "require_zero":
        incomplete = True
        gap_codes.add("target_drift")

    reason_codes = set(review) | gap_codes | fault_codes
    reason_codes.update(f.reason_code for f in open_findings)

    if invalid or fault_codes:
        status = Verdict.ERROR
        fault_codes = fault_codes or {"internal_fault"}
    elif open_findings:
        status = Verdict.FAIL
    elif incomplete:
        status = Verdict.INCONCLUSIVE
    elif review:
        status = Verdict.REVIEW
    else:
        status = Verdict.PASS

    if status == Verdict.ERROR:
        # Preserve validated findings; they remain in the bundle and set the
        # boolean because the run cannot establish a clean pass.
        blocking_present = bool(all_blocking_findings)
    elif status == Verdict.FAIL:
        blocking_present = True
    else:
        blocking_present = False

    # A fault code in a non-ERROR status would be an aggregation bug.
    if status != Verdict.ERROR and any(is_fault_code(c) for c in reason_codes):
        status = Verdict.ERROR
        fault_codes.add("invalid_check_result")
        reason_codes.add("invalid_check_result")

    return VerdictResult(
        status=status,
        exit_code=VERDICT_EXIT_CODES[status],
        blocking_findings_present=blocking_present,
        reason_codes=tuple(sorted(reason_codes)),
        fault_reason_codes=tuple(sorted(fault_codes)),
    )


__all__ = ["Aggregation", "aggregate", "apply_acceptances", "apply_waivers"]
