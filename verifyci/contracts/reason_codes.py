"""Closed reason-code catalog from Appendix A of the v3.1.10 specification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ReasonClass(str, Enum):
    FAULT = "fault"
    REVIEW = "review"
    GAP = "gap"
    FINDING = "finding"
    DIAGNOSTIC = "diagnostic"
    RUN_CONDITION = "run_condition"


@dataclass(frozen=True, slots=True)
class ReasonCode:
    code: str
    reason_class: ReasonClass
    remediation: str = ""
    acceptable: bool = False


FAULTS: dict[str, ReasonCode] = {
    "provenance_integrity_error": ReasonCode(
        "provenance_integrity_error", ReasonClass.FAULT,
        "Re-fetch objects; verify no history rewrite between base, merge base, and head.",
    ),
    "ambiguous_merge_base": ReasonCode(
        "ambiguous_merge_base", ReasonClass.FAULT,
        "Supply an explicit, verified --merge-base, or rebase to a unique merge base.",
    ),
    "shallow_history": ReasonCode(
        "shallow_history", ReasonClass.FAULT,
        "Fetch enough history to establish a unique merge base; do not rely on a shallow clone.",
    ),
    "missing_git_object": ReasonCode(
        "missing_git_object", ReasonClass.FAULT,
        "Fetch the missing objects explicitly; the gate never lazy-fetches.",
    ),
    "invalid_policy": ReasonCode(
        "invalid_policy", ReasonClass.FAULT,
        "Fix schema errors in .verifyci/policy.toml on the target branch (or in the PR if proposed/onboarding).",
    ),
    "path_traversal": ReasonCode(
        "path_traversal", ReasonClass.FAULT,
        "Remove paths escaping the repository from policy.",
    ),
    "invalid_cache_location": ReasonCode(
        "invalid_cache_location", ReasonClass.FAULT,
        "Choose a cache directory outside the working tree.",
    ),
    "cache_integrity_mismatch": ReasonCode(
        "cache_integrity_mismatch", ReasonClass.FAULT,
        "Treat as a security incident: invalidate the cache namespace and investigate.",
    ),
    "manifest_mismatch": ReasonCode(
        "manifest_mismatch", ReasonClass.FAULT,
        "Use the Action/toolchain version matching the release manifest.",
    ),
    "check_not_validated": ReasonCode(
        "check_not_validated", ReasonClass.FAULT,
        "Use a released build; internal builds cannot emit PASS.",
    ),
    "deployment_contract_violation": ReasonCode(
        "deployment_contract_violation", ReasonClass.FAULT,
        "Ensure the Action is SHA-pinned and active target-base CODEOWNERS covers the protected paths with non-empty owners.",
    ),
    "not_executed": ReasonCode(
        "not_executed", ReasonClass.FAULT,
        "Resolve the upstream error recorded in diagnostics.",
    ),
    "invalid_check_result": ReasonCode(
        "invalid_check_result", ReasonClass.FAULT,
        "Report as a gate bug; no user remediation.",
    ),
    "index_inconsistency": ReasonCode(
        "index_inconsistency", ReasonClass.FAULT,
        "Report as a gate bug; re-run uncached.",
    ),
    "witness_replay_mismatch": ReasonCode(
        "witness_replay_mismatch", ReasonClass.FAULT,
        "Report as a gate bug with the preserved witness.",
    ),
    "internal_fault": ReasonCode(
        "internal_fault", ReasonClass.FAULT,
        "Report as a gate bug with the diagnostics.",
    ),
}


REVIEWS: dict[str, ReasonCode] = {
    "policy_change_review": ReasonCode(
        "policy_change_review", ReasonClass.REVIEW,
        "Code-owner review of the policy addition, remediation, or change; merge to the target branch.",
    ),
    "gate_integrity_review": ReasonCode(
        "gate_integrity_review", ReasonClass.REVIEW,
        "Code-owner review of the workflow/CODEOWNERS/.verifyci change.",
    ),
    "waiver_review": ReasonCode(
        "waiver_review", ReasonClass.REVIEW,
        "Remove or validly renew the inactive waiver through a separate policy-clearing PR.",
    ),
    "coverage_acceptance_review": ReasonCode(
        "coverage_acceptance_review", ReasonClass.REVIEW,
        "Remove or validly renew the inactive coverage acceptance through a separate policy-clearing PR.",
    ),
}


GAPS: dict[str, ReasonCode] = {
    "mapping_unresolved": ReasonCode("mapping_unresolved", ReasonClass.GAP, acceptable=True),
    "dynamic_target_unresolved": ReasonCode("dynamic_target_unresolved", ReasonClass.GAP, acceptable=True),
    "dynamic_call": ReasonCode("dynamic_call", ReasonClass.GAP, acceptable=True),
    "unknown_decorator": ReasonCode("unknown_decorator", ReasonClass.GAP, acceptable=True),
    "unresolved_import": ReasonCode("unresolved_import", ReasonClass.GAP, acceptable=True),
    "unknown_call_on_path": ReasonCode("unknown_call_on_path", ReasonClass.GAP, acceptable=True),
    "frontend_capability_missing": ReasonCode("frontend_capability_missing", ReasonClass.GAP, acceptable=True),
    "unsupported_language": ReasonCode("unsupported_language", ReasonClass.GAP, acceptable=True),
    "unsupported_syntax_version": ReasonCode("unsupported_syntax_version", ReasonClass.GAP, acceptable=True),
    "lfs_content_unavailable": ReasonCode("lfs_content_unavailable", ReasonClass.GAP, acceptable=True),
    "taint_path_unresolved": ReasonCode("taint_path_unresolved", ReasonClass.GAP, acceptable=False),
    "secret_candidate_ambiguous": ReasonCode("secret_candidate_ambiguous", ReasonClass.GAP, acceptable=False),
    "solver_unknown": ReasonCode("solver_unknown", ReasonClass.GAP, acceptable=False),
    "semantic_alignment_unresolved": ReasonCode("semantic_alignment_unresolved", ReasonClass.GAP, acceptable=False),
    "parse_error": ReasonCode("parse_error", ReasonClass.GAP, acceptable=False),
    "parse_resource_limit": ReasonCode("parse_resource_limit", ReasonClass.GAP, acceptable=False),
    "budget_exhausted": ReasonCode("budget_exhausted", ReasonClass.GAP, acceptable=False),
    "watchdog_interrupted": ReasonCode("watchdog_interrupted", ReasonClass.GAP, acceptable=False),
}


FINDINGS: dict[str, ReasonCode] = {
    "policy_prohibited": ReasonCode("policy_prohibited", ReasonClass.FINDING),
    "symbol_live": ReasonCode("symbol_live", ReasonClass.FINDING),
    "dangling_reference": ReasonCode("dangling_reference", ReasonClass.FINDING),
    "dynamic_reference_removed": ReasonCode("dynamic_reference_removed", ReasonClass.FINDING),
    "signature_break": ReasonCode("signature_break", ReasonClass.FINDING),
    "export_break": ReasonCode("export_break", ReasonClass.FINDING),
    "call_incompatible": ReasonCode("call_incompatible", ReasonClass.FINDING),
    "guard_removed": ReasonCode("guard_removed", ReasonClass.FINDING),
    "guard_weakened": ReasonCode("guard_weakened", ReasonClass.FINDING),
    "guard_inverted": ReasonCode("guard_inverted", ReasonClass.FINDING),
    "binding_swap": ReasonCode("binding_swap", ReasonClass.FINDING),
    "exception_removed": ReasonCode("exception_removed", ReasonClass.FINDING),
    "secret_detected": ReasonCode("secret_detected", ReasonClass.FINDING),
    "secret_to_sink": ReasonCode("secret_to_sink", ReasonClass.FINDING),
    "taint_to_sink": ReasonCode("taint_to_sink", ReasonClass.FINDING),
    "dangerous_call": ReasonCode("dangerous_call", ReasonClass.FINDING),
}


DIAGNOSTICS: dict[str, ReasonCode] = {
    "candidate_dropped_benign": ReasonCode("candidate_dropped_benign", ReasonClass.DIAGNOSTIC),
    "candidate_outside_defect_set": ReasonCode("candidate_outside_defect_set", ReasonClass.DIAGNOSTIC),
    "stale_waiver_present": ReasonCode("stale_waiver_present", ReasonClass.DIAGNOSTIC),
    "stale_acceptance_present": ReasonCode("stale_acceptance_present", ReasonClass.DIAGNOSTIC),
    "rename_limit_exceeded": ReasonCode("rename_limit_exceeded", ReasonClass.DIAGNOSTIC),
}


RUN_CONDITIONS: dict[str, ReasonCode] = {
    "target_drift": ReasonCode("target_drift", ReasonClass.RUN_CONDITION),
}


DEFECT_REASON_CODES: dict[str, str] = {
    "GRD-UNGROUNDED-EDIT": "policy_prohibited",
    "DEL-REACHABLE-SYMBOL": "symbol_live",
    "DEL-DANGLING-REFERENCE": "dangling_reference",
    "DEL-DYNAMIC-REFERENCE": "dynamic_reference_removed",
    "CTR-SIGNATURE-BREAK": "signature_break",
    "CTR-EXPORT-BREAK": "export_break",
    "CTR-CALL-INCOMPATIBLE": "call_incompatible",
    "SEM-GUARD-REMOVED": "guard_removed",
    "SEM-GUARD-WEAKENED": "guard_weakened",
    "SEM-GUARD-INVERTED": "guard_inverted",
    "SEM-BINDING-SWAP": "binding_swap",
    "SEM-EXCEPTION-REMOVED": "exception_removed",
    "SEC-SECRET": "secret_detected",
    "SEC-SECRET-TO-SINK": "secret_to_sink",
    "SEC-TAINT-TO-SINK": "taint_to_sink",
    "SEC-DANGEROUS-CALL": "dangerous_call",
}


EVIDENCE_KINDS_BY_DEFECT: dict[str, frozenset[str]] = {
    "GRD-UNGROUNDED-EDIT": frozenset({"provenance"}),
    "DEL-REACHABLE-SYMBOL": frozenset({"reference"}),
    "DEL-DANGLING-REFERENCE": frozenset({"reference"}),
    "DEL-DYNAMIC-REFERENCE": frozenset({"reference"}),
    "CTR-SIGNATURE-BREAK": frozenset({"call_site", "reference"}),
    "CTR-EXPORT-BREAK": frozenset({"reference"}),
    "CTR-CALL-INCOMPATIBLE": frozenset({"call_site"}),
    "SEM-GUARD-REMOVED": frozenset({"solver"}),
    "SEM-GUARD-WEAKENED": frozenset({"solver"}),
    "SEM-GUARD-INVERTED": frozenset({"solver"}),
    "SEM-BINDING-SWAP": frozenset({"solver"}),
    "SEM-EXCEPTION-REMOVED": frozenset({"solver"}),
    "SEC-SECRET": frozenset({"secret_validation"}),
    "SEC-SECRET-TO-SINK": frozenset({"taint_path"}),
    "SEC-TAINT-TO-SINK": frozenset({"taint_path"}),
    "SEC-DANGEROUS-CALL": frozenset({"call_site"}),
}


ALL_CODES: dict[str, ReasonCode] = {
    **FAULTS,
    **REVIEWS,
    **GAPS,
    **FINDINGS,
    **DIAGNOSTICS,
    **RUN_CONDITIONS,
}


def is_acceptable_gap(code: str) -> bool:
    return GAPS.get(code, ReasonCode(code, ReasonClass.GAP)).acceptable


def is_finding_code(code: str) -> bool:
    return code in FINDINGS


def is_fault_code(code: str) -> bool:
    return code in FAULTS


def is_review_code(code: str) -> bool:
    return code in REVIEWS


def reason_class(code: str) -> ReasonClass | None:
    entry = ALL_CODES.get(code)
    return entry.reason_class if entry else None


def validate_finding_triple(defect_id: str, code: str, evidence_kind: str) -> bool:
    if DEFECT_REASON_CODES.get(defect_id) != code:
        return False
    return evidence_kind in EVIDENCE_KINDS_BY_DEFECT.get(defect_id, frozenset())


__all__ = [
    "ALL_CODES",
    "DEFECT_REASON_CODES",
    "DIAGNOSTICS",
    "EVIDENCE_KINDS_BY_DEFECT",
    "FAULTS",
    "FINDINGS",
    "GAPS",
    "REVIEWS",
    "RUN_CONDITIONS",
    "ReasonClass",
    "ReasonCode",
    "is_acceptable_gap",
    "is_fault_code",
    "is_finding_code",
    "is_review_code",
    "reason_class",
    "validate_finding_triple",
]
