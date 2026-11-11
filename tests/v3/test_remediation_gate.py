"""Remediation-phase regression tests (Nov 2026).

Fail-closed hardening for reason-code validation, provenance-premise
integrity, missing-fact scope gaps, waiver/acceptance matching, and
evidence payload integrity.
"""

from __future__ import annotations

import pytest

from verifyci.checks.base import (
    CheckContext,
    error_result,
    inconclusive_gap_result,
    make_finding,
    unsupported_scope_gaps,
)
from verifyci.contracts.model import (
    Evidence,
    EvidenceKind,
    Finding,
    Outcome,
    Policy,
    Tier,
    WitnessLevel,
)
from verifyci.contracts.reason_codes import GAPS
from verifyci.scope.entities import ChangedScope, SourceFacts


def _entry(path: str = "app.py") -> "object":
    from verifyci.contracts.model import DiffEntry
    return DiffEntry(
        status="M",
        base_path=path,
        head_path=path,
        base_blob="a" * 40,
        head_blob="b" * 40,
        base_mode="100644",
        head_mode="100644",
        base_source="x = 1\n",
        head_source="x = 2\n",
        hunks=(),
    )


def _scope(head_facts=None, base_facts=None) -> ChangedScope:
    return ChangedScope(
        base_facts=base_facts or {},
        head_facts=head_facts or {},
        changed_entities=frozenset(),
        base_entities=frozenset(),
        head_entities=frozenset(),
    )


def _context(entries=(), head_facts=None, base_facts=None, policy=None) -> CheckContext:
    policy = policy or Policy(
        raw={}, blob_hash=None, source="builtin_bootstrap_v1", effective_hash="eff-h"
    )
    return CheckContext(
        git=None,
        policy=policy,
        entries=tuple(entries),
        scope=_scope(head_facts, base_facts),
        as_of_date="2026-10-21",
        object_format="sha1",
        target_base_commit="0" * 40,
        merge_base_commit="1" * 40,
        head_commit="2" * 40,
        toolchain_fingerprint="tc-fp",
    )


# ---------------------------------------------------------------------------
# A1: make_finding rejects caller premises that shadow required provenance.
# ---------------------------------------------------------------------------

REQUIRED_KEYS = (
    "target_base_commit",
    "merge_base_commit",
    "head_commit",
    "base_blob",
    "head_blob",
    "authoritative_policy_source",
    "authoritative_policy_hash",
    "check_version",
    "toolchain_fingerprint",
)


def _sec_finding(ctx, premises):
    return make_finding(
        context=ctx,
        check_id="security",
        defect_id="SEC-SECRET",
        subject={"path": "app.py"},
        premises=premises,
        evidence_kind=EvidenceKind.SECRET_VALIDATION,
        evidence_payload={"redacted": "ghp_..."},
        message="secret",
    )


def test_a1_make_finding_rejects_premise_overriding_required_provenance():
    for key in REQUIRED_KEYS:
        ctx = _context(entries=(_entry(),))
        with pytest.raises(ValueError) as exc:
            _sec_finding(ctx, {key: "forged-provenance"})
        assert key in str(exc.value)


def test_a1_make_finding_preserves_non_required_premises():
    ctx = _context(entries=(_entry(),))
    finding = _sec_finding(ctx, {"problem": "high entropy token"})
    assert finding.premises["problem"] == "high entropy token"
    assert finding.premises["target_base_commit"] == "0" * 40
    assert finding.premises["head_commit"] == "2" * 40
    assert finding.premises["base_blob"] == "sha1:" + "a" * 40
    assert finding.premises["toolchain_fingerprint"] == "tc-fp"
    assert finding.premises["authoritative_policy_hash"] == "eff-h"


# ---------------------------------------------------------------------------
# A2: changed paths missing from both fact maps are explicit scope gaps.
# ---------------------------------------------------------------------------

def test_a2_unsupported_scope_gaps_report_missing_facts():
    ctx = _context(entries=(_entry("app.py"),))
    gaps = unsupported_scope_gaps(ctx, "deletion")
    assert len(gaps) == 1
    item = gaps[0]
    assert item.reason_code == "unsupported_language"
    assert item.subject == {
        "check_id": "deletion",
        "path": "app.py",
        "language": None,
        "parse_error": "facts_missing",
    }


def test_a2_gap_classification_kept_for_present_facts():
    supported = SourceFacts(path="app.py", language="python", supported=True)
    unsupported = SourceFacts(
        path="old.rs", language="rust", supported=False,
        parse_error="unsupported language frontend",
    )
    ctx = _context(
        entries=(_entry("app.py"), _entry("old.rs")),
        head_facts={"app.py": supported},
        base_facts={"old.rs": unsupported},
    )
    gaps = unsupported_scope_gaps(ctx, "deletion", exclude_path=lambda p: p == "old.rs")
    assert gaps == []  # supported path never produces a gap

    gaps = unsupported_scope_gaps(ctx, "deletion")
    assert [g.reason_code for g in gaps] == ["unsupported_language"]
    assert gaps[0].subject["language"] == "rust"
    assert gaps[0].subject["parse_error"] == "unsupported language frontend"


# ---------------------------------------------------------------------------
# A3: inconclusive_gap_result validates its reason code against the registry.
# ---------------------------------------------------------------------------

def test_a3_raise_on_unknown_gap_reason_code():
    ctx = _context()
    with pytest.raises(ValueError) as exc:
        inconclusive_gap_result(
            context=ctx,
            check_id="contract",
            reason_code="made_up_gap_code",
            detail="x",
        )
    assert "unknown" in str(exc.value)


def test_a3_inconclusive_gap_result_accepts_registered_gap_code():
    ctx = _context()
    for code in ("parse_resource_limit", "budget_exhausted", "watchdog_interrupted"):
        assert code in GAPS
        result = inconclusive_gap_result(
            context=ctx, check_id="deletion", reason_code=code, detail="d"
        )
        assert result.outcome == Outcome.INCONCLUSIVE
        assert result.coverage_gaps[0].reason_code == code


# ---------------------------------------------------------------------------
# A4: error_result validates its fault code against the registry.
# ---------------------------------------------------------------------------

def test_a4_error_result_rejects_unregistered_reason_code():
    ctx = _context()
    with pytest.raises(ValueError) as exc:
        error_result(context=ctx, check_id="deletion", detail="oops", reason_code="bogus_fault")
    assert "bogus_fault" in str(exc.value)


def test_a4_error_result_default_not_executed_still_uses_registered_fault():
    from verifyci.contracts.reason_codes import is_fault_code

    ctx = _context()
    assert is_fault_code("not_executed")  # default must be registered
    result = error_result(context=ctx, check_id="deletion", detail="oops")
    assert result.outcome == Outcome.ERROR
    assert result.reason_codes == ("not_executed",)


# ---------------------------------------------------------------------------
# A5: CheckResult.validate rejects unknown reason/gap codes (fail-closed).
# ---------------------------------------------------------------------------

def _check_result(reason_codes=(), coverage_gaps=()):
    from verifyci.contracts.model import CheckResult, Coverage, Maturity

    return CheckResult(
        check_id="deletion",
        check_version=1,
        tier=Tier.BLOCKING,
        maturity=Maturity.PROVISIONAL,
        outcome=Outcome.INCONCLUSIVE,
        coverage=Coverage.PARTIAL,
        evaluated_scope={},
        scope_enumeration={"complete": False},
        candidate_discovery={"complete": False},
        applicability_evidence={},
        method="deletion",
        method_version=1,
        reason_codes=tuple(reason_codes),
        coverage_gaps=tuple(coverage_gaps),
    )


def test_a5_validate_rejects_unknown_reason_codes():
    from verifyci.contracts.reason_codes import FAULTS, GAPS

    synchronous = FAULTS.keys() | GAPS.keys()
    result = _check_result(
        reason_codes=("totally_unknown_code", "taint_path_unresolved")
    )
    assert "totally_unknown_code" not in synchronous
    errors = result.validate()
    assert any("totally_unknown_code" in e for e in errors)


def test_a5_validate_rejects_unknown_gap_codes():
    from verifyci.contracts.model import CoverageGap

    result = _check_result(
        coverage_gaps=(CoverageGap(reason_code="not_a_registered_gap", subject={}),)
    )
    errors = result.validate()
    assert any("not_a_registered_gap" in e for e in errors)


def test_a5_validate_accepts_registered_codes():
    from verifyci.contracts.model import CoverageGap

    result = _check_result(
        reason_codes=("budget_exhausted",),
        coverage_gaps=(CoverageGap(reason_code="budget_exhausted", subject={}),),
    )
    assert result.validate() == []


# ---------------------------------------------------------------------------
# A6: waiver_for requires check_id equality even when the subject omits it.
# ---------------------------------------------------------------------------

FP = "sha256:" + "f" * 64


def _open_finding(check_id=None):
    from verifyci.contracts.model import Disposition

    subject = {"path": "app.py"}
    if check_id is not None:
        subject["check_id"] = check_id
    return Finding(
        tier=Tier.BLOCKING,
        defect_id="SEC-SECRET",
        reason_code="secret_detected",
        defect_semantics_version=1,
        subject=subject,
        premises={},
        evidence=Evidence(kind=EvidenceKind.SECRET_VALIDATION, payload={}),
        witness_level=WitnessLevel.SOURCE,
        message="m",
        disposition=Disposition.OPEN,
        fingerprint=FP,
    )


def _waiver_policy(check="security"):
    from verifyci.contracts.model import WaiverRecord

    waiver = WaiverRecord(
        record_id="w1",
        check=check,
        defect_id="SEC-SECRET",
        fingerprint=FP,
        reason="r",
        approved_by="@org/security",
        created="2026-01-01",
        expires="2026-12-31",
    )
    return Policy(
        raw={}, blob_hash=None, source="t", effective_hash="e",
        waivers={"w1": waiver},
    ), waiver


def test_a6_waiver_skipped_when_subject_lacks_check_id():
    policy, _ = _waiver_policy()
    assert policy.waiver_for(_open_finding(check_id=None)) is None


def test_a6_waiver_applies_when_check_id_matches():
    policy, waiver = _waiver_policy()
    assert policy.waiver_for(_open_finding(check_id="security")) is waiver


def test_a6_waiver_still_rejected_on_check_id_mismatch():
    policy, _ = _waiver_policy()
    assert policy.waiver_for(_open_finding(check_id="deletion")) is None


# ---------------------------------------------------------------------------
# A7: acceptance_for_gap uses a single required-check rule.
# ---------------------------------------------------------------------------

def _acceptance_policy(check: str):
    from verifyci.contracts.model import AcceptanceRecord

    record = AcceptanceRecord(
        record_id="acc1",
        check=check,
        reason_code="unknown_decorator",
        paths=("app.py",),
        symbols=(),
        reason="t",
        approved_by="@org/security",
        created="2026-01-01",
        expires="2026-12-31",
    )
    return Policy(
        raw={}, blob_hash=None, source="t", effective_hash="e",
        acceptances={"acc1": record},
    ), record


def test_a7_acceptance_ignores_check_from_subject_when_widening():
    """An acceptance for check=deletion must not match a contract-tagged gap."""
    from verifyci.contracts.model import CoverageGap

    policy, _ = _acceptance_policy(check="deletion")
    mismatched = CoverageGap(
        reason_code="unknown_decorator",
        subject={"path": "app.py", "check_id": "contract"},
    )
    # RED: OR-widening `acceptance.check in (check_id, subject_check)` makes
    # "deletion" pass here; the single rule requires subject_check first.
    assert policy.acceptance_for_gap("deletion", mismatched) is None


def test_a7_acceptance_matches_subject_check():
    from verifyci.contracts.model import CoverageGap

    policy, record = _acceptance_policy(check="contract")
    gap_item = CoverageGap(
        reason_code="unknown_decorator",
        subject={"path": "app.py", "check_id": "contract"},
    )
    assert policy.acceptance_for_gap("deletion", gap_item) is record


def test_a7_acceptance_matches_caller_check_when_subject_omits_check_id():
    from verifyci.contracts.model import CoverageGap

    policy, record = _acceptance_policy(check="deletion")
    gap_item = CoverageGap(
        reason_code="unknown_decorator",
        subject={"path": "app.py"},
    )
    assert policy.acceptance_for_gap("deletion", gap_item) is record
    assert policy.acceptance_for_gap("contract", gap_item) is None


# ---------------------------------------------------------------------------
# A8: acceptances never apply to non-acceptable gap codes (defense-in-depth).
# ---------------------------------------------------------------------------

def _inconclusive_result(check_id: str, gap_item):
    from verifyci.contracts.model import (
        CheckResult,
        Coverage,
        Maturity,
    )

    return CheckResult(
        check_id=check_id,
        check_version=1,
        tier=Tier.BLOCKING,
        maturity=Maturity.PROVISIONAL,
        outcome=Outcome.INCONCLUSIVE,
        coverage=Coverage.PARTIAL,
        evaluated_scope={},
        scope_enumeration={"complete": True},
        candidate_discovery={"complete": True},
        applicability_evidence={},
        method="deletion",
        method_version=1,
        coverage_gaps=(gap_item,),
    )


def test_a8_acceptance_not_applied_to_nonacceptable_gap():
    from verifyci.contracts.model import CoverageGap
    from verifyci.contracts.reason_codes import is_acceptable_gap
    from verifyci.gate.verdict import apply_acceptances

    gap_item = CoverageGap(
        reason_code="budget_exhausted",
        subject={"path": "app.py", "check_id": "deletion"},
    )
    assert not is_acceptable_gap("budget_exhausted")
    policy, _ = _acceptance_policy(check="deletion")
    # align acceptance reason_code with the non-acceptable gap under test
    from verifyci.contracts.model import AcceptanceRecord

    acceptance = AcceptanceRecord(
        record_id="acc-raw",
        check="deletion",
        reason_code="budget_exhausted",
        paths=("app.py",),
        symbols=(),
        reason="startle",
        approved_by="@org/security",
        created="2026-01-01",
        expires="2026-12-31",
    )
    policy = Policy(
        raw={}, blob_hash=None, source="t", effective_hash="e",
        acceptances={"acc-raw": acceptance},
    )
    evaluated, accepted, _, _ = apply_acceptances(
        [_inconclusive_result("deletion", gap_item)],
        policy,
        as_of_date="2026-10-21",
    )
    assert evaluated[0].coverage_gaps[0].accepted is False
    assert evaluated[0].coverage_gaps[0].acceptance_id is None
    assert evaluated[0].outcome == Outcome.INCONCLUSIVE
    assert accepted == ()


def test_a8_acceptance_still_applies_to_acceptable_gap():
    from verifyci.contracts.model import Coverage, CoverageGap
    from verifyci.gate.verdict import apply_acceptances

    gap_item = CoverageGap(
        reason_code="unknown_decorator",
        subject={"path": "app.py", "check_id": "deletion"},
    )
    policy, _ = _acceptance_policy(check="deletion")
    evaluated, accepted, _, _ = apply_acceptances(
        [_inconclusive_result("deletion", gap_item)],
        policy,
        as_of_date="2026-10-21",
    )
    assert evaluated[0].coverage_gaps[0].accepted is True
    assert evaluated[0].coverage_gaps[0].acceptance_id == "acc1"
    assert evaluated[0].coverage == Coverage.COMPLETE
    assert len(accepted) == 1


# ---------------------------------------------------------------------------
# A9: EvidenceBundle.verify_payload_hash recomputes the canonical digest.
# ---------------------------------------------------------------------------

def test_a9_verify_payload_hash_detects_tampering():
    from verifyci.contracts.model import EvidenceBundle
    from verifyci.evidence.canonical import payload_hash

    payload = {"verdict": {"status": "PASS"}, "n": 1}
    ok = EvidenceBundle(payload=payload, envelope={"payload_hash": payload_hash(payload)})
    assert ok.verify_payload_hash() is True

    tampered_envelope = dict(ok.envelope)
    tampered_envelope["payload_hash"] = "sha256:" + "0" * 64
    tampered = EvidenceBundle(payload=payload, envelope=tampered_envelope)
    assert tampered.verify_payload_hash() is False

    # payload mutated, envelope unchanged
    mutated = EvidenceBundle(payload={**payload, "n": 2}, envelope=dict(ok.envelope))
    assert mutated.verify_payload_hash() is False

    # absent hash cannot claim integrity
    assert EvidenceBundle(payload=payload, envelope={}).verify_payload_hash() is False
