import hashlib
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verifyci.contracts.canonical import (
    effective_policy_bundle_hash,
    report_hash,
)
from verifyci.contracts.verification_ir import (
    BlastRadiusResult,
    CheckResult,
    CheckSummary,
    EvidenceManifestEntry,
    VerificationEnvelope,
    VerificationPolicy,
    VerificationReport,
)
from verifyci.verification.policy import PolicyEvaluator


def _create_sample_report(verdict: str = "PASS") -> VerificationReport:
    check = CheckResult(
        check_id="chk_1",
        passed=(verdict == "PASS"),
        score=1.0 if verdict == "PASS" else 0.0,
        evidence=["evidence_ref_1"],
        explanation="test check outcome",
        blocking=True,
        established=True,
        deterministic=True,
    )
    blast = BlastRadiusResult(
        affected_callers=[],
        affected_callees=[],
        test_coverage_gap=[],
        risk_score=0.0,
        dependency_impact=[],
        vulnerability_impact=[],
    )
    return VerificationReport(
        report_id="rep_123",
        task_id="task_verify",
        policy_id="default",
        checks=[check],
        blast_radius=blast,
        timestamp=time.time(),
    )


def test_verification_envelope_signing_and_verification():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_hex = pub.public_bytes_raw().hex()

    report = _create_sample_report("PASS")
    rep_hash = report_hash(report)
    policy = VerificationPolicy.strict_gate("default")
    pol_hash = effective_policy_bundle_hash(policy)

    envelope = VerificationEnvelope(
        envelope_version="1.0",
        report_id=report.report_id,
        report_hash=rep_hash,
        verdict="PASS",
        rationale="all_checks_passed",
        repository_id="repo_verifyci",
        revision_id="rev_abc",
        source_commit_id="commit_123",
        diff_hash=hashlib.sha256(b"diff content").hexdigest(),
        effective_policy_bundle_hash=pol_hash,
        evidence_manifest=(
            EvidenceManifestEntry(role="test_role", identity="id1", content_hash="hash1"),
        ),
        check_summaries=(
            CheckSummary(
                check_id="chk_1",
                passed=True,
                blocking=True,
                established=True,
                score=1.0,
                evidence_count=1,
            ),
        ),
        created_at=time.time(),
        verifier_build_id="verifyci-0.1.0",
    )

    signed_env = envelope.sign(priv, key_id=pub_hex)
    assert signed_env.signature is not None
    assert signed_env.signing_key_id == pub_hex
    assert signed_env.signature_algorithm == "ed25519"

    # Explicit public key verification
    assert signed_env.verify_signature(public_key=pub) is True
    assert signed_env.verify_signature(public_key=pub_hex) is True

    # Trusted keys store verification
    assert signed_env.verify_signature(trusted_keys=[pub_hex]) is True
    assert signed_env.verify_signature(trusted_keys={"signer_1": pub_hex}) is True

    # Wrong public key fails closed
    other_priv = Ed25519PrivateKey.generate()
    other_pub = other_priv.public_key()
    assert signed_env.verify_signature(public_key=other_pub) is False
    assert signed_env.verify_signature(trusted_keys=[other_pub.public_bytes_raw().hex()]) is False


def test_verification_envelope_anti_self_certification():
    """An unknown key must be rejected even if signing_key_id embeds that key's public hex."""
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()

    report = _create_sample_report("PASS")
    envelope = VerificationEnvelope(
        envelope_version="1.0",
        report_id=report.report_id,
        report_hash=report_hash(report),
        verdict="PASS",
        rationale="all_checks_passed",
        repository_id="repo_verifyci",
        revision_id="rev_abc",
        source_commit_id="commit_123",
        diff_hash=hashlib.sha256(b"diff content").hexdigest(),
        effective_policy_bundle_hash=effective_policy_bundle_hash(VerificationPolicy.strict_gate()),
        evidence_manifest=(),
        check_summaries=(),
        created_at=time.time(),
        verifier_build_id="verifyci-0.1.0",
    )
    signed_env = envelope.sign(priv, key_id=pub_hex)

    # Empty trust store -> fails closed
    assert signed_env.verify_signature(trusted_keys=[]) is False
    assert signed_env.verify_signature(trusted_keys=None) is False

    # Trust store with a different key -> fails closed
    trusted_different = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    assert signed_env.verify_signature(trusted_keys=[trusted_different]) is False


def test_verification_envelope_tampering_invalidates_signature():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    report = _create_sample_report("PASS")
    envelope = VerificationEnvelope(
        envelope_version="1.0",
        report_id=report.report_id,
        report_hash=report_hash(report),
        verdict="PASS",
        rationale="all_checks_passed",
        repository_id="repo_verifyci",
        revision_id="rev_abc",
        source_commit_id="commit_123",
        diff_hash=hashlib.sha256(b"diff content").hexdigest(),
        effective_policy_bundle_hash=effective_policy_bundle_hash(VerificationPolicy.strict_gate()),
        evidence_manifest=(EvidenceManifestEntry("role1", "id1", "h1"),),
        check_summaries=(CheckSummary("c1", True, True, True, 1.0, 1),),
        created_at=time.time(),
        verifier_build_id="verifyci-0.1.0",
    )
    signed = envelope.sign(priv)
    assert signed.verify_signature(public_key=pub) is True

    import dataclasses
    # Tampering with verdict
    tampered_verdict = dataclasses.replace(signed, verdict="FAIL")
    assert tampered_verdict.verify_signature(public_key=pub) is False

    # Tampering with report_hash
    tampered_report = dataclasses.replace(signed, report_hash="0" * 64)
    assert tampered_report.verify_signature(public_key=pub) is False

    # Tampering with effective_policy_bundle_hash
    tampered_policy = dataclasses.replace(signed, effective_policy_bundle_hash="f" * 64)
    assert tampered_policy.verify_signature(public_key=pub) is False

    # Tampering with revision_id
    tampered_rev = dataclasses.replace(signed, revision_id="rev_tampered")
    assert tampered_rev.verify_signature(public_key=pub) is False

    # Tampering with diff_hash
    tampered_diff = dataclasses.replace(signed, diff_hash="a" * 64)
    assert tampered_diff.verify_signature(public_key=pub) is False

    # Tampering with evidence manifest
    tampered_manifest = dataclasses.replace(signed, evidence_manifest=())
    assert tampered_manifest.verify_signature(public_key=pub) is False


def test_effective_policy_bundle_hash_changes_on_any_input():
    p1 = VerificationPolicy.strict_gate("default")
    p2 = VerificationPolicy.advisory("default")
    h1 = effective_policy_bundle_hash(p1)
    h2 = effective_policy_bundle_hash(p2)
    assert h1 != h2

    # Invariants affect hash
    h_with_inv = effective_policy_bundle_hash(p1, invariants=[{"id": "inv1", "rule": "r"}])
    assert h_with_inv != h1

    # Waivers affect hash
    h_with_waiver = effective_policy_bundle_hash(p1, waivers=[{"waiver_id": "w1"}])
    assert h_with_waiver != h1


def test_advisory_profile_emits_advisory_warn_never_pass():
    policy = VerificationPolicy.advisory("advisory_policy")
    check = CheckResult(
        check_id="non_blocking_chk",
        passed=False,
        score=0.0,
        evidence=[],
        explanation="advisory failure",
        blocking=False,
        established=True,
        deterministic=True,
    )
    blast = BlastRadiusResult([], [], [], 0.0, [], [])
    report = VerificationReport("rep", "task", "advisory_policy", [check], blast, 0.0)

    decision = PolicyEvaluator().evaluate(report, policy)
    assert decision.status == "ADVISORY_WARN"
    assert decision.status != "PASS"
