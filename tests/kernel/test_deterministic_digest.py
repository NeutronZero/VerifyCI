"""Tests for RFC 8785 canonicalization and deterministic attestation digests."""

from __future__ import annotations

import json

from verifyci.contracts.attestation import (
    ATTESTATION_DIGEST_DOMAIN,
    CanonicalAttestationPayload,
    canonical_json_bytes,
    normalize_path,
)
from verifyci.contracts.verdict import (
    FindingReason,
    Severity,
    VerificationFinding,
    VerificationVerdict,
)


def test_normalize_path_windows_and_relative() -> None:
    assert normalize_path("src\\sub\\mod.py") == "src/sub/mod.py"
    assert normalize_path("./src/sub/mod.py") == "src/sub/mod.py"
    assert normalize_path(".\\src\\sub\\mod.py") == "src/sub/mod.py"


def test_rfc8785_canonical_json_ordering_and_separators() -> None:
    # Keys out of order, spaces in objects
    raw = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    canon = canonical_json_bytes(raw).decode("utf-8")
    expected = '{"a":2,"m":{"a":4,"b":3},"z":1}'
    assert canon == expected


def test_identical_inputs_produce_identical_digest() -> None:
    finding = VerificationFinding(
        finding_id="f1",
        rule_id="VC-TEST",
        severity=Severity.HIGH,
        verdict=VerificationVerdict.FAIL,
        reason=FindingReason.SECRET_LEAK,
        message="Secret detected",
        file_path="src/auth.py",
        start_line=10,
        end_line=10,
    )

    payload1 = CanonicalAttestationPayload(
        base_commit_sha="abc1234",
        head_commit_sha="def5678",
        files=("src/auth.py", "src/main.py"),
        policy_hash="policy_hash_v1",
        verdict=VerificationVerdict.FAIL,
        findings=(finding,),
    )

    # Identical data but files in reverse order
    payload2 = CanonicalAttestationPayload(
        base_commit_sha="abc1234",
        head_commit_sha="def5678",
        files=("src/main.py", "src/auth.py"),
        policy_hash="policy_hash_v1",
        verdict=VerificationVerdict.FAIL,
        findings=(finding,),
    )

    digest1 = payload1.compute_digest()
    digest2 = payload2.compute_digest()
    assert digest1 == digest2
    assert len(digest1) == 64


def test_different_policy_produces_different_digest() -> None:
    finding = VerificationFinding(
        finding_id="f1",
        rule_id="VC-TEST",
        severity=Severity.HIGH,
        verdict=VerificationVerdict.FAIL,
        reason=FindingReason.SECRET_LEAK,
        message="Secret detected",
        file_path="src/auth.py",
    )

    p1 = CanonicalAttestationPayload(
        base_commit_sha="abc",
        head_commit_sha="def",
        files=("src/auth.py",),
        policy_hash="policy_strict",
        verdict=VerificationVerdict.FAIL,
        findings=(finding,),
    )

    p2 = CanonicalAttestationPayload(
        base_commit_sha="abc",
        head_commit_sha="def",
        files=("src/auth.py",),
        policy_hash="policy_lenient",
        verdict=VerificationVerdict.FAIL,
        findings=(finding,),
    )

    assert p1.compute_digest() != p2.compute_digest()
