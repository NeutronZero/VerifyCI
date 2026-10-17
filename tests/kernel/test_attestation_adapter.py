"""Tests for In-Toto DSSE Ed25519 cryptographic signing and verification."""

from __future__ import annotations

import base64

from verifyci.contracts.attestation import CanonicalAttestationPayload
from verifyci.contracts.verdict import VerificationVerdict
from verifyci.extensions.attestation_adapter import InTotoDSSEAdapter


def test_dsse_signing_and_verification_roundtrip() -> None:
    signer, pubkey = InTotoDSSEAdapter.generate_ephemeral()

    payload = CanonicalAttestationPayload(
        base_commit_sha="c1",
        head_commit_sha="c2",
        files=("src/app.py",),
        policy_hash="p_strict",
        verdict=VerificationVerdict.PASS,
        findings=(),
    )
    raw_bytes = payload.canonical_bytes()

    envelope = signer.sign_payload(raw_bytes)
    assert envelope["payloadType"] == "application/vnd.in-toto+json"
    assert len(envelope["signatures"]) == 1

    # Valid envelope verifies
    assert InTotoDSSEAdapter.verify_envelope(envelope, pubkey) is True


def test_dsse_tampered_payload_is_rejected() -> None:
    signer, pubkey = InTotoDSSEAdapter.generate_ephemeral()
    raw_bytes = b'{"msg": "authentic payload"}'
    envelope = signer.sign_payload(raw_bytes)

    # Tamper with payload
    tampered_bytes = bytearray(raw_bytes)
    tampered_bytes[0] ^= 0xFF
    envelope_tampered = {
        "payloadType": envelope["payloadType"],
        "payload": base64.b64encode(tampered_bytes).decode("ascii"),
        "signatures": envelope["signatures"],
    }

    assert InTotoDSSEAdapter.verify_envelope(envelope_tampered, pubkey) is False


def test_dsse_tampered_signature_is_rejected() -> None:
    signer, pubkey = InTotoDSSEAdapter.generate_ephemeral()
    raw_bytes = b'{"msg": "authentic payload"}'
    envelope = signer.sign_payload(raw_bytes)

    # Tamper with signature
    sig_b64 = envelope["signatures"][0]["sig"]
    sig_bytes = bytearray(base64.b64decode(sig_b64))
    sig_bytes[0] ^= 0xFF
    tampered_sig = base64.b64encode(sig_bytes).decode("ascii")

    envelope_tampered = {
        "payloadType": envelope["payloadType"],
        "payload": envelope["payload"],
        "signatures": [{"keyid": envelope["signatures"][0]["keyid"], "sig": tampered_sig}],
    }

    assert InTotoDSSEAdapter.verify_envelope(envelope_tampered, pubkey) is False
