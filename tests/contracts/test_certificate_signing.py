import dataclasses
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verifyci.contracts.canonical import canonical_certificate_bytes, certificate_hash
from verifyci.contracts.verification_ir import (
    Certificate,
    Conclusion,
    FileEvidence,
    Premise,
    ExecutionTrace,
)
from verifyci.verification.semi_formal_reason import SemiFormalReasoner


def _sample_certificate() -> Certificate:
    return Certificate(
        certificate_id="cert-test-001",
        premises=[
            Premise(premise_id="p-1", statement="file_changed:src/foo.py", source="src/foo.py"),
        ],
        evidence=[
            FileEvidence(
                file_path="src/foo.py",
                line_start=1,
                line_end=5,
                snippet="def foo():\n    return 42\n",
                source_hash="sha256-foo",
            )
        ],
        execution_traces=[
            ExecutionTrace(trace_id="t-1", path=["e-1", "e-2"], conditions=[]),
        ],
        conclusion=Conclusion(result="pass", reasoning="all deterministic checks passed"),
        confidence=1.0,
        generated_by="test_suite",
        checked_by=["diff_parsed", "seeds_grounded"],
        verification_method="semi_formal_reasoning",
        certificate_verified=True,
        timestamp=1700000000.0,
    )


def test_certificate_sign_and_verify():
    """Test generating an Ed25519 keypair, signing a Certificate, and verifying its signature."""
    private_key = Ed25519PrivateKey.generate()
    pub_key = private_key.public_key()
    pub_hex = pub_key.public_bytes_raw().hex()

    cert = _sample_certificate()
    assert cert.signature is None
    assert cert.signing_key_id is None
    assert cert.signature_algorithm is None

    # Canonical bytes and content hash match contract functions
    assert cert.canonical_bytes() == canonical_certificate_bytes(cert)
    assert cert.content_hash() == certificate_hash(cert)

    # Sign certificate
    signed_cert = cert.sign(private_key)
    assert isinstance(signed_cert, Certificate)
    assert signed_cert.signature is not None
    assert len(signed_cert.signature) == 128  # 64 bytes in hex
    assert signed_cert.signing_key_id == pub_hex
    assert signed_cert.signature_algorithm == "ed25519"

    # Envelope binding: signing_key_id and signature_algorithm are bound in signed envelope
    assert signed_cert.signing_key_id == pub_hex
    assert signed_cert.signature_algorithm == "ed25519"

    # Fail-closed without external trust store configured
    assert signed_cert.verify_signature() is False

    # Verification: explicit public key object, raw bytes, and hex string
    assert signed_cert.verify_signature(pub_key) is True
    assert signed_cert.verify_signature(pub_key.public_bytes_raw()) is True
    assert signed_cert.verify_signature(pub_hex) is True

    # Verification: trusted_keys store argument
    assert signed_cert.verify_signature(trusted_keys=[pub_hex]) is True
    assert signed_cert.verify_signature(trusted_keys={pub_hex: pub_key}) is True


def test_certificate_sign_with_raw_bytes_and_hex_and_key_id():
    """Test signing with raw private key bytes, hex string, and custom key_id."""
    private_key = Ed25519PrivateKey.generate()
    priv_raw = private_key.private_bytes_raw()
    priv_hex = priv_raw.hex()
    pub_key = private_key.public_key()

    cert = _sample_certificate()

    # Sign using raw bytes
    signed_from_bytes = cert.sign(priv_raw)
    assert signed_from_bytes.verify_signature(pub_key) is True

    # Sign using hex string
    signed_from_hex = cert.sign(priv_hex)
    assert signed_from_hex.verify_signature(pub_key) is True

    # Sign with custom key_id
    custom_key_id = "signer-identity-prod-01"
    signed_with_id = cert.sign(private_key, key_id=custom_key_id)
    assert signed_with_id.signing_key_id == custom_key_id
    assert signed_with_id.verify_signature(pub_key) is True


def test_tampering_any_field_fails_verification():
    """Test that tampering with any field in Certificate causes verify_signature() to return False."""
    private_key = Ed25519PrivateKey.generate()
    pub_key = private_key.public_key()
    cert = _sample_certificate().sign(private_key)
    assert cert.verify_signature(pub_key) is True

    tampered_fields = [
        ("conclusion", Conclusion(result="fail", reasoning="tampered reasoning")),
        ("confidence", 0.5),
        ("certificate_verified", False),
        ("certificate_id", "cert-tampered-999"),
        ("timestamp", 1700000001.0),
        ("generated_by", "adversary"),
        ("verification_method", "fraudulent"),
        (
            "premises",
            [Premise(premise_id="p-fake", statement="unverified", source="unknown")],
        ),
        (
            "evidence",
            [
                FileEvidence(
                    file_path="src/evil.py",
                    line_start=1,
                    line_end=1,
                    snippet="evil()",
                    source_hash="sha256-evil",
                )
            ],
        ),
        (
            "execution_traces",
            [ExecutionTrace(trace_id="t-fake", path=["e-bad"], conditions=[])],
        ),
        ("checked_by", ["tampered_check"]),
        ("signing_key_id", "attacker-forged-key-id"),
        ("signature_algorithm", "ed25519-fake"),
    ]

    for field_name, new_val in tampered_fields:
        tampered_cert = dataclasses.replace(cert, **{field_name: new_val})
        assert tampered_cert.verify_signature(pub_key) is False, f"Tampering with {field_name} did not fail verification"


def test_fail_closed_on_wrong_key_corrupted_signature_missing_signature():
    """Test wrong public key, corrupted signature hex, and missing signature fail-closed."""
    private_key = Ed25519PrivateKey.generate()
    cert = _sample_certificate().sign(private_key)

    # 1. Wrong public key
    other_key = Ed25519PrivateKey.generate()
    assert cert.verify_signature(other_key.public_key()) is False
    assert cert.verify_signature(other_key.public_key().public_bytes_raw().hex()) is False
    assert cert.verify_signature("00" * 32) is False

    # 2. Corrupted signature hex
    corrupted_hex = dataclasses.replace(cert, signature="bad_hex_not_valid_signature")
    assert corrupted_hex.verify_signature() is False

    # 3. Corrupted signature bytes (wrong 64-byte payload)
    corrupted_bytes = dataclasses.replace(cert, signature="00" * 64)
    assert corrupted_bytes.verify_signature() is False

    # 4. Truncated signature
    truncated_sig = dataclasses.replace(cert, signature="aa" * 32)
    assert truncated_sig.verify_signature() is False

    # 5. Missing signature
    missing_sig = dataclasses.replace(cert, signature=None)
    assert missing_sig.verify_signature() is False

    empty_sig = dataclasses.replace(cert, signature="")
    assert empty_sig.verify_signature() is False

    # 6. Unsupported signature algorithm
    wrong_alg = dataclasses.replace(cert, signature_algorithm="hmac-sha256")
    assert wrong_alg.verify_signature() is False

    # 7. Unsupported or malformed public key argument
    assert cert.verify_signature("not-a-valid-pubkey") is False
    assert cert.verify_signature(12345) is False
    assert cert.verify_signature(b"too_short") is False

    # 8. Unsigned certificate
    unsigned_cert = _sample_certificate()
    assert unsigned_cert.verify_signature() is False


def test_environment_variable_public_keys(monkeypatch):
    """Test verification using VERIFYCI_CERTIFICATE_PUBLIC_KEYS environment variable."""
    private_key = Ed25519PrivateKey.generate()
    pub_hex = private_key.public_key().public_bytes_raw().hex()

    # Sign with non-hex key_id so signing_key_id alone cannot verify without env var
    cert = _sample_certificate().sign(private_key, key_id="service-key-alpha")
    assert cert.signing_key_id == "service-key-alpha"

    # Fails without env var configured
    monkeypatch.delenv("VERIFYCI_CERTIFICATE_PUBLIC_KEYS", raising=False)
    monkeypatch.delenv("ACI_CERTIFICATE_PUBLIC_KEYS", raising=False)
    assert cert.verify_signature() is False

    # Succeeds with single hex key in VERIFYCI_CERTIFICATE_PUBLIC_KEYS
    monkeypatch.setenv("VERIFYCI_CERTIFICATE_PUBLIC_KEYS", pub_hex)
    assert cert.verify_signature() is True

    # Succeeds with JSON mapping of key_id -> pubkey
    key_map = json.dumps({"service-key-alpha": pub_hex, "other-key": "00" * 32})
    monkeypatch.setenv("VERIFYCI_CERTIFICATE_PUBLIC_KEYS", key_map)
    assert cert.verify_signature() is True

    # Succeeds with comma-separated list of keys
    csv_keys = f"{"11" * 32},{pub_hex},{"22" * 32}"
    monkeypatch.setenv("VERIFYCI_CERTIFICATE_PUBLIC_KEYS", csv_keys)
    assert cert.verify_signature() is True

    # Fails when env var has only wrong keys
    wrong_keys = f"{"11" * 32},{"22" * 32}"
    monkeypatch.setenv("VERIFYCI_CERTIFICATE_PUBLIC_KEYS", wrong_keys)
    assert cert.verify_signature() is False


def test_semi_formal_reasoner_with_signing_key():
    """Test SemiFormalReasoner configured with a signing key produces a valid signed certificate."""
    private_key = Ed25519PrivateKey.generate()
    pub_hex = private_key.public_key().public_bytes_raw().hex()

    # 1. Reasoner without signing key produces unsigned certificate
    unsigned_reasoner = SemiFormalReasoner()
    cert_unsigned = unsigned_reasoner.verify(diff="", graph=None)
    assert cert_unsigned.signature is None
    assert cert_unsigned.signing_key_id is None
    assert cert_unsigned.signature_algorithm is None
    assert cert_unsigned.verify_signature() is False

    # 2. Reasoner with Ed25519PrivateKey produces signed certificate
    signed_reasoner = SemiFormalReasoner(signing_key=private_key)
    cert_empty = signed_reasoner.verify(diff="", graph=None)
    assert cert_empty.signature is not None
    assert cert_empty.signing_key_id == pub_hex
    assert cert_empty.signature_algorithm == "ed25519"
    assert cert_empty.verify_signature(private_key.public_key()) is True

    # 3. Non-code path (documentation) produces valid signed certificate
    doc_diff = (
        "diff --git a/docs/guide.md b/docs/guide.md\n"
        "--- a/docs/guide.md\n"
        "+++ b/docs/guide.md\n"
        "@@ -1,1 +1,2 @@\n"
        "-guide v1\n"
        "+guide v2\n"
        "+new line\n"
    )
    cert_doc = signed_reasoner.verify(diff=doc_diff, graph=None)
    assert cert_doc.signature is not None
    assert cert_doc.signing_key_id == pub_hex
    assert cert_doc.conclusion.result == "pass"
    assert cert_doc.verify_signature(private_key.public_key()) is True

    # 4. Reasoner with hex private key and explicit signing_key_id
    priv_hex = private_key.private_bytes_raw().hex()
    custom_id_reasoner = SemiFormalReasoner(
        signing_key=priv_hex,
        signing_key_id="custom-reasoner-id",
    )
    cert_custom = custom_id_reasoner.verify(diff="", graph=None)
    assert cert_custom.signature is not None
    assert cert_custom.signing_key_id == "custom-reasoner-id"
    assert cert_custom.signature_algorithm == "ed25519"
    assert cert_custom.verify_signature(private_key.public_key()) is True


def test_unknown_key_cannot_self_certify(monkeypatch):
    """Regression test: A certificate signed by an unknown key is rejected
    even if its embedded identifier contains that key's public key."""
    attacker_key = Ed25519PrivateKey.generate()
    attacker_pub_hex = attacker_key.public_key().public_bytes_raw().hex()

    trusted_key = Ed25519PrivateKey.generate()
    trusted_pub_hex = trusted_key.public_key().public_bytes_raw().hex()

    # Attacker signs certificate with attacker private key and embeds attacker pubkey in signing_key_id
    malicious_cert = _sample_certificate().sign(attacker_key, key_id=attacker_pub_hex)
    assert malicious_cert.signing_key_id == attacker_pub_hex

    # 1. Without trust store configured, fails closed
    monkeypatch.delenv("VERIFYCI_CERTIFICATE_PUBLIC_KEYS", raising=False)
    monkeypatch.delenv("ACI_CERTIFICATE_PUBLIC_KEYS", raising=False)
    assert malicious_cert.verify_signature() is False

    # 2. With trust store configured with authorized key, unknown attacker key is rejected!
    monkeypatch.setenv("VERIFYCI_CERTIFICATE_PUBLIC_KEYS", trusted_pub_hex)
    assert malicious_cert.verify_signature() is False

    # 3. With mapping trust store {"trusted_signer": trusted_pub_hex}, attacker is rejected!
    key_map = json.dumps({"trusted_signer": trusted_pub_hex})
    monkeypatch.setenv("VERIFYCI_CERTIFICATE_PUBLIC_KEYS", key_map)
    assert malicious_cert.verify_signature() is False
    assert malicious_cert.verify_signature(trusted_keys={"trusted_signer": trusted_pub_hex}) is False

    # 4. Legitimately signed certificate succeeds under the same trusted store
    valid_cert = _sample_certificate().sign(trusted_key, key_id=trusted_pub_hex)
    assert valid_cert.verify_signature(trusted_keys=[trusted_pub_hex]) is True
    assert valid_cert.verify_signature() is True


def test_malformed_metadata_and_non_finite_fields_fail_closed():
    """Regression test: Malformed signer metadata types and non-finite float fields
    fail closed without raising unhandled exceptions (AttributeError, ValueError, TypeError)."""
    private_key = Ed25519PrivateKey.generate()
    pub_key = private_key.public_key()
    pub_hex = pub_key.public_bytes_raw().hex()
    valid_cert = _sample_certificate().sign(private_key, key_id=pub_hex)
    assert valid_cert.verify_signature(pub_key) is True

    # 1. Malformed signature_algorithm types (None, non-string: int, list, dict, object)
    for bad_alg in [None, "", 123, ["ed25519"], {"algo": "ed25519"}, object(), 3.14, True]:
        bad_cert = dataclasses.replace(valid_cert, signature_algorithm=bad_alg)
        assert bad_cert.verify_signature(pub_key) is False
        assert bad_cert.verify_signature(trusted_keys=[pub_hex]) is False

    # 2. Malformed signing_key_id types (non-string: int, list, dict, object)
    for bad_kid in [123, [pub_hex], {"key_id": pub_hex}, object(), False]:
        bad_cert = dataclasses.replace(valid_cert, signing_key_id=bad_kid)
        assert bad_cert.verify_signature(pub_key) is False
        assert bad_cert.verify_signature(trusted_keys=[pub_hex]) is False

    # 3. Malformed signature types (non-str/bytes/bytearray: int, list, dict)
    for bad_sig in [123, [1, 2, 3], {"sig": "hex"}, object(), False]:
        bad_cert = dataclasses.replace(valid_cert, signature=bad_sig)
        assert bad_cert.verify_signature(pub_key) is False
        assert bad_cert.verify_signature(trusted_keys=[pub_hex]) is False

    # 4. Non-finite float fields (NaN, Infinity, -Infinity)
    # json.dumps(..., allow_nan=False) raises ValueError on non-finite floats;
    # verify_signature must catch this and return False fail-closed.
    for bad_float in [float("nan"), float("inf"), float("-inf")]:
        # Non-finite confidence
        cert_bad_conf = dataclasses.replace(valid_cert, confidence=bad_float)
        assert cert_bad_conf.verify_signature(pub_key) is False
        assert cert_bad_conf.verify_signature(trusted_keys=[pub_hex]) is False

        # Non-finite timestamp
        cert_bad_ts = dataclasses.replace(valid_cert, timestamp=bad_float)
        assert cert_bad_ts.verify_signature(pub_key) is False
        assert cert_bad_ts.verify_signature(trusted_keys=[pub_hex]) is False


def test_missing_signature_algorithm_rejected():
    """Regression test: A certificate with a valid Ed25519 signature over an envelope
    where signature_algorithm is None (missing) is rejected fail-closed."""
    private_key = Ed25519PrivateKey.generate()
    pub_key = private_key.public_key()
    pub_hex = pub_key.public_bytes_raw().hex()

    cert = _sample_certificate()
    # Construct an envelope with signature_algorithm=None (omitted)
    envelope = dataclasses.replace(
        cert,
        signature=None,
        signing_key_id=pub_hex,
        signature_algorithm=None,
    )
    # Compute a valid cryptographic Ed25519 signature directly over this envelope's canonical bytes
    sig_bytes = private_key.sign(envelope.canonical_bytes())
    cert_missing_alg = dataclasses.replace(
        envelope,
        signature=sig_bytes.hex(),
    )
    assert cert_missing_alg.signature_algorithm is None
    # Must fail closed: missing signature algorithm is rejected even with valid signature
    assert cert_missing_alg.verify_signature(pub_key) is False
    assert cert_missing_alg.verify_signature(trusted_keys=[pub_hex]) is False


