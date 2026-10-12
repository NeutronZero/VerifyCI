"""Unit tests for external CI execution receipts (F2 remediation).

Contract: keyed trust only (hmac-sha256 / ed25519, mirroring waivers,
minus bearer); canonical bytes pinned; no pin -> unverified, always.
"""
import hmac as hmac_mod
import hashlib

from verifyci.verification.receipts import (
    ReceiptTrust,
    canonical_receipt_bytes,
    verify_receipt_signature,
)


def _payload(**kw):
    base = dict(receipt_id="r1", ci_system="github-actions", run_id="123",
                commit_sha="a" * 40, targets=["e_login"],
                executed_at="2026-10-12T08:00:00Z", algorithm="hmac-sha256",
                key_id="default", signature="")
    base.update(kw)
    return base


def test_canonical_bytes_pinned():
    assert canonical_receipt_bytes(_payload()) == (
        "r1|github-actions|123|" + "a" * 40 + "|e_login|2026-10-12T08:00:00Z"
    ).encode("utf-8")


def test_canonical_sorts_targets():
    a = canonical_receipt_bytes(_payload(targets=["e2", "e1"]))
    b = canonical_receipt_bytes(_payload(targets=["e1", "e2"]))
    assert a == b


def test_canonical_rejects_noncanonical():
    for bad in ({"receipt_id": ""}, {"commit_sha": "a|b"},
                {"targets": []}, {"targets": "e1"},
                {"executed_at": None}, {"ci_system": "a|b"}):
        try:
            canonical_receipt_bytes(_payload(**bad))
        except ValueError:
            continue
        raise AssertionError(f"noncanonical accepted: {bad}")


def test_hmac_round_trip():
    secret = "test-secret"
    p = _payload()
    sig = hmac_mod.new(secret.encode(), canonical_receipt_bytes(p),
                       hashlib.sha256).hexdigest()
    p["signature"] = sig
    trust = ReceiptTrust(keys={"default": ("hmac-sha256", secret)})
    assert verify_receipt_signature(p, trust) is True


def test_hmac_wrong_secret_rejected():
    p = _payload()
    p["signature"] = "0" * 64
    trust = ReceiptTrust(keys={"default": ("hmac-sha256", "other")})
    assert verify_receipt_signature(p, trust) is False


def test_unknown_key_id_rejected():
    p = _payload(key_id="nope")
    p["signature"] = "0" * 64
    trust = ReceiptTrust(keys={"default": ("hmac-sha256", "s")})
    assert verify_receipt_signature(p, trust) is False


def test_algorithm_mismatch_rejected():
    p = _payload(algorithm="ed25519")
    p["signature"] = "0" * 128
    trust = ReceiptTrust(keys={"default": ("hmac-sha256", "s")})
    assert verify_receipt_signature(p, trust) is False


def test_no_pin_rejects_all():
    p = _payload()
    p["signature"] = "anything"
    assert verify_receipt_signature(p, ReceiptTrust(keys={})) is False


def test_ed25519_round_trip():
    pytest = __import__("pytest")
    pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    import binascii
    pub_hex = binascii.hexlify(pub.public_bytes_raw()).decode()
    p = _payload(algorithm="ed25519")
    sig = priv.sign(canonical_receipt_bytes(p)).hex()
    p["signature"] = sig
    trust = ReceiptTrust(keys={"default": ("ed25519", pub_hex)})
    assert verify_receipt_signature(p, trust) is True
    p["signature"] = "0" * 128
    assert verify_receipt_signature(p, trust) is False


# ---------------------------------------------------------------------------
# Conversion: receipts -> verified witnesses + dispositions
# ---------------------------------------------------------------------------

def _signed(secret="s", commit="a" * 40, **kw):
    import hmac as hmac_mod2
    import hashlib as hashlib2
    from verifyci.verification.receipts import canonical_receipt_bytes as _canon
    p = _payload(commit_sha=commit, **kw)
    p["signature"] = hmac_mod2.new(secret.encode(), _canon(p), hashlib2.sha256).hexdigest()
    return p


_TRUST = ReceiptTrust(keys={"default": ("hmac-sha256", "s")})
_COMMIT = "a" * 40


def test_conversion_accepts_valid():
    from verifyci.verification.receipts import witnesses_from_receipts
    ws, disp = witnesses_from_receipts([_signed()], _COMMIT, _TRUST)
    assert disp == ["accepted:r1"]
    assert len(ws) == 1
    w = ws[0]
    assert (w.execution_verified, w.execution_receipt_id, w.target_entity_id,
            w.is_general_regression, w.association_method) == (
            True, "r1", "e_login", False, "ci_receipt")


def test_conversion_rejects_matrix():
    from verifyci.verification.receipts import witnesses_from_receipts
    bad_sig = _signed()
    bad_sig["signature"] = "0" * 64
    cases = [
        (bad_sig, "rejected:r1:receipt_untrusted"),
        (_signed(commit="b" * 40), "rejected:r1:receipt_stale"),
        ({"receipt_id": "r9"}, "rejected:r9:receipt_malformed"),
        (_signed(targets=["src/auth.py"]), "rejected:r1:receipt_malformed"),
    ]
    for payload, want in cases:
        ws, disp = witnesses_from_receipts([payload], _COMMIT, _TRUST)
        assert ws == [] and disp == [want], (payload, disp)


def test_conversion_unresolved_skips_all():
    from verifyci.verification.receipts import witnesses_from_receipts
    ws, disp = witnesses_from_receipts([_signed()], None, _TRUST)
    assert ws == [] and disp == ["skipped:r1:revision_unresolved"]


def test_conversion_dedupes_replay():
    from verifyci.verification.receipts import witnesses_from_receipts
    ws, disp = witnesses_from_receipts([_signed(), _signed()], _COMMIT, _TRUST)
    assert len(ws) == 1
    assert disp == ["accepted:r1", "duplicate:r1"]


def test_conversion_future_dated_rejected():
    from verifyci.verification.receipts import witnesses_from_receipts
    p = _signed(executed_at="2030-01-01T00:00:00Z")
    ws, disp = witnesses_from_receipts(
        [p], _COMMIT, _TRUST, now=1780000000.0)
    assert ws == [] and disp == ["rejected:r1:receipt_time_anomaly"]


def test_conversion_no_pin_untrusted():
    from verifyci.verification.receipts import witnesses_from_receipts
    ws, disp = witnesses_from_receipts([_signed()], _COMMIT, ReceiptTrust(keys={}))
    assert ws == [] and disp == ["rejected:r1:receipt_untrusted"]
