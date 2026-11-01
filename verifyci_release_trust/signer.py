"""Ed25519 Detached Signature Authority and Envelope Verifier (§15.10 Component S).

Signs RFC 8785 canonical payloads using domain separation:
    "VERIFYCI-RELEASE-EVIDENCE\\0" || JCS(payload)
Prevents cross-protocol signature substitution and binds public key identifier.
"""
from __future__ import annotations

import base64
import os
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from verifyci_release_trust.evidence import canonical_jcs_bytes

SIGNING_DOMAIN_SEPARATOR = b"VERIFYCI-RELEASE-EVIDENCE\0"
DEFAULT_KEY_ID = "verifyci-release-authority-ed25519-v1"
DEFAULT_PUBLIC_KEY_HEX = (
    "7926b9524e2ec893f7834b9081228da255f058709fa158d77a75d7d21a3715f7"
)


def sign_release_payload(
    payload: dict[str, Any],
    private_key_hex: str | None = None,
    key_id: str = DEFAULT_KEY_ID,
) -> dict[str, Any]:
    """Sign canonical JCS payload with Ed25519 and return enveloped record."""
    key_val = private_key_hex or os.environ.get("VERIFYCI_RELEASE_SIGNING_KEY")
    if not key_val:
        raise RuntimeError("VERIFYCI_RELEASE_SIGNING_KEY is missing; cannot sign release evidence")

    priv_bytes = bytes.fromhex(key_val.strip())
    priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    pub_key_hex = priv_key.public_key().public_bytes_raw().hex()

    canonical_data = canonical_jcs_bytes(payload)
    message = SIGNING_DOMAIN_SEPARATOR + canonical_data
    sig_raw = priv_key.sign(message)
    sig_b64 = base64.b64encode(sig_raw).decode("ascii")

    return {
        "schema": "verifyci.release_validation/v3",
        "payload": payload,
        "signature": {
            "algorithm": "Ed25519",
            "key_id": key_id,
            "public_key": pub_key_hex,
            "value": sig_b64,
        },
    }


def verify_release_envelope(
    envelope: dict[str, Any],
    expected_public_key_hex: str = DEFAULT_PUBLIC_KEY_HEX,
    expected_key_id: str = DEFAULT_KEY_ID,
) -> tuple[bool, str | None]:
    """Verify Ed25519 cryptographic signature of a release evidence envelope."""
    if not isinstance(envelope, dict):
        return False, "envelope must be a JSON object"

    schema = envelope.get("schema")
    if schema != "verifyci.release_validation/v3":
        return False, f"unsupported envelope schema: {schema}"

    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return False, "envelope missing valid 'payload' object"

    sig_block = envelope.get("signature")
    if not isinstance(sig_block, dict):
        return False, "envelope missing valid 'signature' block"

    if sig_block.get("algorithm") != "Ed25519":
        return False, f"unsupported signature algorithm: {sig_block.get('algorithm')}"

    if sig_block.get("key_id") != expected_key_id:
        return False, f"key_id mismatch: expected '{expected_key_id}', got '{sig_block.get('key_id')}'"

    pub_hex = sig_block.get("public_key")
    if pub_hex != expected_public_key_hex:
        return False, f"public_key mismatch: expected '{expected_public_key_hex}', got '{pub_hex}'"

    sig_b64 = sig_block.get("value")
    if not isinstance(sig_b64, str):
        return False, "signature value must be a base64 string"

    try:
        sig_raw = base64.b64decode(sig_b64.encode("ascii"))
    except Exception as exc:
        return False, f"failed to decode base64 signature: {exc}"

    try:
        canonical_data = canonical_jcs_bytes(payload)
        message = SIGNING_DOMAIN_SEPARATOR + canonical_data
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub_key.verify(sig_raw, message)
        return True, None
    except Exception as exc:
        return False, f"Ed25519 signature verification failed: {exc}"
