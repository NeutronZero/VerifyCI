"""In-Toto DSSE Ed25519 cryptographic signing and verification adapter."""

from __future__ import annotations

import base64
import hashlib
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


def pae_encode(payload_type: str, payload_bytes: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (PAE) according to DSSE specification."""
    return (
        f"DSSEv1 {len(payload_type)} {payload_type} {len(payload_bytes)} ".encode("utf-8")
        + payload_bytes
    )


class InTotoDSSEAdapter:
    """Asymmetric Ed25519 DSSE attestation signer and verifier."""

    def __init__(
        self,
        private_key: ed25519.Ed25519PrivateKey | None = None,
    ) -> None:
        self.private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    @classmethod
    def generate_ephemeral(cls) -> tuple[InTotoDSSEAdapter, bytes]:
        """Generate ephemeral signer and return (adapter, public_key_bytes)."""
        signer = cls()
        pub_bytes = signer.public_key.public_bytes_raw()
        return signer, pub_bytes

    def sign_payload(
        self,
        payload_bytes: bytes,
        payload_type: str = "application/vnd.in-toto+json",
    ) -> dict[str, Any]:
        """Sign canonical payload bytes and produce standard DSSE envelope."""
        pae = pae_encode(payload_type, payload_bytes)
        signature = self.private_key.sign(pae)

        pub_bytes = self.public_key.public_bytes_raw()
        key_id = hashlib.sha256(pub_bytes).hexdigest()[:16]

        return {
            "payloadType": payload_type,
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "signatures": [
                {
                    "keyid": key_id,
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        }

    @staticmethod
    def verify_envelope(
        envelope: Mapping[str, Any],
        public_key_bytes: bytes,
    ) -> bool:
        """Verify DSSE envelope signature against public key, detecting any tampering."""
        payload_type = envelope.get("payloadType", "")
        b64_payload = envelope.get("payload", "")
        signatures = envelope.get("signatures", [])

        if not payload_type or not b64_payload or not signatures:
            return False

        try:
            payload_bytes = base64.b64decode(b64_payload)
            pae = pae_encode(payload_type, payload_bytes)
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

            for sig_entry in signatures:
                sig_bytes = base64.b64decode(sig_entry.get("sig", ""))
                pub_key.verify(sig_bytes, pae)
            return True
        except (InvalidSignature, ValueError, KeyError):
            return False
