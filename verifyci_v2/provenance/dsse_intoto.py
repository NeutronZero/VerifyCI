from __future__ import annotations

import base64
import msgspec
from typing import Any, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from verifyci_v2.contracts.attestation import (
    DSSEEnvelope,
    DSSESignature,
    InTotoVerificationPredicate,
    VerificationFinding,
)
from verifyci_v2.contracts.canonical import (
    blake3_hex,
    canonical_jcs_bytes,
)

INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def dsse_pae(payload_type: str, payload_bytes: bytes) -> bytes:
    """Delegates PAE to securesystemslib (the reference DSSE v1.0 implementation) when available.
    Falls back to the standard-conformant PAE byte formula if securesystemslib is not installed."""
    try:
        from securesystemslib.dsse import Envelope

        if isinstance(payload_type, bytes):
            payload_type = payload_type.decode("utf-8")
        return Envelope(payload_bytes, payload_type, signatures={}).pae()
    except ImportError:
        pt_bytes = (
            payload_type.encode("utf-8")
            if isinstance(payload_type, str)
            else payload_type
        )
        header = (
            f"DSSEv1 {len(pt_bytes)} ".encode("utf-8")
            + pt_bytes
            + f" {len(payload_bytes)} ".encode("utf-8")
        )
        return header + payload_bytes


class InTotoDSSESigner:
    """
    Layer 7 Cryptographic Attestation Signer (`verifyci_v2/provenance/dsse_intoto.py`).
    Uses Ed25519 asymmetric cryptography to sign the DSSE v1.0 PAE encoding.
    Requires an explicit Ed25519PrivateKey (no hardcoded secret defaults).
    """

    def __init__(self, signing_key: Ed25519PrivateKey | None = None) -> None:
        if signing_key is None or not isinstance(signing_key, Ed25519PrivateKey):
            raise TypeError(
                "InTotoDSSESigner requires an explicit cryptography Ed25519PrivateKey instance"
            )
        self._private_key = signing_key
        pub_bytes = self._private_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        self.keyid = blake3_hex(pub_bytes, domain="verifyci.v2.dsse.keyid")[:16]

    @classmethod
    def generate_ephemeral(cls) -> tuple[InTotoDSSESigner, Ed25519PublicKey]:
        """Generates an ephemeral Ed25519 keypair for stateless CI attestation signing."""
        priv = Ed25519PrivateKey.generate()
        return cls(signing_key=priv), priv.public_key()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def sign_predicate(self, predicate: InTotoVerificationPredicate) -> DSSEEnvelope:
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": predicate.repo_id,
                    "digest": {
                        "gitCommit": predicate.head_commit_sha,
                        "ussaMerkleRoot": predicate.ussa_merkle_root,
                    },
                }
            ],
            "predicateType": "https://verifyci.dev/attestations/verification/v2",
            "predicate": msgspec.to_builtins(predicate),
        }
        raw_payload = canonical_jcs_bytes(statement)
        pae_bytes = dsse_pae(INTOTO_PAYLOAD_TYPE, raw_payload)
        sig_bytes = self._private_key.sign(pae_bytes)

        return DSSEEnvelope(
            payloadType=INTOTO_PAYLOAD_TYPE,
            payload=base64.b64encode(raw_payload).decode("ascii"),
            signatures=(
                DSSESignature(
                    keyid=self.keyid,
                    sig=base64.b64encode(sig_bytes).decode("ascii"),
                ),
            ),
        )

    def verify_envelope(
        self,
        envelope: DSSEEnvelope,
        public_key: Ed25519PublicKey | None = None,
    ) -> bool:
        verifying_key = public_key or self.public_key
        try:
            raw_payload = base64.b64decode(
                envelope.payload.encode("ascii"), validate=True
            )
            pae_bytes = dsse_pae(envelope.payloadType, raw_payload)
            for s in envelope.signatures:
                sig_bytes = base64.b64decode(s.sig.encode("ascii"), validate=True)
                verifying_key.verify(sig_bytes, pae_bytes)
                return True
        except (InvalidSignature, Exception):
            return False
        return False


def export_sarif_v2(
    findings: Sequence[VerificationFinding],
    *,
    ussa_merkle_root: str,
    rsl_entry_hash: str,
) -> dict[str, Any]:
    """Exports findings, Z3 counterexample witnesses, and verified CEGIS fixes to SARIF v2.1.0."""
    results: list[dict[str, Any]] = []
    for f in findings:
        level_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
        }
        sarif_fixes = [
            {
                "description": {
                    "text": "Z3-verified UNSAT auto-repair synthesized by VerifyCI v2 CEGIS"
                },
                "artifactChanges": [
                    {
                        "artifactLocation": {"uri": fix.file_path},
                        "replacements": [
                            {
                                "deletedRegion": {
                                    "startLine": fix.start_line,
                                    "endLine": fix.end_line,
                                },
                                "insertedContent": {"text": fix.replacement_text},
                            }
                        ],
                    }
                ],
            }
            for fix in f.fixes
            if fix.z3_verified_unsat
        ]

        res_item: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": level_map.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": {"startLine": f.start_line, "endLine": f.end_line},
                    }
                }
            ],
            "properties": {
                "finding_id": f.finding_id,
                "verdict": f.verdict,
                "witness": msgspec.to_builtins(f.witness) if f.witness else None,
            },
        }
        if sarif_fixes:
            res_item["fixes"] = sarif_fixes
        results.append(res_item)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VerifyCI v2.0 Neuro-Symbolic Engine",
                        "semanticVersion": "2.0.0",
                    }
                },
                "properties": {
                    "ussa_merkle_root": ussa_merkle_root,
                    "gittuf_rsl_entry_hash": rsl_entry_hash,
                },
                "results": results,
            }
        ],
    }
