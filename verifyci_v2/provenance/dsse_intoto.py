from __future__ import annotations

import base64
from dataclasses import asdict
import hmac
from typing import Any, Sequence

from verifyci_v2.contracts.attestation import (
    DSSEEnvelope,
    DSSESignature,
    InTotoVerificationPredicate,
    VerificationFinding,
)
from verifyci_v2.contracts.canonical import (
    blake3_bytes,
    blake3_hex,
    canonical_jcs_bytes,
)

INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"


def dsse_pae(payload_type: str, payload_bytes: bytes) -> bytes:
    """
    Computes the Dead Simple Signing Envelope (DSSE v1.0) Pre-Authentication Encoding:
    PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
    """
    pt_bytes = payload_type.encode("utf-8")
    header = f"DSSEv1 {len(pt_bytes)} ".encode("utf-8") + pt_bytes + f" {len(payload_bytes)} ".encode("utf-8")
    return header + payload_bytes


class InTotoDSSESigner:
    """
    Layer 7 Cryptographic Attestation Signer (`verifyci_v2/provenance/dsse_intoto.py`).
    Serializes `InTotoVerificationPredicate` via RFC 8785 JCS and signs the DSSE v1.0 PAE.
    """

    def __init__(self, signing_key: str | bytes = "verifyci-v2-default-ed25519-seed") -> None:
        self._key_bytes = (
            signing_key.encode("utf-8") if isinstance(signing_key, str) else bytes(signing_key)
        )
        self.keyid = blake3_hex(self._key_bytes, domain="verifyci.v2.dsse.keyid")[:16]

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
            "predicate": asdict(predicate),
        }
        raw_payload = canonical_jcs_bytes(statement)
        pae_bytes = dsse_pae(INTOTO_PAYLOAD_TYPE, raw_payload)
        sig_bytes = hmac.new(
            blake3_bytes(self._key_bytes, domain="verifyci.v2.dsse.key"),
            pae_bytes,
            digestmod="sha256",
        ).digest()

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

    def verify_envelope(self, envelope: DSSEEnvelope) -> bool:
        try:
            raw_payload = base64.b64decode(envelope.payload.encode("ascii"), validate=True)
        except Exception:
            return False
        pae_bytes = dsse_pae(envelope.payloadType, raw_payload)
        expected_sig = hmac.new(
            blake3_bytes(self._key_bytes, domain="verifyci.v2.dsse.key"),
            pae_bytes,
            digestmod="sha256",
        ).digest()
        expected_b64 = base64.b64encode(expected_sig).decode("ascii")
        return any(
            s.keyid == self.keyid and hmac.compare_digest(s.sig, expected_b64)
            for s in envelope.signatures
        )


def export_sarif_v2(
    findings: Sequence[VerificationFinding],
    *,
    ussa_merkle_root: str,
    rsl_entry_hash: str,
) -> dict[str, Any]:
    """Exports findings, Z3 counterexample witnesses, and verified CEGIS fixes to SARIF v2.1.0."""
    results: list[dict[str, Any]] = []
    for f in findings:
        level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        sarif_fixes = [
            {
                "description": {"text": "Z3-verified UNSAT auto-repair synthesized by VerifyCI v2 CEGIS"},
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
                "witness": asdict(f.witness) if f.witness else None,
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