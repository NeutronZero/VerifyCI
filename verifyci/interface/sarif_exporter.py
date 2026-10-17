"""OASIS SARIF v2.1.0 exporter for VerifyCI certificates."""

from __future__ import annotations

from typing import Any, Mapping

from verifyci import __version__
from verifyci.contracts.attestation import VerificationCertificate
from verifyci.contracts.verdict import Severity, VerificationVerdict


def _sarif_level(severity: Severity, verdict: VerificationVerdict) -> str:
    if verdict == VerificationVerdict.FAIL:
        return "error"
    elif verdict == VerificationVerdict.INCONCLUSIVE:
        return "warning"
    return "note"


def certificate_to_sarif(cert: VerificationCertificate) -> dict[str, Any]:
    """Convert a VerificationCertificate into an OASIS SARIF v2.1.0 compliant document."""
    rules_dict: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for finding in cert.payload.findings:
        rule_id = finding.rule_id
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", "_").lower(),
                "shortDescription": {"text": finding.reason.value},
                "defaultConfiguration": {
                    "level": _sarif_level(finding.severity, finding.verdict)
                },
            }

        level = _sarif_level(finding.severity, finding.verdict)
        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file_path},
                "region": {
                    "startLine": max(1, finding.start_line),
                    "endLine": max(1, finding.end_line),
                },
            }
        }

        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": finding.message},
                "locations": [location],
                "properties": {
                    "findingId": finding.finding_id,
                    "reason": finding.reason.value,
                    "verdict": finding.verdict.value,
                    "details": dict(finding.details),
                },
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VerifyCI",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/NeutronZero/VerifyCI",
                        "rules": list(rules_dict.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "verdict": cert.verdict.value,
                            "attestationDigest": cert.digest,
                            "rationale": cert.rationale,
                        },
                    }
                ],
                "results": sarif_results,
            }
        ],
    }
