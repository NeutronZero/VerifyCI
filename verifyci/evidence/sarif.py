"""SARIF v2.1.0 projection of the canonical evidence bundle."""

from __future__ import annotations

from typing import Any, Mapping

from verifyci.contracts.model import EvidenceBundle


def _rule_map(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for check in payload.get("manifest", {}).get("checks", []):
        for defect_id in check.get("defect_ids", []):
            rules[defect_id] = {
                "id": defect_id,
                "name": defect_id,
                "shortDescription": {"text": f"{check.get('check_id')} defect"},
                "fullDescription": {"text": check.get("method", "")},
                "properties": {
                    "check_id": check.get("check_id"),
                    "tier": check.get("tier"),
                    "maturity": check.get("maturity"),
                },
            }
    return [rules[key] for key in sorted(rules)]


def _level(finding: Mapping[str, Any], status: str) -> str:
    if finding.get("tier") == "advisory":
        return "note"
    if status == "FAIL":
        return "error"
    if status in ("INCONCLUSIVE", "REVIEW", "ERROR"):
        return "warning"
    return "note"


def bundle_to_sarif(bundle: EvidenceBundle) -> dict[str, Any]:
    payload = bundle.payload
    status = str(payload.get("verdict", {}).get("status", "ERROR"))
    results: list[dict[str, Any]] = []
    for finding in payload.get("findings", []):
        subject = finding.get("subject", {})
        path = str(subject.get("path") or "")
        line = 1
        evidence = finding.get("evidence", {})
        ev_payload = evidence.get("payload", {}) if isinstance(evidence, Mapping) else {}
        if isinstance(ev_payload, Mapping):
            line = int(ev_payload.get("line") or ev_payload.get("start_line") or 1)
        result: dict[str, Any] = {
            "ruleId": finding.get("defect_id"),
            "level": _level(finding, status),
            "message": {"text": finding.get("message", "")},
            "properties": {
                "reason_code": finding.get("reason_code"),
                "fingerprint": finding.get("fingerprint"),
                "disposition": finding.get("disposition"),
                "evidence_kind": evidence.get("kind") if isinstance(evidence, Mapping) else None,
                "premises": finding.get("premises", {}),
            },
        }
        if path:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": max(line, 1)},
                    }
                }
            ]
        results.append(result)

    notifications = []
    for diagnostic in payload.get("diagnostics", []):
        notifications.append(
            {
                "level": "warning",
                "message": {"text": f"{diagnostic.get('code')}: {diagnostic.get('detail') or diagnostic}"},
                "descriptor": {"id": str(diagnostic.get("code") or "diagnostic")},
            }
        )
    for code in payload.get("verdict", {}).get("reason_codes", []):
        if code in {"waiver_review", "coverage_acceptance_review", "policy_change_review", "gate_integrity_review", "target_drift"}:
            notifications.append(
                {
                    "level": "warning",
                    "message": {"text": code},
                    "descriptor": {"id": code},
                }
            )

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "verifyci",
                "version": str(payload.get("tool", {}).get("version", "3.1.10")),
                "informationUri": "https://github.com/verifyci/verifyci",
                "rules": _rule_map(payload),
            }
        },
        "invocations": [
            {
                "executionSuccessful": status != "ERROR",
                "exitCode": int(payload.get("verdict", {}).get("exit_code", 3)),
                "toolExecutionNotifications": notifications,
            }
        ],
        "results": results,
        "properties": {
            "verdict": status,
            "payload_hash": bundle.envelope.get("payload_hash"),
            "reason_codes": payload.get("verdict", {}).get("reason_codes", []),
        },
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


__all__ = ["bundle_to_sarif"]
