"""SARIF v2.1.0 projection of the canonical evidence bundle."""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import quote

from verifyci.contracts.manifest import TOOL_VERSION
from verifyci.contracts.model import EvidenceBundle


_LINE_KEYS = ("line", "start_line")


def _line_from(value: Any) -> int | None:
    if isinstance(value, Mapping):
        for key in _LINE_KEYS:
            candidate = value.get(key)
            if isinstance(candidate, int) and candidate > 0:
                return candidate
    return None


def _finding_line(finding: Mapping[str, Any], ev_payload: Mapping[str, Any]) -> tuple[int, bool]:
    """Locate the finding's source line; return (line, defaulted)."""
    subject = finding.get("subject") or {}
    candidates: list[Any] = [subject.get("head_span"), subject, ev_payload]
    for key in ("span", "reference", "call", "source", "sink", "removed", "identity"):
        nested = ev_payload.get(key)
        candidates.append(nested)
        if isinstance(nested, Mapping):
            candidates.append(nested.get("span"))
    for candidate in candidates:
        line = _line_from(candidate)
        if line is not None:
            return line, False
    return 1, True


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
    notifications = []
    results: list[dict[str, Any]] = []
    for finding in payload.get("findings", []):
        subject = finding.get("subject", {})
        path = str(subject.get("path") or "")
        evidence = finding.get("evidence", {})
        ev_payload: Mapping[str, Any] = (
            evidence.get("payload", {}) if isinstance(evidence, Mapping) else {}
        )
        if not isinstance(ev_payload, Mapping):
            ev_payload = {}
        line, defaulted = _finding_line(finding, ev_payload)
        if defaulted:
            notifications.append(
                {
                    "level": "note",
                    "message": {"text": f"finding line defaulted to 1 for {finding.get('defect_id')}"},
                    "descriptor": {"id": "line_defaulted"},
                }
            )
        fingerprint = finding.get("fingerprint")
        result: dict[str, Any] = {
            "ruleId": finding.get("defect_id"),
            "level": _level(finding, status),
            "message": {"text": finding.get("message", "")},
            "properties": {
                "reason_code": finding.get("reason_code"),
                "fingerprint": fingerprint,
                "disposition": finding.get("disposition"),
                "evidence_kind": evidence.get("kind") if isinstance(evidence, Mapping) else None,
                "premises": finding.get("premises", {}),
            },
        }
        if fingerprint:
            result["partialFingerprints"] = {"verifyciFingerprint/v1": str(fingerprint)}
        if path:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": quote(path, safe="/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": max(line, 1)},
                    }
                }
            ]
        results.append(result)

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
                "version": str(payload.get("tool", {}).get("version", TOOL_VERSION)),
                "informationUri": "https://github.com/NeutronZero/VerifyCI",
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
            "payload_hash_verified": bundle.verify_payload_hash(),
            "reason_codes": payload.get("verdict", {}).get("reason_codes", []),
        },
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


__all__ = ["bundle_to_sarif"]
