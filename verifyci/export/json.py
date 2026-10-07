"""Stable machine-readable Certificate and Verification Report JSON exporter."""
from __future__ import annotations

import json
from typing import Any

from verifyci.contracts.jsonio import to_json_dict


def _exit_code_for_status(status: str) -> int:
    """Derive CLI exit code from verification status."""
    if status in ("PASS", "COMPLETED"):
        return 0
    if status in ("FAIL", "FAILED"):
        return 1
    if status in ("INFRA_ERROR", "TIMEOUT"):
        return 3
    # HUMAN_REVIEW, INCONCLUSIVE, or other uncertain status
    return 2


def export_certificate_json(verify_result: dict[str, Any]) -> str:
    """Serialize verification result, authoritative Certificate, and Report to stable JSON.

    Parameters
    ----------
    verify_result : dict
        The result dictionary returned by ``run_verify(..., return_artifacts=True)``.

    Returns
    -------
    str
        Formatted JSON string conforming to VerifyCI machine-readable contract.
    """
    status = verify_result.get("status", "INCONCLUSIVE")
    rationale = verify_result.get("rationale", "")
    report_id = verify_result.get("report_id", "")
    revision_id = verify_result.get("revision_id", "")
    files = verify_result.get("files", [])
    changed_entities = verify_result.get("changed_entities", [])

    cert = verify_result.get("certificate")
    report = verify_result.get("report")
    decision = verify_result.get("decision")
    policy = verify_result.get("policy")

    decision_id = getattr(decision, "decision_id", "") if decision else ""
    policy_id = getattr(policy, "policy_id", "default") if policy else "default"
    timestamp = getattr(decision, "timestamp", None) if decision else None

    # Construct the canonical machine-readable document
    payload = {
        "$schema": "https://verifyci.org/schemas/v1/certificate-report.json",
        "version": "1.0",
        "verdict": {
            "status": status,
            "rationale": rationale,
            "report_id": report_id,
            "decision_id": decision_id,
            "policy_id": policy_id,
            "exit_code": _exit_code_for_status(status),
            "timestamp": timestamp,
        },
        "provenance": {
            "revision_id": revision_id,
            "files": sorted(files) if files else [],
            "changed_entities": sorted(changed_entities) if changed_entities else [],
            "reproducible": True,
        },
        "policy": to_json_dict(policy) if policy is not None else None,
        "certificate": to_json_dict(cert) if cert is not None else None,
        "report": to_json_dict(report) if report is not None else None,
        "infra_error": verify_result.get("infra_error") or verify_result.get("error"),
    }

    if "contract" in verify_result:
        payload["verdict"]["contract"] = verify_result["contract"]

    return json.dumps(payload, indent=2, ensure_ascii=False)
