"""OASIS SARIF v2.1.0 Exporter for VerifyCI.

Converts VerifyCI verification results, certificates, and check reports into
standard Static Analysis Results Interchange Format (SARIF) documents.
Preserves the honest semantic distinction between:
- Verification FAIL: error / fail
- Human Review: warning / review
- Inconclusive: note / open
- Infrastructure error: executionSuccessful=false, infrastructure alert
- Operational timeout: executionSuccessful=false, timeout alert
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

_DEFAULT_RULES: dict[str, dict[str, Any]] = {
    "semi_formal": {
        "name": "CPGGroundingAndEntityCoverage",
        "shortDescription": {"text": "Verifies that changed lines ground into code entity spans and execution traces."},
        "fullDescription": {"text": "Code-property graph grounding ensures that every diff line lands within recognized AST entities and valid control-flow traces without ungrounded stray edits."},
        "defaultConfiguration": {"level": "error"},
        "help": {"text": "Ensure that modified files are indexed in VerifyCI and that edits land within function or class declarations."},
    },
    "blast_radius": {
        "name": "ImpactBlastRadiusCheck",
        "shortDescription": {"text": "Evaluates dependency impact, affected callers, and test coverage gaps."},
        "fullDescription": {"text": "Traverses the call-graph to identify affected callers and callees, checking whether risk score exceeds safety thresholds."},
        "defaultConfiguration": {"level": "error"},
        "help": {"text": "Add test coverage for high-risk callers or reduce changes in core dependency paths."},
    },
    "removal_provenance": {
        "name": "RemovalProvenanceIntegrity",
        "shortDescription": {"text": "Verifies that removed lines match stored base revision code snippets."},
        "fullDescription": {"text": "Prevents fabricated or stale deletions where an agent removes lines that did not exist in the base revision."},
        "defaultConfiguration": {"level": "error"},
        "help": {"text": "Verify that your patch is based on the latest base revision."},
    },
    "return_statement": {
        "name": "ReturnStatementIntegrity",
        "shortDescription": {"text": "Detects invalid return statements or dangerous control flow alterations."},
        "fullDescription": {"text": "Validates return statement semantics across modified functions."},
        "defaultConfiguration": {"level": "error"},
    },
    "call_target": {
        "name": "CallTargetResolution",
        "shortDescription": {"text": "Verifies that modified call targets resolve to valid functions or methods."},
        "fullDescription": {"text": "Ensures that newly called methods or functions exist in the repository or imported modules."},
        "defaultConfiguration": {"level": "error"},
    },
    "call_semantics": {
        "name": "CallSemanticsCompatibility",
        "shortDescription": {"text": "Verifies caller/callee argument count and signature compatibility."},
        "fullDescription": {"text": "Detects parameter count mismatches or invalid keyword arguments in function calls."},
        "defaultConfiguration": {"level": "error"},
    },
    "guard_condition": {
        "name": "GuardConditionIntegrity",
        "shortDescription": {"text": "Detects unauthorized removal or inversion of security/validation guards."},
        "fullDescription": {"text": "Fail-closed check ensuring defensive checks, bounds checks, or auth assertions are not deleted or inverted."},
        "defaultConfiguration": {"level": "error"},
    },
    "import_resolution": {
        "name": "ImportResolutionIntegrity",
        "shortDescription": {"text": "Verifies that added or modified imports resolve within repository scope."},
        "fullDescription": {"text": "Ensures imported symbols exist and do not introduce unresolvable cycles or missing dependencies."},
        "defaultConfiguration": {"level": "error"},
    },
    "secrets_scan": {
        "name": "HardcodedSecretDetected",
        "shortDescription": {"text": "Detects hardcoded credentials, API keys, tokens, or private keys."},
        "fullDescription": {"text": "Deterministic entropy and pattern scanner detecting secrets in added diff lines."},
        "defaultConfiguration": {"level": "error"},
    },
    "provenance_check": {
        "name": "EvidenceProvenanceRequirement",
        "shortDescription": {"text": "Requires non-empty evidence citations and entity grounding for verified code paths."},
        "fullDescription": {"text": "Ensures that verified assertions are backed by non-empty evidence citations and stored entity provenance."},
        "defaultConfiguration": {"level": "warning"},
    },
    "unverified_policy_change": {
        "name": "UnverifiedPolicyChange",
        "shortDescription": {"text": "Detects modifications to gate configuration and invariants in diff."},
        "fullDescription": {"text": "Modifications to .verifyci/invariants.yaml or waivers require human review and cannot pass automatically."},
        "defaultConfiguration": {"level": "warning"},
    },
    "storage_unavailable": {
        "name": "StorageSubstrateUnavailable",
        "shortDescription": {"text": "VerifyCI graph database or revision substrate is unavailable or corrupt."},
        "fullDescription": {"text": "Reports infrastructure failures preventing deterministic verification from completing."},
        "defaultConfiguration": {"level": "error"},
    },
    "verification_timeout": {
        "name": "VerificationTimeout",
        "shortDescription": {"text": "Verification task exceeded maximum allocated execution time."},
        "fullDescription": {"text": "The verification pipeline timed out before all scheduled checks could conclude."},
        "defaultConfiguration": {"level": "error"},
    },
}


def _normalize_uri(path: str) -> str:
    """Normalize file path for SARIF URI."""
    return path.replace("\\", "/").lstrip("/")


def _parse_location_string(loc_str: str) -> tuple[str, int | None, int | None]:
    """Parse locations formatted like 'path:line', 'path:start-end', or 'path:line:pattern'."""
    parts = loc_str.split(":")
    if len(parts) >= 2:
        path = parts[0]
        line_part = parts[1]
        if "-" in line_part:
            start_s, end_s = line_part.split("-", 1)
            try:
                return path, int(start_s), int(end_s)
            except ValueError:
                pass
        else:
            try:
                line_no = int(line_part)
                return path, line_no, None
            except ValueError:
                pass
    return loc_str, None, None


def _build_physical_location(file_path: str, start_line: int | None = None, end_line: int | None = None) -> dict[str, Any]:
    artifact_loc = {
        "uri": _normalize_uri(file_path),
        "uriBaseId": "%SRCROOT%",
    }
    loc: dict[str, Any] = {
        "artifactLocation": artifact_loc,
    }
    if start_line is not None and start_line >= 1:
        region: dict[str, Any] = {"startLine": start_line}
        if end_line is not None and end_line >= start_line:
            region["endLine"] = end_line
        loc["region"] = region
    return {"physicalLocation": loc}


def export_sarif(verify_result: dict[str, Any]) -> str:
    """Export a VerifyCI verification result as a SARIF v2.1.0 document.

    Parameters
    ----------
    verify_result : dict
        Result returned by ``run_verify(..., return_artifacts=True)``.

    Returns
    -------
    str
        Formatted JSON string conforming to the OASIS SARIF v2.1.0 schema.
    """
    status = verify_result.get("status", "INCONCLUSIVE")
    rationale = verify_result.get("rationale", "")
    report_id = verify_result.get("report_id", "")
    revision_id = verify_result.get("revision_id", "")
    files = verify_result.get("files", [])
    infra_error = verify_result.get("infra_error") or verify_result.get("error")

    report = verify_result.get("report")

    rules_dict: dict[str, dict[str, Any]] = dict(_DEFAULT_RULES)
    results: list[dict[str, Any]] = []

    def ensure_rule(rule_id: str) -> None:
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "name": re.sub(r"[^A-Za-z0-9]", "", rule_id.title()) or "CustomRule",
                "shortDescription": {"text": f"Verification rule: {rule_id}"},
                "fullDescription": {"text": f"Enforces deterministic invariant or check {rule_id}."},
                "defaultConfiguration": {"level": "error"},
            }

    # 1. Handle Infrastructure Failure
    if status == "INFRA_ERROR":
        ensure_rule("storage_unavailable")
        msg = f"Infrastructure substrate failure: {rationale or infra_error or 'database unavailable'}"
        results.append({
            "ruleId": "storage_unavailable",
            "level": "error",
            "kind": "fail",
            "message": {"text": msg},
            "locations": [],
            "properties": {
                "verdict": "INFRA_ERROR",
                "rationale": rationale,
                "infra_error": infra_error,
            },
        })

    # 2. Handle Timeout
    elif status == "TIMEOUT":
        ensure_rule("verification_timeout")
        msg = f"Verification timed out: {rationale or 'task exceeded deadline'}"
        results.append({
            "ruleId": "verification_timeout",
            "level": "error",
            "kind": "fail",
            "message": {"text": msg},
            "locations": [],
            "properties": {
                "verdict": "TIMEOUT",
                "rationale": rationale,
            },
        })

    # 3. Handle Gate Policy Modification in Diff
    elif status == "HUMAN_REVIEW" and "unverified_policy_change" in rationale:
        ensure_rule("unverified_policy_change")
        policy_files = [f for f in files if "invariants" in f or "waivers" in f or ".verifyci" in f]
        locations = [_build_physical_location(f) for f in policy_files] if policy_files else []
        results.append({
            "ruleId": "unverified_policy_change",
            "level": "warning",
            "kind": "review",
            "message": {"text": rationale},
            "locations": locations,
            "properties": {
                "verdict": "HUMAN_REVIEW",
                "rationale": rationale,
            },
        })

    # 4. Check results from the VerificationReport
    if report and hasattr(report, "checks"):
        for check in report.checks:
            if check.passed:
                continue

            # Determine rule ID
            cid = check.check_id
            expl = getattr(check, "explanation", "") or ""
            if expl.startswith("invariant_"):
                m = re.match(r"^invariant_([a-zA-Z0-9_:.-]+)_(?:passed|failed)", expl)
                if m:
                    raw_rule = m.group(1)
                else:
                    raw_rule = cid
            elif cid.startswith("invariant_"):
                raw_rule = cid[len("invariant_"):]
            else:
                raw_rule = cid

            if raw_rule.startswith("forbid_call:"):
                rule_id = "forbid_call"
            elif raw_rule.startswith("forbid_import:"):
                rule_id = "forbid_import"
            elif raw_rule.startswith("check_call:"):
                rule_id = "call_target"
            else:
                rule_id = raw_rule

            ensure_rule(rule_id)

            # Determine SARIF Level and Kind
            is_established = getattr(check, "established", True)
            is_blocking = getattr(check, "blocking", True)

            if not is_established:
                # Inability / uncertainty -> note / open
                level = "note"
                kind = "open"
            elif is_blocking:
                # Rejection / failure -> error / fail
                level = "error"
                kind = "fail"
            else:
                # Non-blocking warning -> warning / review
                level = "warning"
                kind = "review"

            # Parse locations from check evidence
            locs: list[dict[str, Any]] = []
            for ev_item in getattr(check, "evidence", []):
                if isinstance(ev_item, str):
                    path, start, end = _parse_location_string(ev_item)
                    locs.append(_build_physical_location(path, start, end))

            # Fallback to touched files if no specific evidence line
            if not locs and files:
                locs = [_build_physical_location(f) for f in sorted(files)[:5]]

            # Fingerprint calculation for alert tracking
            fp_src = f"{rule_id}:{check.explanation}:{sorted(getattr(check, 'evidence', []))}"
            fingerprint = hashlib.sha256(fp_src.encode("utf-8")).hexdigest()

            results.append({
                "ruleId": rule_id,
                "level": level,
                "kind": kind,
                "message": {"text": check.explanation or f"Check {rule_id} did not pass."},
                "locations": locs,
                "partialFingerprints": {
                    "primaryLocationLineHash": fingerprint[:16],
                },
                "properties": {
                    "checkId": check.check_id,
                    "blocking": is_blocking,
                    "established": is_established,
                    "deterministic": getattr(check, "deterministic", True),
                    "verdict": status,
                },
            })

    # Prepare Artifacts list
    artifacts = [
        {"location": {"uri": _normalize_uri(f), "uriBaseId": "%SRCROOT%"}}
        for f in sorted(files)
    ]

    # Invocations record
    is_exec_successful = status not in ("INFRA_ERROR", "TIMEOUT") and infra_error is None
    invocation = {
        "executionSuccessful": is_exec_successful,
        "properties": {
            "verdict": status,
            "rationale": rationale,
            "reportId": report_id,
            "revisionId": revision_id,
        },
    }

    rules_list = [
        {"id": rid, **rdata}
        for rid, rdata in sorted(rules_dict.items(), key=lambda x: x[0])
    ]

    sarif_doc = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VerifyCI",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/NeutronZero/VerifyCI",
                        "rules": rules_list,
                    }
                },
                "artifacts": artifacts,
                "results": results,
                "invocations": [invocation],
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2, ensure_ascii=False)
