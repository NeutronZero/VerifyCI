"""Grounding and policy-prohibited-change checks."""

from __future__ import annotations

from verifyci.checks.base import CheckContext, gap, make_finding, make_result
from verifyci.contracts.model import (
    CheckResult,
    Coverage,
    EvidenceKind,
    Outcome,
    WitnessLevel,
)
from verifyci.contracts.names import path_matches_any, symbol_matches_any


def _fact_for_path(context: CheckContext, path: str):
    return context.scope.head_facts.get(path) or context.scope.base_facts.get(path)


def run(context: CheckContext) -> CheckResult:
    rules = context.policy.deny_changes
    changed_paths = sorted(
        {p for entry in context.entries for p in entry.changed_paths}
    )
    changed_symbols = sorted(context.scope.changed_entities)

    path_matches: dict[str, set[str]] = {}
    symbol_matches: dict[str, set[str]] = {}
    for rule_id, rule in rules.items():
        paths = tuple(rule.get("paths", ()))
        symbols = tuple(rule.get("symbols", ()))
        for path in changed_paths:
            if paths and path_matches_any(paths, path):
                path_matches.setdefault(path, set()).add(rule_id)
        for symbol in changed_symbols:
            if symbols and symbol_matches_any(symbols, symbol):
                symbol_matches.setdefault(symbol, set()).add(rule_id)

    findings = []
    for path, rule_ids in sorted(path_matches.items()):
        entry = next((e for e in context.entries if path in e.changed_paths), None)
        ordered_rules = sorted(rule_ids)
        primary_rule_id = ordered_rules[0]
        is_binary = entry.is_binary if entry else False
        witness_level = WitnessLevel.NONE if is_binary else WitnessLevel.SOURCE
        payload = {
            "primary_rule_id": primary_rule_id,
            "matched_rule_ids": ordered_rules,
            "rule_ids": ordered_rules,
            "matched_subject": path,
            "matched_kind": "path",
            "base_blob": entry.base_blob if entry else None,
            "head_blob": entry.head_blob if entry else None,
        }
        message = (
            f"Changed binary path {path} matches active deny_changes rule {primary_rule_id}"
            if is_binary
            else f"Changed path {path} matches active deny_changes rule {primary_rule_id}"
        )
        findings.append(
            make_finding(
                context=context,
                check_id="grounding",
                defect_id="GRD-UNGROUNDED-EDIT",
                subject={
                    "file": path,
                    "path": path,
                    "kind": "path",
                    "symbol": "",
                    "entity": "",
                },
                premises={
                    "rule_ids": ordered_rules,
                    "rule_reasons": {rule_id: rules[rule_id].get("reason", "") for rule_id in ordered_rules},
                },
                evidence_kind=EvidenceKind.PROVENANCE,
                evidence_payload=payload,
                witness_level=witness_level,
                message=message,
                remediation=(
                    "Remove this change, or obtain code-owner review and update the "
                    "policy through a separate target-branch policy change."
                ),
            )
        )
    for symbol, rule_ids in sorted(symbol_matches.items()):
        entity = context.scope.entity(symbol)
        file_path = entity.file_path if entity else ""
        entry = next((e for e in context.entries if file_path in e.changed_paths), None)
        ordered_rules = sorted(rule_ids)
        primary_rule_id = ordered_rules[0]
        payload = {
            "primary_rule_id": primary_rule_id,
            "matched_rule_ids": ordered_rules,
            "rule_ids": ordered_rules,
            "matched_subject": symbol,
            "matched_kind": "symbol",
            "base_blob": entry.base_blob if entry else None,
            "head_blob": entry.head_blob if entry else None,
        }
        findings.append(
            make_finding(
                context=context,
                check_id="grounding",
                defect_id="GRD-UNGROUNDED-EDIT",
                subject={
                    "file": file_path,
                    "path": file_path,
                    "kind": "symbol",
                    "symbol": symbol,
                    "entity": symbol,
                },
                premises={
                    "rule_ids": ordered_rules,
                    "rule_reasons": {rule_id: rules[rule_id].get("reason", "") for rule_id in ordered_rules},
                },
                evidence_kind=EvidenceKind.PROVENANCE,
                evidence_payload=payload,
                witness_level=WitnessLevel.SOURCE,
                message=f"Changed entity {symbol} matches active deny_changes rule {primary_rule_id}",
                remediation=(
                    "Remove this change, or obtain code-owner review and update the "
                    "policy through a separate target-branch policy change."
                ),
            )
        )

    gaps = []
    for item in context.scope.unmapped_hunks:
        path = str(item.get("path") or item.get("file") or "")
        code = str(item.get("reason_code") or "mapping_unresolved")
        gaps.append(
            gap(
                code,
                {
                    "check_id": "grounding",
                    "path": path,
                    "hunk": item.get("hunk"),
                },
            )
        )

    other_text = [
        dict(h) for h in context.scope.mapped_hunks if h.get("mapped_entity") == "other_text"
    ]

    vendored = context.policy.path_classes.get("vendored", ()) if context.policy.path_classes else ()
    generated = context.policy.path_classes.get("generated", ()) if context.policy.path_classes else ()
    excluded_classes = tuple(vendored) + tuple(generated)
    excluded_paths = [
        p for p in changed_paths
        if path_matches_any(excluded_classes, p)
    ]
    all_excluded = bool(changed_paths and len(excluded_paths) == len(changed_paths))

    if findings:
        outcome = Outcome.FAIL
        coverage = Coverage.COMPLETE
    elif gaps:
        outcome = Outcome.INCONCLUSIVE
        coverage = Coverage.PARTIAL
    elif not context.entries or (all_excluded and not rules):
        outcome = Outcome.NOT_APPLICABLE
        coverage = Coverage.COMPLETE
    else:
        outcome = Outcome.PASS
        coverage = Coverage.COMPLETE

    if outcome == Outcome.NOT_APPLICABLE and all_excluded:
        applicability_evidence = {
            "applicable_deny_rules": [],
            "excluded_paths": sorted(excluded_paths),
        }
    else:
        applicability_evidence = {
            "deny_changes": sorted(rules),
            "changed_entries": len(context.entries),
        }

    return make_result(
        context=context,
        check_id="grounding",
        outcome=outcome,
        coverage=coverage,
        evaluated_scope={
            "paths": changed_paths,
            "symbols": changed_symbols,
            "other_text_hunks": other_text,
            "deny_rule_count": len(rules),
        },
        scope_enumeration={
            "complete": not gaps,
            "unmapped_hunks": len(context.scope.unmapped_hunks),
        },
        candidate_discovery={
            "complete": True,
            "candidate_paths": len(changed_paths),
            "candidate_symbols": len(changed_symbols),
        },
        applicability_evidence=applicability_evidence,
        reason_codes=tuple(sorted({g.reason_code for g in gaps})),
        coverage_gaps=gaps,
        findings=findings,
        diagnostics=(
            [{"code": "rename_limit_exceeded"}] if context.rename_limit_exceeded else []
        ),
    )


__all__ = ["run"]


__all__ = ["run"]
