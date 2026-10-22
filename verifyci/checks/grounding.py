"""Grounding and policy-prohibited-change checks."""

from __future__ import annotations


from verifyci.checks.base import CheckContext, gap, make_finding, make_result
from verifyci.contracts.model import (
    CheckResult,
    Coverage,
    EvidenceKind,
    Outcome,
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
        payload = {
            "identity": {
                "rule_ids": ordered_rules,
                "path": path,
                "base_blob": entry.base_blob if entry else None,
                "head_blob": entry.head_blob if entry else None,
                "hunks": [h.to_dict() for h in (entry.hunks if entry else ())],
            },
            "rule_ids": ordered_rules,
            "rule_reasons": {rule_id: rules[rule_id].get("reason", "") for rule_id in ordered_rules},
            "path": path,
            "base_blob": entry.base_blob if entry else None,
            "head_blob": entry.head_blob if entry else None,
            "hunks": [h.to_dict() for h in (entry.hunks if entry else ())],
        }
        findings.append(
            make_finding(
                context=context,
                check_id="grounding",
                defect_id="GRD-UNGROUNDED-EDIT",
                subject={
                    "path": path,
                    "symbol": "",
                    "hunk": (entry.hunks[0].to_dict() if entry and entry.hunks else None),
                },
                premises={
                    "rule_ids": ordered_rules,
                    "rule_reasons": payload["rule_reasons"],
                },
                evidence_kind=EvidenceKind.PROVENANCE,
                evidence_payload=payload,
                message=(
                    f"change to {path} is prohibited by deny_changes."
                    + ", deny_changes.".join(ordered_rules)
                ),
                remediation=(
                    "Remove this change, or obtain code-owner review and update the "
                    "policy through a separate target-branch policy change."
                ),
            )
        )
    for symbol, rule_ids in sorted(symbol_matches.items()):
        entity = context.scope.entity(symbol)
        ordered_rules = sorted(rule_ids)
        payload = {
            "identity": {"rule_ids": ordered_rules, "symbol": symbol},
            "rule_ids": ordered_rules,
            "rule_reasons": {rule_id: rules[rule_id].get("reason", "") for rule_id in ordered_rules},
            "symbol": symbol,
            "path": entity.file_path if entity else "",
            "blob": None,
        }
        findings.append(
            make_finding(
                context=context,
                check_id="grounding",
                defect_id="GRD-UNGROUNDED-EDIT",
                subject={
                    "path": entity.file_path if entity else "",
                    "symbol": symbol,
                    "hunk": None,
                },
                premises={
                    "rule_ids": ordered_rules,
                    "rule_reasons": payload["rule_reasons"],
                },
                evidence_kind=EvidenceKind.PROVENANCE,
                evidence_payload=payload,
                message=(
                    f"change to symbol {symbol} is prohibited by deny_changes."
                    + ", deny_changes.".join(ordered_rules)
                ),
                remediation=(
                    "Remove this change, or obtain code-owner review and update the "
                    "policy through a separate target-branch policy change."
                ),
            )
        )

    gaps = []
    other_text: list[dict[str, object]] = []
    symbol_rules = any(rule.get("symbols") for rule in rules.values())
    if symbol_rules:
        for item in context.scope.unmapped_hunks:
            path = str(item.get("path") or "")
            facts = _fact_for_path(context, path)
            if (
                facts is not None
                and facts.supported
                and facts.language in {"python", "typescript", "javascript"}
            ):
                # Module-level and other non-entity edits are still grounded as
                # other_text with hunk provenance; they are not symbol edits.
                other_text.append(dict(item))
            elif facts is not None and not facts.supported:
                gaps.append(
                    gap(
                        "unsupported_language",
                        {
                            "check_id": "grounding",
                            "path": path,
                            "language": facts.language,
                            "parse_error": facts.parse_error,
                        },
                    )
                )

    if findings:
        outcome = Outcome.FAIL
    elif gaps:
        outcome = Outcome.INCONCLUSIVE
    elif not context.entries:
        outcome = Outcome.NOT_APPLICABLE
    else:
        outcome = Outcome.PASS
    coverage = Coverage.COMPLETE if not gaps else Coverage.PARTIAL
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
            "unmapped_hunks": len(context.scope.unmapped_hunks) if symbol_rules else 0,
        },
        candidate_discovery={
            "complete": True,
            "candidate_paths": len(changed_paths),
            "candidate_symbols": len(changed_symbols),
        },
        applicability_evidence={
            "deny_changes": sorted(rules),
            "changed_entries": len(context.entries),
        },
        reason_codes=tuple(sorted({g.reason_code for g in gaps})),
        coverage_gaps=gaps,
        findings=findings,
        diagnostics=(
            [{"code": "rename_limit_exceeded"}] if context.rename_limit_exceeded else []
        ),
    )


__all__ = ["run"]
