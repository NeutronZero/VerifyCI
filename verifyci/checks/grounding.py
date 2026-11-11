"""Grounding and policy-prohibited-change checks."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from verifyci.checks.base import (
    CheckContext,
    budget_exhausted_result,
    check_deadline,
    entity_budget_exceeded,
    gap,
    make_finding,
    make_result,
)
from verifyci.contracts.model import (
    CheckResult,
    Coverage,
    EvidenceKind,
    Finding,
    Outcome,
    WitnessLevel,
)
from verifyci.contracts.names import path_matches_any, symbol_matches_any


def _make_grounding_finding(
    context: CheckContext,
    *,
    rule_ids: Sequence[str],
    rules: Mapping[str, Mapping[str, Any]],
    file_path: str,
    symbol: str,
    kind: str,
    entry: Any,
    witness_level: WitnessLevel,
    message: str,
    extra_payload: Mapping[str, Any] = (),
) -> Finding:
    ordered_rules = sorted(rule_ids)
    primary_rule_id = ordered_rules[0]
    payload: dict[str, Any] = {
        "primary_rule_id": primary_rule_id,
        "matched_rule_ids": ordered_rules,
        "rule_ids": ordered_rules,
        "matched_subject": symbol if kind == "symbol" else file_path,
        "matched_kind": kind,
        "base_blob": entry.base_blob if entry else None,
        "head_blob": entry.head_blob if entry else None,
        **dict(extra_payload),
    }
    return make_finding(
        context=context,
        check_id="grounding",
        defect_id="GRD-UNGROUNDED-EDIT",
        subject={
            "file": file_path,
            "path": file_path,
            "kind": kind,
            "symbol": symbol,
            "entity": symbol,
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


def run(context: CheckContext) -> CheckResult:
    if expired := check_deadline(context, "grounding"):
        return expired

    exceeded, enumerated = entity_budget_exceeded(context)
    if exceeded:
        budget = getattr(context, "budget", None)
        max_entities = getattr(budget, "max_entities", 0) if budget is not None else 0
        return budget_exhausted_result(
            context, "grounding", f"max_entities limit exceeded ({enumerated} > {max_entities})"
        )
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

    entries_by_changed_path: dict[str, Any] = {
        p: e for e in context.entries for p in e.changed_paths
    }
    findings = []
    for path, rule_ids in sorted(path_matches.items()):
        if expired := check_deadline(context, "grounding"):
            return expired
        entry = entries_by_changed_path.get(path)
        primary_rule_id = min(rule_ids)
        is_binary = entry.is_binary if entry else False
        witness_level = WitnessLevel.NONE if is_binary else WitnessLevel.SOURCE
        extra_payload: dict[str, Any] = {}
        if is_binary:
            content = b""
            if entry is not None:
                if hasattr(entry, "content"):
                    raw_c = getattr(entry, "content")
                    content = raw_c if isinstance(raw_c, bytes) else str(raw_c).encode("utf-8")
                elif context.git is not None:
                    blob_id = entry.head_blob or entry.base_blob
                    if blob_id:
                        try:
                            content = context.git.read_blob(blob_id)
                        except Exception:
                            content = b""
                if not content:
                    if entry.head_source:
                        content = entry.head_source.encode("utf-8")
                    elif entry.base_source:
                        content = entry.base_source.encode("utf-8")
            extra_payload["content_sha256"] = hashlib.sha256(content).hexdigest()
        message = (
            f"Changed binary path {path} matches active deny_changes rule {primary_rule_id}"
            if is_binary
            else f"Changed path {path} matches active deny_changes rule {primary_rule_id}"
        )
        findings.append(
            _make_grounding_finding(
                context,
                rule_ids=tuple(rule_ids),
                rules=rules,
                file_path=path,
                symbol="",
                kind="path",
                entry=entry,
                witness_level=witness_level,
                message=message,
                extra_payload=extra_payload,
            )
        )
    for symbol, rule_ids in sorted(symbol_matches.items()):
        if expired := check_deadline(context, "grounding"):
            return expired
        entity = context.scope.entity(symbol)
        file_path = entity.file_path if entity else ""
        entry = entries_by_changed_path.get(file_path)
        primary_rule_id = min(rule_ids)
        findings.append(
            _make_grounding_finding(
                context,
                rule_ids=tuple(rule_ids),
                rules=rules,
                file_path=file_path,
                symbol=symbol,
                kind="symbol",
                entry=entry,
                witness_level=WitnessLevel.SOURCE,
                message=f"Changed entity {symbol} matches active deny_changes rule {primary_rule_id}",
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
