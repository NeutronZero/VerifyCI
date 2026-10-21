"""Deletion and dangling-reference checks."""

from __future__ import annotations

import re
from typing import Any

from verifyci.checks.base import (
    CheckContext,
    gap,
    make_finding,
    make_result,
    unsupported_scope_gaps,
)
from verifyci.contracts.model import CheckResult, Coverage, EvidenceKind, Outcome
from verifyci.contracts.names import symbol_matches_any


def _simple_name(qname: str) -> str:
    qual = qname.split(":", 1)[-1]
    return qual.rsplit(".", 1)[-1]


def _public_policy_match(context: CheckContext, entity) -> bool:
    patterns = context.policy.public_api.get("symbols", ())
    entry_patterns = context.policy.entrypoints.get("symbols", ())
    return bool(
        (patterns and symbol_matches_any(patterns, entity.qname))
        or (entry_patterns and symbol_matches_any(entry_patterns, entity.qname))
    )


def _head_references(context: CheckContext, simple: str) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    for path, facts in context.scope.head_facts.items():
        for call in facts.calls:
            if call.callee == simple or call.callee.endswith(f".{simple}"):
                references.append(
                    {
                        "path": path,
                        "line": call.line,
                        "kind": "call",
                        "callee": call.callee,
                    }
                )
        for imp in facts.imports:
            if simple in imp.names:
                references.append(
                    {
                        "path": path,
                        "line": imp.line,
                        "kind": "import",
                        "module": imp.module,
                    }
                )
    return references


def _dynamic_references(context: CheckContext, simple: str) -> list[dict[str, Any]]:
    pattern = re.compile(
        rf"(?:getattr\s*\([^,\n]+,\s*['\"]{re.escape(simple)}['\"]|\[['\"]{re.escape(simple)}['\"]\])"
    )
    out: list[dict[str, Any]] = []
    for entry in context.entries:
        if not entry.head_source:
            continue
        for line_number, line in enumerate(entry.head_source.splitlines(), start=1):
            if pattern.search(line):
                out.append(
                    {
                        "path": entry.head_path,
                        "line": line_number,
                        "kind": "dynamic",
                        "symbol": simple,
                    }
                )
    return out


def run(context: CheckContext) -> CheckResult:
    removed: list[Any] = []
    for path, facts in context.scope.base_facts.items():
        for entity in facts.entities:
            if entity.qname not in context.scope.head_entities:
                removed.append(entity)

    findings = []
    gaps = unsupported_scope_gaps(context, "deletion")
    references_found: list[dict[str, Any]] = []
    for entity in removed:
        simple = _simple_name(entity.qname)
        refs = _head_references(context, simple)
        dynamic_refs = _dynamic_references(context, simple)
        is_public = entity.is_export or _public_policy_match(context, entity)
        if refs:
            references_found.extend(refs)
            primary = refs[0]
            findings.append(
                make_finding(
                    context=context,
                    check_id="deletion",
                    defect_id="DEL-REACHABLE-SYMBOL",
                    subject={"path": entity.file_path, "symbol": entity.qname},
                    premises={
                        "removed_symbol": entity.qname,
                        "reference": primary,
                        "references": refs,
                    },
                    evidence_kind=EvidenceKind.REFERENCE,
                    evidence_payload={
                        "identity": {
                            "symbol": entity.qname,
                            "reference": primary,
                            "reference_count": len(refs),
                        },
                        "removed": entity.to_dict(),
                        "reference": primary,
                        "references": refs,
                    },
                    message=(
                        f"removed symbol {entity.qname} is still referenced by "
                        f"{primary['kind']} at {primary['path']}:{primary['line']}"
                    ),
                    remediation="Restore the symbol or update every live reference.",
                )
            )
        elif is_public:
            findings.append(
                make_finding(
                    context=context,
                    check_id="deletion",
                    defect_id="DEL-REACHABLE-SYMBOL",
                    subject={"path": entity.file_path, "symbol": entity.qname},
                    premises={"removed_symbol": entity.qname, "reason": "export_or_public_api"},
                    evidence_kind=EvidenceKind.REFERENCE,
                    evidence_payload={
                        "identity": {"symbol": entity.qname, "removed_export": True},
                        "removed": entity.to_dict(),
                        "reference": {
                            "kind": "export",
                            "path": entity.file_path,
                            "line": entity.start_line,
                            "symbol": entity.qname,
                        },
                    },
                    message=(
                        f"removed symbol {entity.qname} was an export/public-API symbol "
                        "and remains reachable through that export"
                    ),
                    remediation="Restore the symbol or make an explicit public-API breaking change.",
                )
            )
        if dynamic_refs:
            for ref in dynamic_refs:
                findings.append(
                    make_finding(
                        context=context,
                        check_id="deletion",
                        defect_id="DEL-DYNAMIC-REFERENCE",
                        subject={"path": entity.file_path, "symbol": entity.qname},
                        premises={"removed_symbol": entity.qname, "dynamic_reference": ref},
                        evidence_kind=EvidenceKind.REFERENCE,
                        evidence_payload={
                            "identity": {"symbol": entity.qname, "dynamic_reference": ref},
                            "removed": entity.to_dict(),
                            "reference": ref,
                        },
                        message=(
                            f"removed symbol {entity.qname} is dynamically referenced at "
                            f"{ref['path']}:{ref['line']}"
                        ),
                        remediation="Restore the symbol or change the dynamic lookup to a defined target.",
                    )
                )

    # A head import of a base symbol that no longer exists in head is a
    # dangling reference even when the removed definition was not exported.
    for path, facts in context.scope.head_facts.items():
        for imp in facts.imports:
            for name in imp.names:
                if not name or name == "*":
                    continue
                matching_base = [
                    e for e in context.scope.base_entities if e.endswith(f":{name}") or e.endswith(f".{name}")
                ]
                if not matching_base:
                    continue
                if not any(e.endswith(f":{name}") or e.endswith(f".{name}") for e in context.scope.head_entities):
                    findings.append(
                        make_finding(
                            context=context,
                            check_id="deletion",
                            defect_id="DEL-DANGLING-REFERENCE",
                            subject={"path": path, "symbol": name},
                            premises={
                                "imported_name": name,
                                "module": imp.module,
                                "head_line": imp.line,
                            },
                            evidence_kind=EvidenceKind.REFERENCE,
                            evidence_payload={
                                "identity": {
                                    "path": path,
                                    "line": imp.line,
                                    "module": imp.module,
                                    "name": name,
                                },
                                "reference": {
                                    "kind": "import",
                                    "path": path,
                                    "line": imp.line,
                                    "module": imp.module,
                                    "name": name,
                                },
                            },
                            message=f"head imports {name!r} from {imp.module!r}, but no head definition exists",
                            remediation="Restore the definition or update the import.",
                        )
                    )

    # Unsupported or dynamic scope is only a gap when deletion was relevant.
    if removed:
        dynamic_paths = sorted(
            path for path, facts in context.scope.head_facts.items() if facts.has_dynamic_dispatch
        )
        if dynamic_paths:
            gaps.append(
                gap(
                    "dynamic_target_unresolved",
                    {
                        "check_id": "deletion",
                        "paths": dynamic_paths,
                        "reason": "dynamic_dispatch_in_repository_scope",
                    },
                )
            )
        for path in sorted({e.file_path for e in removed}):
            facts = context.scope.head_facts.get(path) or context.scope.base_facts.get(path)
            if facts is not None and not facts.supported:
                gaps.append(
                    gap(
                        "unsupported_language",
                        {
                            "check_id": "deletion",
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
    elif not removed:
        outcome = Outcome.NOT_APPLICABLE
    else:
        outcome = Outcome.PASS
    coverage = Coverage.COMPLETE if not gaps else Coverage.PARTIAL
    return make_result(
        context=context,
        check_id="deletion",
        outcome=outcome,
        coverage=coverage,
        evaluated_scope={
            "base_entities": len(context.scope.base_entities),
            "head_entities": len(context.scope.head_entities),
            "removed_symbols": sorted(e.qname for e in removed),
        },
        scope_enumeration={"complete": not gaps, "removed_count": len(removed)},
        candidate_discovery={
            "complete": not gaps,
            "live_references": len(references_found),
            "dynamic_scope_gaps": len(gaps),
        },
        applicability_evidence={"removed_symbols": len(removed)},
        reason_codes=tuple(sorted({g.reason_code for g in gaps})),
        coverage_gaps=gaps,
        findings=findings,
    )


__all__ = ["run"]
