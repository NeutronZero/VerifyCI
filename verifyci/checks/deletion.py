"""Deletion and dangling-reference checks."""

from __future__ import annotations

from collections import defaultdict
import re
from typing import Any, Mapping

from verifyci.checks._modules import (
    module_candidates as _module_candidates,
    normalize_module_path as _normalized_module_path,
    python_module_name as _module_name,
    resolve_dotted_module as _resolve_module,
)
from verifyci.checks.base import (
    CheckContext,
    budget_exhausted_result,
    check_deadline,
    entity_budget_exceeded,
    gap,
    make_finding,
    make_result,
    simple_symbol_name as _simple_name,
    unsupported_scope_gaps,
)
from verifyci.contracts.model import CheckResult, Coverage, EvidenceKind, Outcome
from verifyci.contracts.names import path_matches_any, symbol_matches_any


def _public_policy_match(context: CheckContext, entity) -> bool:
    patterns = context.policy.public_api.get("symbols", ())
    entry_patterns = context.policy.entrypoints.get("symbols", ())
    return bool(
        (patterns and symbol_matches_any(patterns, entity.qname))
        or (entry_patterns and symbol_matches_any(entry_patterns, entity.qname))
    )


def _head_references(
    context: CheckContext,
    entity: Any,
    importers_by_symbol: Mapping[tuple[str, str], list[str]] | None = None,
) -> list[dict[str, Any]]:
    simple = _simple_name(entity.qname)
    entity_module = _module_name(entity.file_path)
    references: list[dict[str, Any]] = []

    entity_modules = {entity_module, _normalized_module_path(entity.file_path)}
    if importers_by_symbol is not None:
        candidate_paths: set[str] = set()
        for module_key in entity_modules:
            candidate_paths.update(importers_by_symbol.get((module_key, simple), ()))
        candidate_paths.add(entity.file_path)
        path_items = [
            (p, context.scope.head_facts[p])
            for p in candidate_paths
            if p in context.scope.head_facts
        ]
    else:
        path_items = list(context.scope.head_facts.items())

    for path, facts in path_items:
        same_module = path == entity.file_path
        imports_symbol = False
        for imp in facts.imports:
            if simple not in imp.names:
                continue
            if _module_candidates(imp.module or "", path, getattr(imp, "level", 0)) & entity_modules:
                imports_symbol = True
                break
        if not same_module and not imports_symbol:
            continue
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


def _dynamic_references(
    context: CheckContext,
    entity: Any,
    entries_by_head_path: Mapping[str, Any] | None = None,
    importers_by_symbol: Mapping[tuple[str, str], list[str]] | None = None,
    lines_by_path: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    simple = _simple_name(entity.qname)
    entity_module = _module_name(entity.file_path)
    pattern = re.compile(
        rf"(?:getattr\s*\([^,\n]+,\s*['\"]{re.escape(simple)}['\"]|\[['\"]{re.escape(simple)}['\"]\])"
    )
    out: list[dict[str, Any]] = []

    if importers_by_symbol is not None:
        candidate_paths = set()
        for module_key in {entity_module, _normalized_module_path(entity.file_path)}:
            candidate_paths.update(importers_by_symbol.get((module_key, simple), ()))
        candidate_paths.add(entity.file_path)
        path_items = [
            (p, context.scope.head_facts[p])
            for p in candidate_paths
            if p in context.scope.head_facts
        ]
    else:
        path_items = list(context.scope.head_facts.items())

    for path, facts in path_items:
        # Only attribute a dynamic lookup to this entity when the file is the
        # same module or imports the symbol from this entity's module.
        same_module = path == entity.file_path
        entity_modules = {entity_module, _normalized_module_path(entity.file_path)}
        imports_symbol = any(
            simple in imp.names
            and _module_candidates(imp.module or "", path, getattr(imp, "level", 0)) & entity_modules
            for imp in facts.imports
        )
        if not same_module and not imports_symbol:
            continue
        if entries_by_head_path is not None:
            entry = entries_by_head_path.get(path)
        else:
            entry = next((e for e in context.entries if e.head_path == path), None)
        if entry is None or not entry.head_source:
            continue
        if lines_by_path is not None:
            lines = lines_by_path.get(path)
            if lines is None:
                lines = entry.head_source.splitlines()
                lines_by_path[path] = lines
        else:
            lines = entry.head_source.splitlines()
        for line_number, line in enumerate(lines, start=1):
            if "__all__" in line:
                continue
            if pattern.search(line):
                out.append(
                    {
                        "path": path,
                        "line": line_number,
                        "kind": "dynamic",
                        "symbol": simple,
                    }
                )
    return out


def run(context: CheckContext) -> CheckResult:
    if expired := check_deadline(context, "deletion"):
        return expired
    entities_over_budget, enumerated_entities = entity_budget_exceeded(context)
    if entities_over_budget:
        return budget_exhausted_result(
            context,
            "deletion",
            f"max_entities limit exceeded ({enumerated_entities} > {context.budget.max_entities})",
        )
    excluded_patterns = []
    for key in ("generated", "vendored"):
        excluded_patterns.extend(context.policy.path_classes.get(key, ()))
    excluded_patterns = tuple(excluded_patterns)

    removed: list[Any] = []
    reachable_removed: set[tuple[str, str]] = set()
    for path, facts in context.scope.base_facts.items():
        for entity in facts.entities:
            if entity.qname not in context.scope.head_entities:
                if excluded_patterns and path_matches_any(excluded_patterns, entity.file_path):
                    continue
                removed.append(entity)

    findings = []
    gaps = unsupported_scope_gaps(context, "deletion")
    references_found: list[dict[str, Any]] = []
    proven_dynamic_paths: set[str] = set()

    entries_by_head_path: dict[str, Any] = {
        e.head_path: e for e in context.entries if e.head_path
    }
    init_imported_symbols: set[str] = set()
    importers_by_symbol: dict[tuple[str, str], list[str]] = defaultdict(list)
    for p, hf in context.scope.head_facts.items():
        if p.endswith("__init__.py"):
            for imp in hf.imports:
                init_imported_symbols.update(imp.names)
        for imp in hf.imports:
            resolved = _module_candidates(imp.module or "", p, getattr(imp, "level", 0))
            for module_key in resolved:
                for name in imp.names:
                    importers_by_symbol[(module_key, name)].append(p)

    dynamic_lines_cache: dict[str, list[str]] = {}
    for entity in removed:
        if expired := check_deadline(context, "deletion"):
            return expired
        simple = _simple_name(entity.qname)
        refs = _head_references(context, entity, importers_by_symbol=importers_by_symbol)
        dynamic_refs = _dynamic_references(
            context,
            entity,
            entries_by_head_path=entries_by_head_path,
            importers_by_symbol=importers_by_symbol,
            lines_by_path=dynamic_lines_cache,
        )
        facts = context.scope.base_facts.get(entity.file_path)
        is_exported = False
        if entity.file_path.endswith(".py"):
            if facts is not None and simple in facts.exports:
                is_exported = True
            elif simple in init_imported_symbols:
                is_exported = True
        else:
            is_exported = bool(entity.is_export)
        is_public = is_exported or _public_policy_match(context, entity)
        if is_public:
            reachable_removed.add((entity.file_path, simple))
        if refs and is_public:
            references_found.extend(refs)
            if len(references_found) > context.budget.max_references:
                return budget_exhausted_result(
                    context,
                    "deletion",
                    f"max_references limit exceeded ({len(references_found)} > {context.budget.max_references})",
                )
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
                proven_dynamic_paths.add(str(ref.get("path")))
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
    # Re-export imports in package __init__ files are covered by the
    # reachable-symbol finding and are not separately reported as dangling.
    removed_simple_names = {_simple_name(entity.qname) for entity in removed}
    emitted_dangling: set[tuple[str, str]] = set()
    unresolved_import_paths: set[str] = set()

    base_files_by_module: dict[str, list[str]] = defaultdict(list)
    for p in context.scope.base_facts:
        base_files_by_module[_module_name(p)].append(p)
    head_modules: set[str] = {_module_name(p) for p in context.scope.head_facts}

    for path, facts in context.scope.head_facts.items():
        if expired := check_deadline(context, "deletion"):
            return expired
        if path.endswith("__init__.py"):
            continue
        # TypeScript/JavaScript specifiers are repository paths, not module
        # identities, and packages imported from outside the tree are not gaps.
        # Cross-file TS references are covered by reachable-symbol analysis.
        if not path.endswith(".py"):
            continue
        for imp in facts.imports:
            for name in imp.names:
                if not name or name == "*":
                    continue
                resolved = _resolve_module(imp.module or "", path, getattr(imp, "level", 0))
                if resolved is None:
                    if path not in unresolved_import_paths:
                        unresolved_import_paths.add(path)
                    continue
                base_files = base_files_by_module.get(resolved, [])
                if not base_files:
                    # The imported module cannot be resolved against the base
                    # repository; report incomplete coverage instead of a
                    # possibly wrong finding.
                    if path not in unresolved_import_paths:
                        unresolved_import_paths.add(path)
                    continue
                base_matches = [
                    entity
                    for p in base_files
                    for entity in context.scope.base_facts[p].entities
                    if _simple_name(entity.qname) == name
                ]
                # An imported name may itself be a submodule of the resolved
                # module (for example ``from . import helper`` or
                # ``from pkg import helper``).  Check that submodule identity
                # before treating the import as unresolved.
                submodule = f"{resolved}.{name}"
                sub_files = base_files_by_module.get(submodule, [])
                if sub_files:
                    sub_survives = submodule in head_modules
                    # A submodule import is dangling only when the module
                    # itself disappeared.  Internal symbol removals are
                    # handled as separate symbol findings.
                    if not sub_survives:
                        emitted_dangling.add((path, name))
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
                    continue
                # Fall back only for a package re-export boundary: when the
                # imported module is a package (__init__), resolve the name
                # through the modules that the package itself imports it from.
                # Do not fall back for an ordinary module.
                if not base_matches:
                    package_init = next(
                        (
                            p
                            for p in context.scope.base_facts
                            if _module_name(p) == resolved and p.endswith("__init__.py")
                        ),
                        None,
                    )
                    if package_init is None:
                        continue
                    candidate_modules: set[str] = set()
                    for imp in context.scope.base_facts[package_init].imports:
                        if name not in (imp.names or ()):
                            continue
                        cand = _resolve_module(imp.module or "", package_init, getattr(imp, "level", 0))
                        if cand and cand in base_files_by_module:
                            candidate_modules.add(cand)
                    if not candidate_modules:
                        continue
                    base_matches = [
                        entity
                        for mod in candidate_modules
                        for p in base_files_by_module.get(mod, ())
                        for entity in context.scope.base_facts[p].entities
                        if _simple_name(entity.qname) == name
                    ]
                if not base_matches:
                    continue
                removed_matches = [e for e in base_matches if e.qname not in context.scope.head_entities]
                if not removed_matches:
                    continue
                emitted_dangling.add((path, name))
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

    # Direct calls to a removed symbol with no head definition are also
    # dangling references, including calls to private helpers.
    removed_by_path_and_simple = {(e.file_path, _simple_name(e.qname)) for e in removed}
    for path, facts in context.scope.head_facts.items():
        if expired := check_deadline(context, "deletion"):
            return expired
        if path.endswith("__init__.py"):
            continue
        for call in facts.calls:
            simple = call.callee.split(".")[-1]
            if not simple or simple not in removed_simple_names:
                continue
            if (path, simple) in reachable_removed:
                continue
            # Only treat a call as dangling when a removed entity with that
            # name existed in the same file as the call.  A same-named symbol
            # in an unrelated scope does not make the call safe.
            if (path, simple) not in removed_by_path_and_simple:
                continue
            if (path, simple) in emitted_dangling:
                continue
            emitted_dangling.add((path, simple))
            findings.append(
                make_finding(
                    context=context,
                    check_id="deletion",
                    defect_id="DEL-DANGLING-REFERENCE",
                    subject={"path": path, "symbol": simple},
                    premises={
                        "called_name": simple,
                        "callee": call.callee,
                        "head_line": call.line,
                    },
                    evidence_kind=EvidenceKind.REFERENCE,
                    evidence_payload={
                        "identity": {
                            "path": path,
                            "line": call.line,
                            "callee": call.callee,
                            "name": simple,
                        },
                        "reference": {
                            "kind": "call",
                            "path": path,
                            "line": call.line,
                            "callee": call.callee,
                            "name": simple,
                        },
                    },
                    message=f"head calls {simple!r}, but no head definition exists",
                    remediation="Restore the definition or update the call.",
                )
            )

    if removed and unresolved_import_paths:
        gaps.append(
            gap(
                "mapping_unresolved",
                {
                    "check_id": "deletion",
                    "paths": sorted(unresolved_import_paths),
                    "reason": "unresolved_import_module",
                },
            )
        )

    # Unsupported or dynamic scope is only a gap when deletion was relevant.
    if removed:
        dynamic_paths = sorted(
            path
            for path, facts in context.scope.head_facts.items()
            if facts.has_dynamic_dispatch and path not in proven_dynamic_paths
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
    if any(g.reason_code in ("unsupported_language", "parse_error") for g in gaps):
        coverage = Coverage.UNKNOWN
    else:
        coverage = Coverage.COMPLETE if not gaps else Coverage.PARTIAL
    scope_complete = not any(
        g.reason_code in ("unsupported_language", "parse_error", "rename_limit_exceeded")
        for g in gaps
    )
    candidate_complete = not any(
        g.reason_code in ("dynamic_target_unresolved", "unresolved_scope")
        for g in gaps
    )
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
        scope_enumeration={
            "complete": scope_complete,
            "removed_count": len(removed),
        },
        candidate_discovery={
            "complete": candidate_complete,
            "live_references": len(references_found),
            "dynamic_scope_gaps": len(gaps),
        },
        applicability_evidence={"removed_symbols": len(removed)},
        reason_codes=tuple(sorted({g.reason_code for g in gaps})),
        coverage_gaps=gaps,
        findings=findings,
    )


__all__ = ["run"]
