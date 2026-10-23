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
from verifyci.contracts.names import path_matches_any, symbol_matches_any


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


def _module_name(path: str) -> str:
    mod = path.rsplit(".", 1)[0].replace("/", ".").replace("\\", ".")
    # Normalize package __init__ modules to their package name.
    if mod.endswith(".__init__"):
        mod = mod[: -len(".__init__")]
    return mod


def _resolve_module(imp_module: str, importing_path: str) -> str | None:
    if not imp_module:
        return None
    if not imp_module.startswith("."):
        return imp_module
    dots = len(imp_module) - len(imp_module.lstrip("."))
    rest = imp_module.lstrip(".")
    base_mod = _module_name(importing_path)
    if importing_path.endswith("__init__.py"):
        # The module name is already the package name.
        pkg = base_mod
    elif dots == 1:
        pkg = base_mod.rsplit(".", 1)[0] if "." in base_mod else ""
    else:
        parts = base_mod.split(".")
        # Go up (dots-1) levels.
        if dots - 1 >= len(parts):
            return None
        pkg = ".".join(parts[: len(parts) - (dots - 1)])
    if rest:
        return f"{pkg}.{rest}" if pkg else rest
    return pkg or None


def _head_references(context: CheckContext, entity: Any) -> list[dict[str, Any]]:
    simple = _simple_name(entity.qname)
    entity_module = _module_name(entity.file_path)
    references: list[dict[str, Any]] = []
    for path, facts in context.scope.head_facts.items():
        same_module = path == entity.file_path
        imports_symbol = False
        for imp in facts.imports:
            if simple not in imp.names:
                continue
            if _resolve_module(imp.module or "", path) == entity_module:
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


def _dynamic_references(context: CheckContext, entity: Any) -> list[dict[str, Any]]:
    simple = _simple_name(entity.qname)
    entity_module = _module_name(entity.file_path)
    pattern = re.compile(
        rf"(?:getattr\s*\([^,\n]+,\s*['\"]{re.escape(simple)}['\"]|\[['\"]{re.escape(simple)}['\"]\])"
    )
    out: list[dict[str, Any]] = []
    for path, facts in context.scope.head_facts.items():
        # Only attribute a dynamic lookup to this entity when the file is the
        # same module or imports the symbol from this entity's module.
        same_module = path == entity.file_path
        imports_symbol = any(
            simple in imp.names and _resolve_module(imp.module or "", path) == entity_module
            for imp in facts.imports
        )
        if not same_module and not imports_symbol:
            continue
        entry = next((e for e in context.entries if e.head_path == path), None)
        if entry is None or not entry.head_source:
            continue
        for line_number, line in enumerate(entry.head_source.splitlines(), start=1):
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
    for entity in removed:
        simple = _simple_name(entity.qname)
        refs = _head_references(context, entity)
        dynamic_refs = _dynamic_references(context, entity)
        facts = context.scope.base_facts.get(entity.file_path)
        is_exported = False
        if entity.file_path.endswith(".py"):
            if facts is not None and simple in facts.exports:
                is_exported = True
            for p, hf in context.scope.head_facts.items():
                if p.endswith("__init__.py"):
                    if any(simple in imp.names for imp in hf.imports):
                        is_exported = True
        else:
            is_exported = bool(entity.is_export)
        is_public = is_exported or _public_policy_match(context, entity)
        if is_public:
            reachable_removed.add((entity.file_path, simple))
        if refs and is_public:
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
    for path, facts in context.scope.head_facts.items():
        if path.endswith("__init__.py"):
            continue
        for imp in facts.imports:
            for name in imp.names:
                if not name or name == "*":
                    continue
                resolved = _resolve_module(imp.module or "", path)
                if resolved is None:
                    if path not in unresolved_import_paths:
                        unresolved_import_paths.add(path)
                    continue
                base_files = [p for p in context.scope.base_facts if _module_name(p) == resolved]
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
                        mod = (imp.module or "").strip()
                        if not mod:
                            continue
                        # Relative imports lose their leading dots in the
                        # frontend, so resolve against the package first.
                        candidates = {
                            f"{resolved}.{mod}",
                            mod,
                        }
                        for cand in candidates:
                            if any(_module_name(p) == cand for p in context.scope.base_facts):
                                candidate_modules.add(cand)
                    if not candidate_modules:
                        continue
                    base_matches = [
                        entity
                        for p in context.scope.base_facts
                        if _module_name(p) in candidate_modules
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
    for path, facts in context.scope.head_facts.items():
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
            if not any(
                _simple_name(entity.qname) == simple and entity.file_path == path
                for entity in removed
            ):
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
