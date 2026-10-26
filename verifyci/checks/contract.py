"""Signature, export, and local call-site compatibility checks."""

from __future__ import annotations

from dataclasses import dataclass
import posixpath
from typing import Any

from verifyci.checks.base import (
    CheckContext,
    gap,
    make_finding,
    make_result,
    unsupported_scope_gaps,
)
from verifyci.contracts.model import CheckResult, Coverage, Entity, EvidenceKind, Outcome
from verifyci.contracts.names import symbol_matches_any
from verifyci.scope.entities import CallSite, SourceFacts

_BUILTIN_CALLS: frozenset[str] = frozenset(
    {
        "print",
        "len",
        "range",
        "str",
        "int",
        "float",
        "bool",
        "dict",
        "list",
        "set",
        "tuple",
        "min",
        "max",
        "sum",
        "any",
        "all",
        "zip",
        "enumerate",
        "isinstance",
        "issubclass",
        "hasattr",
        "getattr",
        "setattr",
        "super",
        "open",
        "type",
        "repr",
        "id",
        "hash",
        "sorted",
        "filter",
        "map",
        "round",
        "abs",
        "divmod",
        "pow",
        "callable",
        "iter",
        "next",
        "slice",
        "format",
        "bytes",
        "bytearray",
        "console",
        "Math",
        "JSON",
        "Promise",
        "Array",
        "Object",
        "String",
        "Number",
        "Boolean",
        "Error",
        "TypeError",
        "parseInt",
        "parseFloat",
        "isNaN",
    }
)


@dataclass(frozen=True, slots=True)
class _Sig:
    params: tuple[tuple[str, str, bool], ...]

    @property
    def positional(self) -> tuple[tuple[str, str, bool], ...]:
        return tuple(p for p in self.params if p[1] in ("posonly", "positional"))

    @property
    def required_positional(self) -> int:
        return sum(1 for p in self.positional if not p[2])

    @property
    def has_vararg(self) -> bool:
        return any(p[1] == "vararg" for p in self.params)

    @property
    def has_kwarg(self) -> bool:
        return any(p[1] == "kwarg" for p in self.params)

    @property
    def keyword_names(self) -> set[str]:
        return {p[0] for p in self.params if p[1] in ("positional", "kwonly")}

    @property
    def required_kwonly(self) -> set[str]:
        return {p[0] for p in self.params if p[1] == "kwonly" and not p[2]}


def _sig(entity: Entity) -> _Sig:
    return _Sig(tuple(entity.parameters))


def _simple(qname: str) -> str:
    return qname.split(":", 1)[-1].rsplit(".", 1)[-1]


def _normalize_mod(path: str) -> str:
    p = path.replace("\\", "/").strip()
    for ext in (
        ".py",
        ".pyi",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".mts",
        ".cts",
        ".go",
        ".rs",
    ):
        if p.endswith(ext):
            p = p[: -len(ext)]
            break
    if p.endswith("/__init__"):
        p = p[: -len("/__init__")]
    elif p.endswith(".__init__"):
        p = p[: -len(".__init__")]
    return p.replace(".", "/")


def _resolve_import_module(imp_module: str, importing_path: str, level: int = 0) -> str:
    importing_dir = posixpath.dirname(importing_path.replace("\\", "/"))
    imp_module = (imp_module or "").strip()
    if imp_module.startswith("./") or imp_module.startswith("../"):
        norm = posixpath.normpath(posixpath.join(importing_dir, imp_module))
        return _normalize_mod(norm)
    if imp_module.startswith("."):
        dots = len(imp_module) - len(imp_module.lstrip("."))
        level = level or dots
        imp_module = imp_module.lstrip(".")
    if level and level > 0:
        base_mod = _normalize_mod(importing_path)
        parts = base_mod.split("/") if base_mod else []
        if not importing_path.endswith("__init__.py") and parts:
            parts = parts[:-1]
        if level > 1:
            if level - 1 >= len(parts):
                parts = []
            else:
                parts = parts[: len(parts) - (level - 1)]
        pkg = "/".join(parts)
        if imp_module:
            rel = imp_module.replace(".", "/")
            return f"{pkg}/{rel}" if pkg else rel
        return pkg
    return _normalize_mod(imp_module)


def _match_callee_to_entity(
    call: CallSite,
    caller_path: str,
    caller_facts: SourceFacts,
    target: Entity,
) -> str:
    target_mod = _normalize_mod(target.file_path)
    target_symbol = target.qname.split(":", 1)[-1]
    target_simple = target_symbol.rsplit(".", 1)[-1]

    callee = call.callee

    if "." not in callee:
        if caller_path == target.file_path:
            for imp in caller_facts.imports:
                for orig_name, local_name in getattr(imp, "aliases", ()):
                    if local_name == callee:
                        imp_mod = _resolve_import_module(
                            imp.module, caller_path, getattr(imp, "level", 0)
                        )
                        if imp_mod != target_mod:
                            return "NO_MATCH"
                if not getattr(imp, "aliases", ()) and callee in imp.names:
                    imp_mod = _resolve_import_module(
                        imp.module, caller_path, getattr(imp, "level", 0)
                    )
                    if imp_mod != target_mod:
                        return "NO_MATCH"
            if callee == target_simple:
                return "MATCH"
            return "NO_MATCH"

        for imp in caller_facts.imports:
            imp_mod = _resolve_import_module(
                imp.module, caller_path, getattr(imp, "level", 0)
            )
            aliases = getattr(imp, "aliases", ())
            if aliases:
                for orig_name, local_name in aliases:
                    if local_name == callee:
                        if imp_mod == target_mod and (
                            orig_name == target_symbol or orig_name == target_simple
                        ):
                            return "MATCH"
                        return "NO_MATCH"
            else:
                if callee in imp.names:
                    if imp_mod == target_mod and callee == target_simple:
                        return "MATCH"
                    return "NO_MATCH"

        for ent in caller_facts.entities:
            ent_simple = ent.qname.split(":", 1)[-1].rsplit(".", 1)[-1]
            if ent_simple == callee:
                return "NO_MATCH"

        if callee in _BUILTIN_CALLS:
            return "NO_MATCH"

        if callee == target_simple:
            return "AMBIGUOUS"

        return "NO_MATCH"

    else:
        receiver, attr = callee.rsplit(".", 1)
        if attr != target_simple:
            return "NO_MATCH"

        if receiver in ("self", "cls"):
            if caller_path == target.file_path:
                return "MATCH"
            return "NO_MATCH"

        for imp in caller_facts.imports:
            imp_mod = _resolve_import_module(
                imp.module, caller_path, getattr(imp, "level", 0)
            )
            aliases = getattr(imp, "aliases", ())
            if aliases:
                for orig_name, local_name in aliases:
                    if local_name == receiver or local_name == callee:
                        if imp_mod == target_mod:
                            return "MATCH"
                        return "NO_MATCH"
            else:
                if (
                    receiver in imp.names
                    or receiver == imp.module
                    or receiver.rsplit(".", 1)[-1] == imp.module.rsplit(".", 1)[-1]
                ):
                    if imp_mod == target_mod:
                        return "MATCH"
                    return "NO_MATCH"

        rec_mod = _normalize_mod(receiver)
        if rec_mod == target_mod:
            return "MATCH"

        return "AMBIGUOUS"


def _call_problem(call: CallSite, sig: _Sig) -> str:
    if call.has_starargs or call.has_kwargs:
        return ""
    if call.positional < sig.required_positional:
        return "too_few_positional_arguments"
    max_positional = len(sig.positional)
    if not sig.has_vararg and call.positional > max_positional:
        return "too_many_positional_arguments"
    if sig.has_kwarg:
        return ""
    for keyword in call.keywords:
        if keyword not in sig.keyword_names:
            return f"unknown_keyword:{keyword}"
    missing = sig.required_kwonly - set(call.keywords)
    if missing:
        return f"missing_required_keyword:{sorted(missing)[0]}"
    return ""


def _changed_new_lines(context: CheckContext) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for entry in context.entries:
        if not entry.head_path:
            continue
        lines = out.setdefault(entry.head_path, set())
        for hunk in entry.hunks:
            for line in range(hunk.new_start, hunk.new_end() + 1):
                lines.add(line)
    return out


def _public_api(context: CheckContext, entity: Entity) -> bool:
    patterns = context.policy.public_api.get("symbols", ())
    return bool(patterns and symbol_matches_any(patterns, entity.qname))


def _finding_call(
    context: CheckContext,
    *,
    entity: Entity,
    call_path: str,
    call: CallSite,
    problem: str,
    base_sig: _Sig,
    new_sig: _Sig | None = None,
    defect_id: str = "CTR-CALL-INCOMPATIBLE",
) -> Any:
    signature_changed = defect_id == "CTR-SIGNATURE-BREAK"
    return make_finding(
        context=context,
        check_id="contract",
        defect_id=defect_id,
        subject={
            "path": entity.file_path if signature_changed else call_path,
            "symbol": entity.qname,
        },
        premises={
            "callee": call.callee,
            "call_line": call.line,
            "problem": problem,
            "base_signature": [list(p) for p in base_sig.params],
            **({"head_signature": [list(p) for p in new_sig.params]} if new_sig else {}),
        },
        evidence_kind=EvidenceKind.CALL_SITE,
        evidence_payload={
            "identity": {
                "symbol": entity.qname,
                "caller_file": call_path,
                "call": {
                    "callee": call.callee,
                    "line": call.line,
                    "positional": call.positional,
                    "keywords": list(call.keywords),
                },
                "problem": problem,
                **({"head_signature": [list(p) for p in new_sig.params]} if new_sig else {}),
            },
            "callee": call.callee,
            "call": call.to_dict(),
            "base_signature": [list(p) for p in base_sig.params],
            **({"head_signature": [list(p) for p in new_sig.params]} if new_sig else {}),
            "problem": problem,
            "caller_file": call_path,
        },
        message=(
            f"call to {call.callee} at {call_path}:{call.line} is incompatible "
            f"with the {'changed' if signature_changed else 'unchanged'} signature ({problem})"
        ),
        remediation="Update the call site or preserve the previous signature.",
    )


def run(context: CheckContext) -> CheckResult:
    base_entities: dict[str, Entity] = {}
    head_entities: dict[str, Entity] = {}
    for facts in context.scope.base_facts.values():
        base_entities.update({e.qname: e for e in facts.entities})
    for facts in context.scope.head_facts.values():
        head_entities.update({e.qname: e for e in facts.entities})

    changed_lines = _changed_new_lines(context)
    all_head_calls: list[tuple[str, SourceFacts, CallSite]] = []
    for path, facts in context.scope.head_facts.items():
        for call in facts.calls:
            all_head_calls.append((path, facts, call))

    findings = []
    gaps = unsupported_scope_gaps(context, "contract")
    relevant = False
    checked_calls = 0

    changed_qnames = set(context.scope.changed_entities)
    for qname in sorted(changed_qnames):
        base = base_entities.get(qname)
        head = head_entities.get(qname)
        if base is None and head is None:
            continue
        relevant = True
        if base is not None and head is not None:
            old_sig = _sig(base)
            new_sig = _sig(head)
            async_changed = base.is_async != head.is_async
            if old_sig.params != new_sig.params or async_changed:
                problems: list[str] = []
                if async_changed:
                    problems.append("async_changed")
                if new_sig.required_positional > old_sig.required_positional:
                    problems.append("required_positional_parameters_added")
                if old_sig.has_vararg and not new_sig.has_vararg:
                    problems.append("varargs_removed")
                if old_sig.has_kwarg and not new_sig.has_kwarg:
                    problems.append("kwargs_removed")
                if old_sig.keyword_names - new_sig.keyword_names:
                    problems.append("keyword_parameters_removed")
                matched_callers = []
                for path, facts, call in all_head_calls:
                    res = _match_callee_to_entity(call, path, facts, head)
                    if res == "MATCH":
                        matched_callers.append((path, facts, call))
                    elif res == "AMBIGUOUS":
                        gaps.append(
                            gap(
                                "dynamic_target_unresolved",
                                {
                                    "check_id": "contract",
                                    "path": path,
                                    "line": call.line,
                                    "callee": call.callee,
                                    "target": head.qname,
                                },
                            )
                        )

                public = _public_api(context, head)
                if problems and (public or not matched_callers):
                    findings.append(
                        make_finding(
                            context=context,
                            check_id="contract",
                            defect_id="CTR-SIGNATURE-BREAK",
                            subject={"path": head.file_path, "symbol": qname},
                            premises={
                                "base_signature": [list(p) for p in old_sig.params],
                                "head_signature": [list(p) for p in new_sig.params],
                                "problems": problems,
                                "async_changed": async_changed,
                            },
                            evidence_kind=EvidenceKind.REFERENCE,
                            evidence_payload={
                                "identity": {
                                    "symbol": qname,
                                    "base_signature": [list(p) for p in old_sig.params],
                                    "head_signature": [list(p) for p in new_sig.params],
                                    "problems": problems,
                                    "async_changed": async_changed,
                                },
                                "base": base.to_dict(),
                                "head": head.to_dict(),
                                "problems": problems,
                                "async_changed": async_changed,
                            },
                            message=(
                                f"signature of {qname} changed incompatibly: " + ", ".join(problems)
                            ),
                            remediation="Preserve the previous signature or migrate every caller.",
                        )
                    )
                for path, facts, call in matched_callers:
                    if call.has_starargs or call.has_kwargs:
                        gaps.append(
                            gap(
                                "dynamic_call",
                                {
                                    "check_id": "contract",
                                    "path": path,
                                    "line": call.line,
                                    "callee": call.callee,
                                },
                            )
                        )
                        continue
                    problem = _call_problem(call, new_sig)
                    if not problem and async_changed:
                        problem = "async_changed"
                    if problem:
                        checked_calls += 1
                        if not (public and problems):
                            findings.append(
                                _finding_call(
                                    context,
                                    entity=head,
                                    call_path=path,
                                    call=call,
                                    problem=problem,
                                    base_sig=old_sig,
                                    new_sig=new_sig,
                                    defect_id="CTR-SIGNATURE-BREAK",
                                )
                            )
        elif base is not None and head is None:
            if _public_api(context, base):
                findings.append(
                    make_finding(
                        context=context,
                        check_id="contract",
                        defect_id="CTR-EXPORT-BREAK",
                        subject={"path": base.file_path, "symbol": qname},
                        premises={"public_api": True, "removed": True},
                        evidence_kind=EvidenceKind.REFERENCE,
                        evidence_payload={
                            "identity": {"symbol": qname, "removed_public_api": True},
                            "removed": base.to_dict(),
                            "reference": {
                                "kind": "public_api",
                                "path": base.file_path,
                                "line": base.start_line,
                                "symbol": qname,
                            },
                        },
                        message=f"public API symbol {qname} was removed",
                        remediation="Restore the export or make an explicit public-API breaking change.",
                    )
                )
        # Added entities are not a contract break.

    # A caller changed in the head can break against an unchanged base callee.
    for path, facts, call in all_head_calls:
        if call.line not in changed_lines.get(path, set()):
            continue
        if call.has_starargs or call.has_kwargs:
            gaps.append(
                gap(
                    "dynamic_call",
                    {"check_id": "contract", "path": path, "line": call.line, "callee": call.callee},
                )
            )
            continue
        matched_bases = []
        ambiguous = False
        for entity in base_entities.values():
            if entity.qname in changed_qnames:
                continue
            res = _match_callee_to_entity(call, path, facts, entity)
            if res == "MATCH":
                matched_bases.append(entity)
            elif res == "AMBIGUOUS":
                ambiguous = True
        if ambiguous and not matched_bases:
            gaps.append(
                gap(
                    "dynamic_target_unresolved",
                    {"check_id": "contract", "path": path, "line": call.line, "callee": call.callee},
                )
            )
            continue
        if not matched_bases:
            continue
        base = matched_bases[0]
        old_sig = _sig(base)
        problem = _call_problem(call, old_sig)
        if problem:
            checked_calls += 1
            findings.append(
                _finding_call(
                    context,
                    entity=base,
                    call_path=path,
                    call=call,
                    problem=problem,
                    base_sig=old_sig,
                )
            )
        relevant = True

    # Unsupported code languages make the contract scope incomplete.  Text,
    # docs, config, and other non-code files are out of scope.
    code_suffixes = {
        "py", "pyi", "ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts",
        "go", "rs", "java", "kt", "kts", "c", "cc", "cpp", "h", "hpp", "cs",
        "rb", "php", "swift", "scala",
    }
    for entry in context.entries:
        path = entry.head_path or entry.base_path
        if not path:
            continue
        suffix = path.rsplit(".", 1)[-1].lower()
        if suffix not in code_suffixes:
            continue
        facts = context.scope.head_facts.get(path) or context.scope.base_facts.get(path)
        if facts is not None and not facts.supported:
            relevant = True
            gaps.append(
                gap(
                    "unsupported_language",
                    {"check_id": "contract", "path": path, "language": facts.language},
                )
            )
        elif facts is not None and facts.parse_error:
            relevant = True
            gaps.append(
                gap(
                    "parse_error",
                    {"check_id": "contract", "path": path, "detail": facts.parse_error},
                )
            )
        elif facts is not None and facts.has_unknown_decorator and facts.entities:
            # Decorators can alter call semantics.  A visible decorator is a
            # capability gap, not a silent pass.
            relevant = True
            gaps.append(
                gap(
                    "unknown_decorator",
                    {"check_id": "contract", "path": path},
                )
            )

    if findings:
        outcome = Outcome.FAIL
    elif gaps:
        outcome = Outcome.INCONCLUSIVE
    elif not relevant:
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
        g.reason_code in ("dynamic_call", "dynamic_target_unresolved")
        for g in gaps
    )
    return make_result(
        context=context,
        check_id="contract",
        outcome=outcome,
        coverage=coverage,
        evaluated_scope={
            "changed_entities": sorted(changed_qnames),
            "candidate_calls": len(all_head_calls),
            "checked_calls": checked_calls,
        },
        scope_enumeration={
            "complete": scope_complete,
            "changed_entities": len(changed_qnames),
        },
        candidate_discovery={
            "complete": candidate_complete,
            "local_calls": len(all_head_calls),
            "checked_calls": checked_calls,
        },
        applicability_evidence={
            "changed_entities": len(changed_qnames),
            "public_api_rules": len(context.policy.public_api.get("symbols", ())),
        },
        reason_codes=tuple(sorted({g.reason_code for g in gaps})),
        coverage_gaps=gaps,
        findings=findings,
    )


__all__ = ["run"]
