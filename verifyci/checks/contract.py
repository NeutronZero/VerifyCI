"""Signature, export, and local call-site compatibility checks."""

from __future__ import annotations

from dataclasses import dataclass
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


def _matches_callee(callee: str, simple: str) -> bool:
    return callee == simple or callee.endswith("." + simple)


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
            if old_sig.params != new_sig.params:
                problems: list[str] = []
                if new_sig.required_positional > old_sig.required_positional:
                    problems.append("required_positional_parameters_added")
                if old_sig.has_vararg and not new_sig.has_vararg:
                    problems.append("varargs_removed")
                if old_sig.has_kwarg and not new_sig.has_kwarg:
                    problems.append("kwargs_removed")
                if old_sig.keyword_names - new_sig.keyword_names:
                    problems.append("keyword_parameters_removed")
                callers = [
                    (path, facts, call)
                    for path, facts, call in all_head_calls
                    if _matches_callee(call.callee, _simple(qname))
                ]
                async_changed = base.is_async != head.is_async
                public = _public_api(context, head)
                if public or (not callers and problems):
                    problems = problems or ["declared_public_api"]
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
                                f"signature of {qname} changed incompatibly"
                                + (": " + ", ".join(problems) if problems else " with its declared public API")
                            ),
                            remediation="Preserve the previous signature or migrate every caller.",
                        )
                    )
                for path, facts, call in callers:
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
                        if not public:
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
        candidates = [
            entity
            for entity in base_entities.values()
            if _matches_callee(call.callee, _simple(entity.qname))
            and entity.qname not in changed_qnames
        ]
        if not candidates:
            continue
        base = candidates[0]
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
    coverage = Coverage.COMPLETE if not gaps else Coverage.PARTIAL
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
        scope_enumeration={"complete": not gaps, "changed_entities": len(changed_qnames)},
        candidate_discovery={
            "complete": not gaps,
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
