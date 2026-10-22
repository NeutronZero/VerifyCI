"""Semantic shadow check.

v3.1.10 ships semantic analysis at shadow maturity.  This module performs
candidate discovery only; it does not emit a solver-backed finding.  A
configured semantic scope with relevant constructs is therefore reported as
``semantic_alignment_unresolved`` rather than silently passing.
"""

from __future__ import annotations

import re
from typing import Any

from verifyci.checks.base import CheckContext, gap, make_result
from verifyci.contracts.model import CheckResult, Coverage, Outcome
from verifyci.contracts.names import path_matches_any


def _guard_simple_names(context: CheckContext) -> set[str]:
    names: set[str] = set()
    for rule in context.policy.protected_guards.values():
        for call in rule.get("guard_calls", ()):
            names.add(str(call).split(":")[-1].rsplit(".", 1)[-1])
    for rule in context.policy.protected_errors.values():
        for call in rule.get("raises", ()):
            names.add(str(call).split(":")[-1].rsplit(".", 1)[-1])
    return names


def _effect_names(context: CheckContext) -> set[str]:
    names: set[str] = set()
    for rule in context.policy.protected_guards.values():
        for effect in rule.get("effects", ()):
            names.add(str(effect).split(":", 1)[-1])
    return names


def _relevant_paths(context: CheckContext) -> list[str]:
    paths: set[str] = set()
    for rule in list(context.policy.protected_guards.values()) + list(context.policy.protected_errors.values()):
        patterns = rule.get("paths", ())
        for entry in context.entries:
            for path in entry.changed_paths:
                if not patterns or path_matches_any(patterns, path):
                    paths.add(path)
    return sorted(paths)


def run(context: CheckContext) -> CheckResult:
    if not context.policy.protected_guards and not context.policy.protected_errors:
        return make_result(
            context=context,
            check_id="semantic",
            outcome=Outcome.NOT_APPLICABLE,
            coverage=Coverage.COMPLETE,
            evaluated_scope={},
            scope_enumeration={"complete": True, "configured": False},
            candidate_discovery={"complete": True},
            applicability_evidence={"configured": False},
        )
    paths = _relevant_paths(context)
    if not paths:
        return make_result(
            context=context,
            check_id="semantic",
            outcome=Outcome.NOT_APPLICABLE,
            coverage=Coverage.COMPLETE,
            evaluated_scope={"paths": []},
            scope_enumeration={"complete": True, "relevant_paths": 0},
            candidate_discovery={"complete": True},
            applicability_evidence={"configured": True, "relevant_paths": 0},
        )

    guards = _guard_simple_names(context)
    effects = _effect_names(context)
    candidates: list[dict[str, Any]] = []
    for entry in context.entries:
        path = entry.head_path or entry.base_path
        if path not in paths or not path.endswith(".py"):
            continue
        for side, source in (("base", entry.base_source), ("head", entry.head_source)):
            for line_number, line in enumerate(source.splitlines(), start=1):
                if any(re.search(rf"\b{re.escape(name)}\s*\(", line) for name in guards):
                    candidates.append({"path": path, "side": side, "line": line_number, "kind": "guard"})
                if any(effect in line for effect in effects):
                    candidates.append({"path": path, "side": side, "line": line_number, "kind": "effect"})

    if not candidates:
        return make_result(
            context=context,
            check_id="semantic",
            outcome=Outcome.NOT_APPLICABLE,
            coverage=Coverage.COMPLETE,
            evaluated_scope={"paths": paths},
            scope_enumeration={"complete": True, "relevant_paths": len(paths)},
            candidate_discovery={"complete": True, "candidates": 0},
            applicability_evidence={"configured": True, "guard_or_effect_constructs": 0},
        )

    gaps = [
        gap(
            "semantic_alignment_unresolved",
            {"check_id": "semantic", "path": path, "reason": "solver_not_implemented_in_v3_1_10_shadow"},
        )
        for path in paths
    ]
    return make_result(
        context=context,
        check_id="semantic",
        outcome=Outcome.INCONCLUSIVE,
        coverage=Coverage.PARTIAL,
        evaluated_scope={"paths": paths, "candidate_constructs": candidates[:200]},
        scope_enumeration={"complete": False, "relevant_paths": len(paths)},
        candidate_discovery={"complete": False, "candidates": len(candidates)},
        applicability_evidence={"configured": True, "guard_or_effect_constructs": len(candidates)},
        reason_codes=("semantic_alignment_unresolved",),
        coverage_gaps=gaps,
        diagnostics=(
            {
                "code": "semantic_shadow_only",
                "detail": "solver-backed witnesses are not implemented in v3.1.10; result is advisory",
            },
        ),
    )


__all__ = ["run"]
