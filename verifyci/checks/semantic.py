"""Semantic analysis check backed by symbolic CFG path analysis, Z3 divergence solving, and witness replay.

Covers five declared defect families:
- SEM-GUARD-REMOVED: protected effect reachable without required guard
- SEM-GUARD-WEAKENED: guard threshold/boundary relaxed or nested guard removed
- SEM-GUARD-INVERTED: guard polarity inverted across all paths to effect
- SEM-BINDING-SWAP: argument or tuple return binding swapped without compensation
- SEM-EXCEPTION-REMOVED: policy-protected exception path removed
"""

from __future__ import annotations

import ast
from collections import defaultdict
from typing import Any, Mapping, Sequence, cast
import z3

from verifyci.checks._semantic_replay import (
    ExecutionTrace,
    ReplayResult,
    ReplaySafetyViolation,
    execute_function_isolated,
    execute_ts_function_isolated,
    replay_witness,
    validate_ast_safety as _validate_ast_safety,
)
from verifyci.checks._semantic_symbolic import (
    BudgetExhaustedError,
    SymbolicContext,
    TargetSite,
    UnsupportedControlFlowError,
    UnsupportedExpressionError,
    ast_body_digest as _ast_body_digest,
    ast_to_z3,
    build_enclosing_function_map,
    collect_target_sites,
    extract_model_dict,
    has_null_check,
    node_to_var_name,
)
from verifyci.checks._semantic_ts import analyze_typescript_guard
from verifyci.checks.base import (
    CheckContext,
    budget_exhausted_result,
    check_deadline,
    entity_budget_exceeded,
    gap,
    make_finding,
    make_result,
)
from verifyci.contracts.manifest import CODE_EXTENSIONS
from verifyci.contracts.model import (
    CheckResult,
    Coverage,
    EvidenceKind,
    Finding,
    Outcome,
    WitnessLevel,
)
from verifyci.contracts.names import path_matches_any
from verifyci.scope.parsers import SUPPORTED_CODE_WITH_PYI_EXTENSIONS, path_suffix

_CODE_SUFFIXES = CODE_EXTENSIONS
_SUPPORTED_SUFFIXES = SUPPORTED_CODE_WITH_PYI_EXTENSIONS
_STANDARD_TRANSPARENT_DECORATORS = frozenset(
    {"property", "staticmethod", "classmethod", "abstractmethod"}
)


def _local_identity_decorator_names(tree: ast.AST) -> frozenset[str]:
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args.args
            if len(args) == 1:
                param_name = args[0].arg
                if len(node.body) == 1 and isinstance(node.body[0], ast.Return):
                    ret_val = node.body[0].value
                    if isinstance(ret_val, ast.Name) and ret_val.id == param_name:
                        out.add(node.name)
    return frozenset(out)


def _inconclusive_semantic(
    context: CheckContext,
    *,
    reason_code: str,
    evaluated_scope: Mapping[str, Any],
    candidate_complete: bool,
    applicability_evidence: Mapping[str, Any],
    gap_subject: Mapping[str, Any],
) -> CheckResult:
    return make_result(
        context=context,
        check_id="semantic",
        outcome=Outcome.INCONCLUSIVE,
        coverage=Coverage.PARTIAL,
        evaluated_scope=evaluated_scope,
        scope_enumeration={"complete": True},
        candidate_discovery={"complete": candidate_complete},
        applicability_evidence=applicability_evidence,
        reason_codes=(reason_code,),
        coverage_gaps=[gap(reason_code, {**dict(gap_subject), "reason_code": reason_code})],
    )


def _solver_unknown_result(
    context: CheckContext,
    *,
    path: str,
    symbol: str,
    reason: str,
    line: int | None = None,
) -> CheckResult:
    scope: dict[str, Any] = {"path": path, "symbol": symbol}
    subject: dict[str, Any] = {"path": path, "symbol": symbol, "reason": reason}
    if line is not None:
        scope["line"] = line
        subject["line"] = line
    return _inconclusive_semantic(
        context,
        reason_code="solver_unknown",
        evaluated_scope=scope,
        candidate_complete=True,
        applicability_evidence={"solver_status": "unknown", "reason": reason},
        gap_subject=subject,
    )


def _replay_unconfirmed_result(
    context: CheckContext,
    *,
    path: str,
    symbol: str,
    line: int,
    reason: str,
) -> CheckResult:
    return _inconclusive_semantic(
        context,
        reason_code="semantic_alignment_unresolved",
        evaluated_scope={"path": path, "symbol": symbol, "line": line},
        candidate_complete=True,
        applicability_evidence={"replay_divergence_unconfirmed": True, "detail": reason},
        gap_subject={
            "path": path,
            "line": line,
            "detail": f"solver SAT but concrete replay could not confirm divergence: {reason}",
        },
    )


def _unsupported_construct_result(
    context: CheckContext,
    *,
    path: str,
    symbol: str,
    exc: UnsupportedExpressionError | UnsupportedControlFlowError,
) -> CheckResult:
    gap_reason = (
        "unsupported_syntax_version"
        if isinstance(exc, UnsupportedExpressionError)
        else "semantic_alignment_unresolved"
    )
    return _inconclusive_semantic(
        context,
        reason_code=gap_reason,
        evaluated_scope={"path": path, "symbol": symbol, "line": exc.lineno},
        candidate_complete=False,
        applicability_evidence={"unsupported_construct": True, "detail": str(exc)},
        gap_subject={"path": path, "line": exc.lineno, "detail": str(exc)},
    )


def _semantic_finding(
    context: CheckContext,
    *,
    defect_id: str,
    path: str,
    symbol: str,
    line: int,
    premises: Mapping[str, Any],
    identity: Mapping[str, Any],
    payload_extra: Mapping[str, Any],
    replay_res: ReplayResult,
    message: str,
    remediation: str,
) -> Finding:
    return make_finding(
        context=context,
        check_id="semantic",
        defect_id=defect_id,
        subject={"path": path, "symbol": symbol, "line": line},
        premises=premises,
        evidence_kind=EvidenceKind.SOLVER,
        evidence_payload={
            "identity": dict(identity),
            **dict(payload_extra),
            "solver_status": "sat",
            "replay_confirmed": True,
            "replay_result": replay_res.to_dict(),
            "replay_observation": replay_res.reason,
        },
        message=message,
        remediation=remediation,
        witness_level=WitnessLevel.IR,
    )


def _entry_cache_key(entry: Any, path: str, side: str) -> tuple[str, str, str]:
    blob = entry.base_blob if side == "base" else entry.head_blob
    return (blob or "", path, side)


def _get_entry_tree(
    parsed_trees: dict[tuple[str, str, str], ast.Module],
    entry: Any,
    path: str,
    side: str,
) -> ast.Module:
    key = _entry_cache_key(entry, path, side)
    if key in parsed_trees:
        return parsed_trees[key]
    src = entry.base_source if side == "base" else entry.head_source
    tree = ast.parse(src)
    parsed_trees[key] = tree
    return tree


def _collect_functions_by_name(
    tree: ast.AST,
) -> dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]]:
    funcs: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.setdefault(node.name, []).append(node)
    return funcs


def _pair_target_sites(
    b_fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    h_fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    key: str,
    cache: dict[str, tuple[list[TargetSite], list[TargetSite]]],
    context: CheckContext,
    counter: list[int],
) -> tuple[list[TargetSite], list[TargetSite]]:
    cached = cache.get(key)
    if cached is not None:
        return cached
    ctx_sym = SymbolicContext()
    b_sites = collect_target_sites(
        b_fn_node.body,
        ctx_sym,
        budget=context.budget,
        path_counter=counter,
        deadline=context.deadline,
    )
    h_sites = collect_target_sites(
        h_fn_node.body,
        ctx_sym,
        budget=context.budget,
        path_counter=counter,
        deadline=context.deadline,
    )
    cache[key] = (b_sites, h_sites)
    return b_sites, h_sites


def _check_python_integrity(
    context: CheckContext,
    code_entries: Sequence[Any],
    parsed_trees: dict[tuple[str, str, str], ast.Module],
) -> CheckResult | None:
    for entry in code_entries:
        path = entry.head_path or entry.base_path
        if not path.endswith((".py", ".pyi")):
            continue
        for side, src in (("base", entry.base_source), ("head", entry.head_source)):
            if not src:
                continue
            try:
                parsed_trees[_entry_cache_key(entry, path, side)] = ast.parse(src)
            except SyntaxError as exc:
                return _inconclusive_semantic(
                    context,
                    reason_code="parse_error",
                    evaluated_scope={"path": path, "side": side},
                    candidate_complete=False,
                    applicability_evidence={"parse_error": True},
                    gap_subject={"path": path, "side": side, "detail": str(exc)},
                )

    for entry in code_entries:
        path = entry.head_path or entry.base_path
        if not (path.endswith((".py", ".pyi")) and entry.head_source):
            continue
        tree = _get_entry_tree(parsed_trees, entry, path, "head")
        identity_decorators = _local_identity_decorator_names(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                callee_name = ""
                if isinstance(node.func, ast.Name):
                    callee_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    callee_name = node.func.attr
                if callee_name in ("eval", "exec", "__import__", "getattr", "setattr"):
                    return _inconclusive_semantic(
                        context,
                        reason_code="dynamic_call",
                        evaluated_scope={"path": path},
                        candidate_complete=False,
                        applicability_evidence={"dynamic_dispatch": True},
                        gap_subject={"path": path, "line": node.lineno, "token": f"{callee_name}(...)"},
                    )
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    dec_name = ""
                    if isinstance(dec, ast.Name):
                        dec_name = dec.id
                    elif isinstance(dec, ast.Attribute):
                        dec_name = dec.attr
                    elif isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Name):
                            dec_name = dec.func.id
                        elif isinstance(dec.func, ast.Attribute):
                            dec_name = dec.func.attr
                    is_transparent = (
                        dec_name in _STANDARD_TRANSPARENT_DECORATORS
                        or dec_name in context.policy.transparent_decorators
                        or dec_name in identity_decorators
                    )
                    if not is_transparent and dec_name:
                        return _inconclusive_semantic(
                            context,
                            reason_code="unknown_decorator",
                            evaluated_scope={"path": path},
                            candidate_complete=False,
                            applicability_evidence={"unknown_decorator": True},
                            gap_subject={"path": path, "line": dec.lineno, "decorator": dec_name},
                        )
    return None


def _analyze_ts_entry(
    context: CheckContext,
    entry: Any,
    path: str,
    findings: list[Finding],
) -> CheckResult | None:
    b_src = entry.base_source
    h_src = entry.head_source
    mod_name = path.rsplit(".", 1)[0].replace("\\", "/")
    for rule_id, rule in context.policy.protected_guards.items():
        paths = rule.get("paths", ())
        if paths and not path_matches_any(paths, path):
            continue
        for eff in rule.get("effects", ()):
            if eff not in b_src or eff not in h_src:
                continue
            try:
                analysis = analyze_typescript_guard(
                    b_src, h_src, eff, solver_rlimit=context.budget.solver_rlimit
                )
            except BudgetExhaustedError as exc_budget:
                return _inconclusive_semantic(
                    context,
                    reason_code="solver_unknown",
                    evaluated_scope={"path": path},
                    candidate_complete=True,
                    applicability_evidence={"solver_status": "unknown", "detail": str(exc_budget)},
                    gap_subject={"path": path, "detail": str(exc_budget)},
                )
            if analysis is None:
                continue
            if len(analysis) == 3 and analysis[0] == "unsupported_operator":
                return _inconclusive_semantic(
                    context,
                    reason_code="semantic_alignment_unresolved",
                    evaluated_scope={"path": path, "line": analysis[2]},
                    candidate_complete=True,
                    applicability_evidence={"unsupported_ts_guard_operator": analysis[1]},
                    gap_subject={
                        "check_id": "semantic",
                        "path": path,
                        "line": analysis[2],
                        "detail": f"unsupported_ts_guard_operator:{analysis[1]}",
                    },
                )
            b_fn_name, h_fn_name, phi_base, phi_head, model_values, line_num, guard_desc = analysis
            fn_name = h_fn_name or b_fn_name
            symbol = f"{mod_name}:{fn_name}"
            replay_res = replay_witness(
                base_src=b_src,
                head_src=h_src,
                fn_name=fn_name,
                defect_family="SEM-GUARD-REMOVED",
                target=eff,
                model_values=model_values,
                source_identity=symbol,
                language="typescript",
                phi_base=phi_base,
                phi_head=phi_head,
                solver_model=None,
            )
            if not replay_res.confirmed:
                return _replay_unconfirmed_result(
                    context, path=path, symbol=symbol, line=line_num, reason=replay_res.reason
                )
            findings.append(
                _semantic_finding(
                    context,
                    defect_id="SEM-GUARD-REMOVED",
                    path=path,
                    symbol=symbol,
                    line=line_num,
                    premises={"effect": eff, "rule_id": rule_id, "guard_removed": True},
                    identity={"symbol": symbol, "effect": eff},
                    payload_extra={"effect": eff},
                    replay_res=replay_res,
                    message=f"protected effect {eff} reached without {guard_desc} in {symbol}",
                    remediation=(
                        f"Restore role check protecting {eff}."
                        if "role" in guard_desc
                        else f"Restore protecting guard for {eff}."
                    ),
                )
            )
    return None


def _analyze_python_entry(
    context: CheckContext,
    entry: Any,
    path: str,
    parsed_trees: dict[tuple[str, str, str], ast.Module],
    path_counter: list[int],
    findings: list[Finding],
) -> CheckResult | None:
    b_tree = _get_entry_tree(parsed_trees, entry, path, "base")
    h_tree = _get_entry_tree(parsed_trees, entry, path, "head")
    mod_name = path.replace(".py", "").replace("\\", "/")

    b_funcs = _collect_functions_by_name(b_tree)
    h_funcs = _collect_functions_by_name(h_tree)
    b_enclosing_map = build_enclosing_function_map(b_tree)
    h_enclosing_map = build_enclosing_function_map(h_tree)

    # Category 1: Return Tuple Binding Swaps
    b_returns = [
        n for n in ast.walk(b_tree) if isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple)
    ]
    h_returns = [
        n for n in ast.walk(h_tree) if isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple)
    ]
    if b_returns and h_returns:
        b_ret = b_returns[0]
        b_fn_name = b_enclosing_map.get(id(b_ret), "")
        h_ret = next(
            (r for r in h_returns if h_enclosing_map.get(id(r), "") == b_fn_name),
            None,
        )
        b_elts = [ast.dump(e, include_attributes=False) for e in b_ret.value.elts]  # ty: ignore[unresolved-attribute]
        h_elts = [ast.dump(e, include_attributes=False) for e in (h_ret.value.elts if h_ret is not None else ())]  # ty: ignore[unresolved-attribute]
        if h_ret is not None and len(b_elts) >= 2 and b_elts != h_elts and sorted(b_elts) == sorted(h_elts):
            fn_name = b_fn_name
            symbol = f"{mod_name}:{fn_name}"
            ctx_sym = SymbolicContext()
            b_vars = [ctx_sym.get_var(node_to_var_name(e), "string") for e in b_ret.value.elts]  # ty: ignore[unresolved-attribute]
            h_vars = [ctx_sym.get_var(node_to_var_name(e), "string") for e in h_ret.value.elts]  # ty: ignore[unresolved-attribute]
            solver = z3.Solver()
            solver.set("rlimit", context.budget.solver_rlimit)
            diff_pairs = [bv != hv for bv, hv in zip(b_vars, h_vars) if bv is not hv]
            solver.add(z3.Or(*diff_pairs) if diff_pairs else z3.BoolVal(False))
            solver_res = solver.check()
            if solver_res == z3.unknown:
                return _solver_unknown_result(
                    context, path=path, symbol=symbol, reason=solver.reason_unknown(), line=h_ret.lineno
                )
            if solver_res == z3.sat:
                model = extract_model_dict(solver.model())
                fn_node = (h_funcs.get(fn_name) or [None])[0]
                if fn_node:
                    for arg in fn_node.args.args:
                        if arg.arg not in model and not any(k.startswith(f"{arg.arg}.") for k in model):
                            model[arg.arg] = f"val_{arg.arg}"
                replay_res = replay_witness(
                    base_src=entry.base_source,
                    head_src=entry.head_source,
                    fn_name=fn_name,
                    defect_family="SEM-BINDING-SWAP",
                    target="return",
                    model_values=model,
                    source_identity=symbol,
                )
                if not replay_res.confirmed:
                    return _replay_unconfirmed_result(
                        context, path=path, symbol=symbol, line=h_ret.lineno, reason=replay_res.reason
                    )
                findings.append(
                    _semantic_finding(
                        context,
                        defect_id="SEM-BINDING-SWAP",
                        path=path,
                        symbol=symbol,
                        line=h_ret.lineno,
                        premises={"return_swap": True, "base_tuple": b_elts, "head_tuple": h_elts},
                        identity={"symbol": symbol, "return_swap": True},
                        payload_extra={"return_swap": True},
                        replay_res=replay_res,
                        message=f"returned tuple element bindings swapped in {symbol}",
                        remediation="Restore original tuple return order.",
                    )
                )

    # Category 2: Call Argument Binding Swaps
    b_calls = [n for n in ast.walk(b_tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    h_calls_by_func: dict[str, list[ast.Call]] = defaultdict(list)
    for n in ast.walk(h_tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
            h_calls_by_func[n.func.id].append(n)

    for bc in b_calls:
        callee_name = cast(ast.Name, bc.func).id
        candidate_hcs = h_calls_by_func.get(callee_name)
        if not candidate_hcs or len(bc.args) < 2:
            continue
        b_args = [ast.dump(a, include_attributes=False) for a in bc.args]
        b_args_sorted = sorted(b_args)
        for hc in candidate_hcs:
            if len(bc.args) != len(hc.args):
                continue
            h_args = [ast.dump(a, include_attributes=False) for a in hc.args]
            if b_args == h_args or b_args_sorted != sorted(h_args):
                continue
            compensated = False
            if callee_name in b_funcs and callee_name in h_funcs:
                bf_params = [a.arg for a in b_funcs[callee_name][0].args.args]
                hf_params = [a.arg for a in h_funcs[callee_name][0].args.args]
                if bf_params != hf_params and sorted(bf_params) == sorted(hf_params):
                    compensated = True
            if compensated:
                continue

            caller_fn = h_enclosing_map.get(id(hc), "")
            symbol = f"{mod_name}:{caller_fn}"
            ctx_sym = SymbolicContext()
            b_vars = [ctx_sym.get_var(node_to_var_name(a), "string") for a in bc.args]
            h_vars = [ctx_sym.get_var(node_to_var_name(a), "string") for a in hc.args]
            solver = z3.Solver()
            solver.set("rlimit", context.budget.solver_rlimit)
            diff_pairs = [bv != hv for bv, hv in zip(b_vars, h_vars) if bv is not hv]
            solver.add(z3.Or(*diff_pairs) if diff_pairs else z3.BoolVal(False))
            solver_res = solver.check()
            if solver_res == z3.unknown:
                return _solver_unknown_result(
                    context, path=path, symbol=symbol, reason=solver.reason_unknown(), line=hc.lineno
                )
            if solver_res == z3.sat:
                model = extract_model_dict(solver.model())
                fn_node = (h_funcs.get(caller_fn) or [None])[0]
                if fn_node:
                    for arg in fn_node.args.args:
                        if arg.arg not in model and not any(k.startswith(f"{arg.arg}.") for k in model):
                            model[arg.arg] = (
                                100 if "amount" in arg.arg or "count" in arg.arg else f"val_{arg.arg}"
                            )
                replay_res = replay_witness(
                    base_src=entry.base_source,
                    head_src=entry.head_source,
                    fn_name=caller_fn,
                    defect_family="SEM-BINDING-SWAP",
                    target=callee_name,
                    model_values=model,
                    source_identity=symbol,
                )
                if not replay_res.confirmed:
                    return _replay_unconfirmed_result(
                        context, path=path, symbol=symbol, line=hc.lineno, reason=replay_res.reason
                    )
                findings.append(
                    _semantic_finding(
                        context,
                        defect_id="SEM-BINDING-SWAP",
                        path=path,
                        symbol=symbol,
                        line=hc.lineno,
                        premises={"callee": callee_name, "base_args": b_args, "head_args": h_args},
                        identity={"symbol": symbol, "callee": callee_name},
                        payload_extra={"callee": callee_name},
                        replay_res=replay_res,
                        message=f"argument bindings swapped at call to {callee_name} in {symbol}",
                        remediation="Restore original argument binding order.",
                    )
                )

    fn_sites_cache: dict[str, tuple[list[TargetSite], list[TargetSite]]] = {}

    def _paired_functions(
        used_head: set[int],
    ):
        for b_name, b_fn_list in b_funcs.items():
            for b_fn in b_fn_list:
                if expired := check_deadline(context, "semantic"):
                    yield None, None, expired
                    return
                h_fn = next(
                    (cand for cand in h_funcs.get(b_name, ()) if id(cand) not in used_head),
                    None,
                )
                if h_fn is None:
                    continue
                used_head.add(id(h_fn))
                yield b_fn, h_fn, None

    # Category 3: Protected Exception Removed
    for rule_id, rule in context.policy.protected_errors.items():
        paths = rule.get("paths", ())
        if paths and not path_matches_any(paths, path):
            continue
        for exc in rule.get("raises", ()):
            used_h_cat3: set[int] = set()
            for b_fn, h_fn, expired in _paired_functions(used_h_cat3):
                if expired is not None:
                    return expired
                assert b_fn is not None and h_fn is not None
                try:
                    b_sites, h_sites = _pair_target_sites(
                        b_fn, h_fn, f"{b_fn.name}:{b_fn.lineno}", fn_sites_cache, context, path_counter
                    )
                except BudgetExhaustedError as exc_budget:
                    return budget_exhausted_result(context, "semantic", str(exc_budget))
                except (UnsupportedExpressionError, UnsupportedControlFlowError) as exc_unsupp:
                    return _unsupported_construct_result(
                        context, path=path, symbol=f"{mod_name}:{b_fn.name}", exc=exc_unsupp
                    )

                b_raise_conds = [s.condition for s in b_sites if s.kind == "raise" and s.target_name == exc]
                h_raise_conds = [s.condition for s in h_sites if s.kind == "raise" and s.target_name == exc]
                if not (b_raise_conds and not h_raise_conds):
                    continue

                symbol = f"{mod_name}:{h_fn.name}"
                phi_base_raise = z3.Or(*b_raise_conds) if len(b_raise_conds) > 1 else b_raise_conds[0]
                phi_head_raise = z3.BoolVal(False)
                solver = z3.Solver()
                solver.set("rlimit", context.budget.solver_rlimit)
                solver.add(z3.And(phi_base_raise, z3.Not(phi_head_raise)))
                solver_res = solver.check()
                if solver_res == z3.unknown:
                    return _solver_unknown_result(
                        context, path=path, symbol=symbol, reason=solver.reason_unknown()
                    )
                if solver_res == z3.sat:
                    branch_line = next(
                        (stmt.lineno for stmt in h_fn.body if isinstance(stmt, ast.If)), h_fn.lineno
                    )
                    model = extract_model_dict(solver.model())
                    for arg in h_fn.args.args:
                        if arg.arg not in model and not any(k.startswith(f"{arg.arg}.") for k in model):
                            model[arg.arg] = ""
                    replay_res = replay_witness(
                        base_src=entry.base_source,
                        head_src=entry.head_source,
                        fn_name=h_fn.name,
                        defect_family="SEM-EXCEPTION-REMOVED",
                        target=exc,
                        model_values=model,
                        source_identity=symbol,
                        phi_base=phi_base_raise,
                        phi_head=phi_head_raise,
                        solver_model=solver.model(),
                    )
                    if not replay_res.confirmed:
                        return _replay_unconfirmed_result(
                            context, path=path, symbol=symbol, line=branch_line, reason=replay_res.reason
                        )
                    findings.append(
                        _semantic_finding(
                            context,
                            defect_id="SEM-EXCEPTION-REMOVED",
                            path=path,
                            symbol=symbol,
                            line=branch_line,
                            premises={"exception": exc, "rule_id": rule_id, "removed_in_head": True},
                            identity={"symbol": symbol, "exception": exc},
                            payload_extra={"exception": exc},
                            replay_res=replay_res,
                            message=f"policy-protected exception {exc} was removed in {symbol}",
                            remediation="Preserve protected exception path.",
                        )
                    )

    # Category 4: Protected Guards (REMOVED / WEAKENED / INVERTED)
    for rule_id, rule in context.policy.protected_guards.items():
        paths = rule.get("paths", ())
        if paths and not path_matches_any(paths, path):
            continue
        for eff in rule.get("effects", ()):
            used_h_cat4: set[int] = set()
            for b_fn, h_fn, expired in _paired_functions(used_h_cat4):
                if expired is not None:
                    return expired
                assert b_fn is not None and h_fn is not None
                try:
                    b_sites, h_sites = _pair_target_sites(
                        b_fn, h_fn, f"{b_fn.name}:{b_fn.lineno}", fn_sites_cache, context, path_counter
                    )
                except BudgetExhaustedError as exc_budget:
                    return budget_exhausted_result(context, "semantic", str(exc_budget))
                except (UnsupportedExpressionError, UnsupportedControlFlowError) as exc_unsupp:
                    return _unsupported_construct_result(
                        context, path=path, symbol=f"{mod_name}:{b_fn.name}", exc=exc_unsupp
                    )

                b_eff_sites = [s for s in b_sites if s.kind == "call" and s.target_name == eff]
                h_eff_sites = [s for s in h_sites if s.kind == "call" and s.target_name == eff]
                if not b_eff_sites or not h_eff_sites:
                    continue

                symbol = f"{mod_name}:{h_fn.name}"
                phi_base_eff = z3.Or(*[s.condition for s in b_eff_sites]) if len(b_eff_sites) > 1 else b_eff_sites[0].condition
                phi_head_eff = z3.Or(*[s.condition for s in h_eff_sites]) if len(h_eff_sites) > 1 else h_eff_sites[0].condition

                solver = z3.Solver()
                solver.set("rlimit", context.budget.solver_rlimit)
                solver.add(z3.And(phi_head_eff, z3.Not(phi_base_eff)))
                solver_res = solver.check()
                if solver_res == z3.unsat:
                    continue
                if solver_res == z3.unknown:
                    return _solver_unknown_result(
                        context, path=path, symbol=symbol, reason=solver.reason_unknown()
                    )

                z3_model = solver.model()
                model_dict = extract_model_dict(z3_model)
                b_has_null, null_var = has_null_check(b_fn)
                h_has_null, _ = has_null_check(h_fn)
                null_check_removed = b_has_null and not h_has_null
                if null_check_removed and null_var:
                    model_dict = {k: v for k, v in model_dict.items() if not k.startswith(f"{null_var}.")}
                    model_dict[null_var] = None

                replay_res = replay_witness(
                    base_src=entry.base_source,
                    head_src=entry.head_source,
                    fn_name=h_fn.name,
                    defect_family="SEM-GUARD-REMOVED",
                    target=eff,
                    model_values=model_dict,
                    source_identity=symbol,
                    phi_base=phi_base_eff,
                    phi_head=phi_head_eff,
                    solver_model=z3_model,
                )
                if not replay_res.confirmed:
                    return _replay_unconfirmed_result(
                        context,
                        path=path,
                        symbol=symbol,
                        line=h_eff_sites[0].line,
                        reason=replay_res.reason,
                    )

                b_first_test = next((s.test for s in b_fn.body if isinstance(s, ast.If)), None)
                h_first_test = next((s.test for s in h_fn.body if isinstance(s, ast.If)), None)
                is_inverted = bool(
                    b_first_test
                    and h_first_test
                    and (
                        (
                            isinstance(b_first_test, ast.UnaryOp)
                            and isinstance(b_first_test.op, ast.Not)
                            and ast.dump(b_first_test.operand, include_attributes=False)
                            == ast.dump(h_first_test, include_attributes=False)
                        )
                        or (
                            isinstance(h_first_test, ast.UnaryOp)
                            and isinstance(h_first_test.op, ast.Not)
                            and ast.dump(h_first_test.operand, include_attributes=False)
                            == ast.dump(b_first_test, include_attributes=False)
                        )
                    )
                )
                if is_inverted:
                    findings.append(
                        _semantic_finding(
                            context,
                            defect_id="SEM-GUARD-INVERTED",
                            path=path,
                            symbol=symbol,
                            line=h_eff_sites[0].line - 1 if h_eff_sites[0].line > 1 else 2,
                            premises={"effect": eff, "rule_id": rule_id, "polarity_inverted": True},
                            identity={"symbol": symbol, "effect": eff},
                            payload_extra={"effect": eff},
                            replay_res=replay_res,
                            message=f"polarity of guard protecting {eff} inverted in {symbol}",
                            remediation="Restore original polarity of protecting condition.",
                        )
                    )
                    continue

                b_enc_len = len(b_eff_sites[0].enclosing_conditions)
                h_enc_len = len(h_eff_sites[0].enclosing_conditions)
                uncond_sites = [s for s in h_eff_sites if len(s.enclosing_conditions) == 0]
                if uncond_sites or null_check_removed:
                    msg = (
                        f"null check guard removed for effect {eff} in {symbol}"
                        if null_check_removed
                        else f"protected effect {eff} reached without required guard in {symbol}"
                    )
                    rem = (
                        "Restore null check before buffer commit."
                        if null_check_removed
                        else "Restore the protecting guard condition or remove reachable effect."
                    )
                    line_w = (
                        uncond_sites[0].line
                        if uncond_sites
                        else (h_first_test.lineno if (null_check_removed and h_first_test) else h_eff_sites[0].line)
                    )
                    findings.append(
                        _semantic_finding(
                            context,
                            defect_id="SEM-GUARD-REMOVED",
                            path=path,
                            symbol=symbol,
                            line=line_w,
                            premises={"effect": eff, "rule_id": rule_id, "guard_removed": True},
                            identity={"symbol": symbol, "effect": eff},
                            payload_extra={"effect": eff},
                            replay_res=replay_res,
                            message=msg,
                            remediation=rem,
                        )
                    )
                    continue

                if b_enc_len > h_enc_len and h_enc_len > 0:
                    b_if_tests = [s.test for s in ast.walk(b_fn) if isinstance(s, ast.If)]
                    h_if_tests = [s.test for s in ast.walk(h_fn) if isinstance(s, ast.If)]
                    h_dumps = {ast.dump(t, include_attributes=False) for t in h_if_tests}
                    missing_conds = [
                        t for t in b_if_tests if ast.dump(t, include_attributes=False) not in h_dumps
                    ]
                    cond_text = ast.unparse(missing_conds[0]) if missing_conds else "nested guard"
                    msg = f"nested guard {cond_text} removed for effect {eff} in {symbol}"
                    rem = "Restore all nested protecting guard conditions."
                    line_witness = h_eff_sites[0].line
                else:
                    msg = f"guard boundary relaxed for effect {eff} in {symbol}"
                    rem = "Restore original guard threshold condition."
                    line_witness = h_first_test.lineno if h_first_test else h_eff_sites[0].line

                findings.append(
                    _semantic_finding(
                        context,
                        defect_id="SEM-GUARD-WEAKENED",
                        path=path,
                        symbol=symbol,
                        line=line_witness,
                        premises={"effect": eff, "rule_id": rule_id, "guard_weakened": True},
                        identity={"symbol": symbol, "effect": eff},
                        payload_extra={"effect": eff},
                        replay_res=replay_res,
                        message=msg,
                        remediation=rem,
                    )
                )
    return None


def run(context: CheckContext) -> CheckResult:
    if expired := check_deadline(context, "semantic"):
        return expired
    entities_over_budget, enumerated_entities = entity_budget_exceeded(context)
    if entities_over_budget:
        return budget_exhausted_result(
            context,
            "semantic",
            f"max_entities limit exceeded ({enumerated_entities} > {context.budget.max_entities})",
        )

    code_entries = []
    unsupported_gaps: list[Any] = []
    unsupported_languages: set[str] = set()
    for entry in context.entries:
        path = entry.head_path or entry.base_path
        if not path or entry.is_binary or entry.is_submodule or entry.is_lfs:
            continue
        suffix = path_suffix(path)
        if suffix not in _CODE_SUFFIXES:
            continue
        if suffix not in _SUPPORTED_SUFFIXES:
            lang = suffix or "unknown"
            unsupported_languages.add(lang)
            unsupported_gaps.append(
                gap(
                    "unsupported_language",
                    {"path": path, "language": lang, "reason_code": "unsupported_language"},
                )
            )
            continue
        code_entries.append(entry)

    if unsupported_gaps and not code_entries:
        return make_result(
            context=context,
            check_id="semantic",
            outcome=Outcome.INCONCLUSIVE,
            coverage=Coverage.UNKNOWN,
            evaluated_scope={
                "paths": sorted({str(g.subject.get("path")) for g in unsupported_gaps}),
                "languages": sorted(unsupported_languages),
            },
            scope_enumeration={"complete": False, "languages": sorted(unsupported_languages)},
            candidate_discovery={"complete": False},
            applicability_evidence={"language_supported": False},
            reason_codes=("unsupported_language",),
            coverage_gaps=unsupported_gaps,
        )

    if not code_entries:
        return make_result(
            context=context,
            check_id="semantic",
            outcome=Outcome.NOT_APPLICABLE,
            coverage=Coverage.COMPLETE,
            evaluated_scope={},
            scope_enumeration={"complete": True, "relevant_paths": 0},
            candidate_discovery={"complete": True},
            applicability_evidence={"configured": True, "relevant_paths": 0},
        )

    parsed_trees: dict[tuple[str, str, str], ast.Module] = {}
    if integrity_res := _check_python_integrity(context, code_entries, parsed_trees):
        return integrity_res

    has_body_change = False
    for entry in code_entries:
        path = entry.head_path or entry.base_path
        if path.endswith((".py", ".pyi")):
            b_tree = _get_entry_tree(parsed_trees, entry, path, "base")
            h_tree = _get_entry_tree(parsed_trees, entry, path, "head")
            if _ast_body_digest(b_tree) != _ast_body_digest(h_tree):
                has_body_change = True
        elif path.endswith((".ts", ".tsx", ".js", ".jsx")):
            if entry.base_source.strip() != entry.head_source.strip():
                has_body_change = True

    if not has_body_change:
        return make_result(
            context=context,
            check_id="semantic",
            outcome=Outcome.NOT_APPLICABLE,
            coverage=Coverage.COMPLETE,
            evaluated_scope={},
            scope_enumeration={"complete": True, "body_changes": 0},
            candidate_discovery={"complete": True, "candidates": 0},
            applicability_evidence={"body_changes": False},
        )

    findings: list[Finding] = []
    for entry in code_entries:
        if expired := check_deadline(context, "semantic"):
            return expired
        path = entry.head_path or entry.base_path
        if path.endswith((".ts", ".tsx", ".js", ".jsx")) and entry.base_source and entry.head_source:
            if early := _analyze_ts_entry(context, entry, path, findings):
                return early

    path_counter: list[int] = [0]
    for entry in code_entries:
        if expired := check_deadline(context, "semantic"):
            return expired
        path = entry.head_path or entry.base_path
        if path.endswith((".py", ".pyi")) and entry.base_source and entry.head_source:
            if early := _analyze_python_entry(
                context, entry, path, parsed_trees, path_counter, findings
            ):
                return early

    evaluated_paths = [e.head_path or e.base_path for e in code_entries]
    unsupported_codes = ("unsupported_language",) if unsupported_gaps else ()
    if findings:
        return make_result(
            context=context,
            check_id="semantic",
            outcome=Outcome.FAIL,
            coverage=Coverage.COMPLETE if not unsupported_gaps else Coverage.PARTIAL,
            evaluated_scope={"paths": evaluated_paths},
            scope_enumeration={
                "complete": not unsupported_gaps,
                "analyzed_languages": ["python", "typescript"],
            },
            candidate_discovery={"complete": True, "candidates": len(findings)},
            applicability_evidence={"configured": True},
            reason_codes=unsupported_codes,
            coverage_gaps=unsupported_gaps,
            findings=findings,
        )
    if unsupported_gaps:
        return make_result(
            context=context,
            check_id="semantic",
            outcome=Outcome.INCONCLUSIVE,
            coverage=Coverage.PARTIAL,
            evaluated_scope={"paths": evaluated_paths},
            scope_enumeration={
                "complete": False,
                "languages": sorted(unsupported_languages),
                "analyzed_languages": ["python", "typescript"],
            },
            candidate_discovery={"complete": True, "candidates": 0},
            applicability_evidence={"configured": True, "language_supported": False},
            reason_codes=unsupported_codes,
            coverage_gaps=unsupported_gaps,
        )
    return make_result(
        context=context,
        check_id="semantic",
        outcome=Outcome.PASS,
        coverage=Coverage.COMPLETE,
        evaluated_scope={"paths": evaluated_paths},
        scope_enumeration={"complete": True},
        candidate_discovery={"complete": True, "candidates": 0},
        applicability_evidence={"configured": True},
    )


__all__ = [
    "BudgetExhaustedError",
    "ExecutionTrace",
    "ReplayResult",
    "ReplaySafetyViolation",
    "SymbolicContext",
    "TargetSite",
    "UnsupportedControlFlowError",
    "UnsupportedExpressionError",
    "_ast_body_digest",
    "_validate_ast_safety",
    "ast_to_z3",
    "collect_target_sites",
    "execute_function_isolated",
    "execute_ts_function_isolated",
    "replay_witness",
    "run",
]
