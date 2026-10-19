from __future__ import annotations

import ast
import msgspec
import re
import time
from typing import Any

from verifyci_v2.contracts.attestation import CounterexampleWitness, VerificationFinding
from verifyci_v2.contracts.canonical import content_digest_hex
from verifyci_v2.contracts.redaction import redact_in_place_mapping

try:
    import z3 as _z3_mod  # type: ignore[import-untyped]
except ImportError:
    _z3_mod = None


class _InlineAssignTransformer(ast.NodeTransformer):
    def __init__(self, env: dict[str, ast.AST]):
        self.env = env

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if node.id in self.env and isinstance(node.ctx, ast.Load):
            return self.env[node.id]
        return node


def _ast_to_z3_val(
    node: ast.AST,
    z3_vars: dict[str, Any],
    z3_mod: Any,
    pctx: Any | None = None,
) -> Any:
    """Translate a supported scalar expression into the canonical ``PyVal`` sort.

    The optional ``pctx`` is supplied by the caller and owns the Z3 context and
    datatype. Unsupported or dynamically typed operations return ``None`` so
    intent analysis abstains rather than coercing unrelated Python values into
    integers or Booleans.
    """
    if z3_mod is None:
        return None
    try:
        from verifyci_v2.symbolic.z3_prover import (
            _PyVal,
            _Z3ProofContext,
            _encode_py_eq,
        )
        if pctx is None:
            pctx = _Z3ProofContext(timeout_ms=2000)
    except Exception:
        return None

    pv = pctx.pyval
    if isinstance(node, ast.Name):
        value = z3_vars.get(node.id)
        if isinstance(value, _PyVal):
            return value
        # Parameters are unconstrained runtime Python values. Do not assume an
        # annotation makes them integers, since Python does not enforce hints.
        term = z3_mod.Const(node.id, pv)
        result = _PyVal(term, None)
        z3_vars[node.id] = result
        return result

    if isinstance(node, ast.Constant):
        if node.value is None:
            return pctx.none()
        if isinstance(node.value, bool):
            return pctx.boolean(node.value)
        if isinstance(node.value, int):
            return pctx.integer(node.value)
        if isinstance(node.value, str):
            return pctx.string(node.value)
        return None

    if isinstance(node, ast.UnaryOp):
        operand = _ast_to_z3_val(node.operand, z3_vars, z3_mod, pctx)
        if operand is None:
            return None
        if isinstance(node.op, ast.Not):
            return pctx.boolean(z3_mod.Not(pctx.truth(operand)))
        if operand.kind not in ("INT", "BOOL"):
            return None
        numeric = pctx.numeric(operand)
        if isinstance(node.op, ast.USub):
            return pctx.integer(-numeric)
        if isinstance(node.op, ast.UAdd):
            return pctx.integer(numeric)
        return None

    if isinstance(node, ast.BinOp):
        lhs = _ast_to_z3_val(node.left, z3_vars, z3_mod, pctx)
        rhs = _ast_to_z3_val(node.right, z3_vars, z3_mod, pctx)
        if lhs is None or rhs is None:
            return None
        if isinstance(node.op, ast.Add) and (lhs.kind == "STR" or rhs.kind == "STR"):
            if lhs.kind == rhs.kind == "STR":
                return pctx.string(z3_mod.Concat(pv.str_val(lhs.term), pv.str_val(rhs.term)))
            return None
        if lhs.kind in ("NONE", "STR") or rhs.kind in ("NONE", "STR"):
            return None
        a, b = pctx.numeric(lhs), pctx.numeric(rhs)
        if isinstance(node.op, ast.Add):
            return pctx.integer(a + b)
        if isinstance(node.op, ast.Sub):
            return pctx.integer(a - b)
        if isinstance(node.op, ast.Mult):
            return pctx.integer(a * b)
        return None

    if isinstance(node, ast.Compare):
        left_node = node.left
        lhs = _ast_to_z3_val(left_node, z3_vars, z3_mod, pctx)
        if lhs is None:
            return None
        comparisons = []
        for op, right_node in zip(node.ops, node.comparators):
            rhs = _ast_to_z3_val(right_node, z3_vars, z3_mod, pctx)
            if rhs is None:
                return None
            if isinstance(op, (ast.Eq, ast.NotEq)):
                eq = _encode_py_eq(lhs, rhs, pctx)
                comparisons.append(eq if isinstance(op, ast.Eq) else z3_mod.Not(eq))
            elif isinstance(op, (ast.Is, ast.IsNot)):
                left_singleton = lhs.kind in ("NONE", "BOOL") or (
                    isinstance(left_node, ast.Constant)
                    and (left_node.value is None or isinstance(left_node.value, bool))
                )
                right_singleton = rhs.kind in ("NONE", "BOOL") or (
                    isinstance(right_node, ast.Constant)
                    and (right_node.value is None or isinstance(right_node.value, bool))
                )
                if not (left_singleton or right_singleton):
                    return None
                ident = lhs.term == rhs.term
                comparisons.append(ident if isinstance(op, ast.Is) else z3_mod.Not(ident))
            elif isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
                if lhs.kind == rhs.kind == "STR":
                    a, b = pv.str_val(lhs.term), pv.str_val(rhs.term)
                elif lhs.kind not in ("NONE", "STR") and rhs.kind not in ("NONE", "STR"):
                    a, b = pctx.numeric(lhs), pctx.numeric(rhs)
                else:
                    return None
                if isinstance(op, ast.Lt):
                    comparisons.append(a < b)
                elif isinstance(op, ast.LtE):
                    comparisons.append(a <= b)
                elif isinstance(op, ast.Gt):
                    comparisons.append(a > b)
                else:
                    comparisons.append(a >= b)
            else:
                return None
            lhs, left_node = rhs, right_node
        if not comparisons:
            return pctx.boolean(True)
        result = z3_mod.And(*comparisons) if len(comparisons) > 1 else comparisons[0]
        return pctx.boolean(result)

    if isinstance(node, ast.BoolOp):
        vals = [_ast_to_z3_val(v, z3_vars, z3_mod, pctx) for v in node.values]
        if any(value is None for value in vals):
            return None
        conditions = [pctx.truth(value) for value in vals]
        if isinstance(node.op, ast.And):
            return pctx.boolean(z3_mod.And(*conditions))
        if isinstance(node.op, ast.Or):
            return pctx.boolean(z3_mod.Or(*conditions))
        return None

    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        args = [_ast_to_z3_val(arg, z3_vars, z3_mod, pctx) for arg in node.args]
        if any(arg is None for arg in args):
            return None
        if node.func.id == "abs" and len(args) == 1 and args[0].kind in ("INT", "BOOL"):
            value = pctx.numeric(args[0])
            return pctx.integer(z3_mod.If(value >= 0, value, -value))
        if node.func.id in ("max", "min") and len(args) == 2 and all(a.kind in ("INT", "BOOL") for a in args):
            left, right = pctx.numeric(args[0]), pctx.numeric(args[1])
            condition = left >= right if node.func.id == "max" else left <= right
            return pctx.integer(z3_mod.If(condition, left, right))
    return None


class CompiledSMTPostcondition(msgspec.Struct, frozen=True, kw_only=True):
    """Formal postcondition compiled from natural-language commit/PR intent or invariant rules."""

    intent_text: str
    constraint_kind: (
        str  # 'NON_NEGATIVE_RETURN' | 'STRICT_POSITIVE_RETURN' | 'UPPER_BOUND_RETURN'
    )
    bound_value: int
    smt_lib_expr: str


class IntentToSMTCompiler:
    """
    Compiles natural-language commit messages, PR descriptions, and `.verifyci/invariants.yaml`
    statements into formal SMT post-conditions (`Phi_intent`) and verifies Python functions
    against them using Z3 (or deterministic linear arithmetic bounds analysis).
    """

    def compile_intent(self, intent_text: str) -> CompiledSMTPostcondition | None:
        safe_intent = redact_in_place_mapping(intent_text).lower()

        # Pattern 1: Non-negative return invariant ("never drops below zero", "non-negative", ">= 0")
        if any(
            phrase in safe_intent
            for phrase in (
                "never drops below zero",
                "never negative",
                "non-negative",
                "nonnegative",
                ">= 0",
                "at least 0",
                "not be negative",
            )
        ):
            return CompiledSMTPostcondition(
                intent_text=intent_text,
                constraint_kind="NON_NEGATIVE_RETURN",
                bound_value=0,
                smt_lib_expr="(assert (>= return_val 0))",
            )

        # Pattern 2: Strictly positive return invariant ("strictly positive", "> 0", "greater than zero")
        if any(
            phrase in safe_intent
            for phrase in (
                "strictly positive",
                "greater than zero",
                "> 0",
                "must be positive",
            )
        ):
            return CompiledSMTPostcondition(
                intent_text=intent_text,
                constraint_kind="STRICT_POSITIVE_RETURN",
                bound_value=1,
                smt_lib_expr="(assert (> return_val 0))",
            )

        # Pattern 3: Explicit upper bound ("never exceed N", "<= N", "at most N")
        m_bound = re.search(r"(?:never exceed|at most|<=)\s*(\d+)", safe_intent)
        if m_bound:
            cap = int(m_bound.group(1))
            return CompiledSMTPostcondition(
                intent_text=intent_text,
                constraint_kind="UPPER_BOUND_RETURN",
                bound_value=cap,
                smt_lib_expr=f"(assert (<= return_val {cap}))",
            )

        return None

    def verify_function_against_intent(
        self,
        *,
        file_path: str,
        source: str,
        intent_text: str,
        preparsed_tree: ast.Module | None = None,
    ) -> tuple[VerificationFinding, ...]:
        """Check supported intent postconditions against a retained AST.

        ``preparsed_tree`` is the compilation-owner path. The source-only parse
        remains for compatibility with external callers, but a unified pipeline
        must always provide the pre-parsed tree.
        """
        spec = self.compile_intent(intent_text)
        if spec is None:
            return ()

        start_ns = time.perf_counter_ns()
        try:
            tree = preparsed_tree if preparsed_tree is not None else ast.parse(source, filename=file_path)
        except (SyntaxError, ValueError, IndentationError) as exc:
            fid = content_digest_hex(
                f"INTENT_SYNTAX:{file_path}:{type(exc).__name__}:{exc}",
                domain="verifyci.v2.finding",
            )[:16]
            return (VerificationFinding(
                finding_id=fid,
                rule_id="VC2-INTENT-SYNTAX-ERROR",
                severity="HIGH",
                verdict="INCONCLUSIVE",
                file_path=file_path,
                start_line=getattr(exc, "lineno", None) or 1,
                end_line=getattr(exc, "lineno", None) or 1,
                message=f"Intent checker could not parse complete source for '{file_path}': {exc}",
            ),)

        findings: list[VerificationFinding] = []
        functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        if not functions:
            return ()

        try:
            from verifyci_v2.symbolic.z3_prover import _PyVal, _Z3ProofContext
        except Exception as exc:
            return (self._intent_inconclusive(
                file_path, "<module>", 1, spec,
                f"Typed symbolic context is unavailable: {type(exc).__name__}: {exc}",
                start_ns,
            ),)

        for stmt in functions:
            params = [a.arg for a in (*stmt.args.posonlyargs, *stmt.args.args, *stmt.args.kwonlyargs)]
            if stmt.args.vararg is not None or stmt.args.kwarg is not None:
                findings.append(self._intent_inconclusive(
                    file_path, stmt.name, stmt.lineno, spec,
                    "Variadic parameters are unsupported by the intent prover.", start_ns,
                ))
                continue
            paths = self._collect_paths(stmt.body, incoming_guards=[], local_env={})
            if not paths:
                continue

            if _z3_mod is None:
                for _guards, ret_expr, line_no in paths:
                    if self._can_produce_violation(ret_expr, params, spec):
                        findings.append(self._intent_inconclusive(
                            file_path, stmt.name, line_no, spec,
                            "Z3 solver is unavailable; intent postcondition was not established.", start_ns,
                            witness=CounterexampleWitness(
                                checker_id="VC2-INTENT-POSTCONDITION-VIOLATION",
                                smt_status="SOLVER_UNAVAILABLE", input_assignments={},
                                base_return_state=spec.smt_lib_expr,
                                head_return_state="solver_unavailable",
                                proof_time_ms=round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 3),
                            ),
                        ))
                continue

            try:
                pctx = _Z3ProofContext(timeout_ms=2000)
            except Exception as exc:
                findings.append(self._intent_inconclusive(
                    file_path, stmt.name, stmt.lineno, spec,
                    f"Could not initialize an isolated Z3 context: {type(exc).__name__}: {exc}", start_ns,
                ))
                continue

            # Python annotations are not runtime-enforced. Model parameters as
            # general tagged values, and abstain when the supported scalar
            # fragment cannot prove the input type needed by an operation.
            param_kinds = {}
            for a in [*stmt.args.posonlyargs, *stmt.args.args, *stmt.args.kwonlyargs]:
                if a.annotation is not None:
                    try:
                        ann_str = ast.unparse(a.annotation).strip()
                        if ann_str in ("int", "float"):
                            param_kinds[a.arg] = "INT"
                        elif ann_str == "bool":
                            param_kinds[a.arg] = "BOOL"
                        elif ann_str == "str":
                            param_kinds[a.arg] = "STR"
                    except Exception:
                        pass

            z3_vars: dict[str, Any] = {
                p: _PyVal(_z3_mod.Const(p, pctx.pyval), param_kinds.get(p))
                for p in params
            }
            for guards, ret_expr, line_no in paths:
                solver = pctx.solver()
                for p, v in z3_vars.items():
                    if v.kind == "INT":
                        solver.add(pctx.pyval.is_mk_int(v.term))
                    elif v.kind == "BOOL":
                        solver.add(pctx.pyval.is_mk_bool(v.term))
                    elif v.kind == "STR":
                        solver.add(pctx.pyval.is_mk_str(v.term))
                supported = True
                for guard_ast, branch_bool in guards:
                    guard = _ast_to_z3_val(guard_ast, z3_vars, _z3_mod, pctx)
                    if guard is None:
                        supported = False
                        break
                    condition = pctx.truth(guard)
                    solver.add(condition if branch_bool else _z3_mod.Not(condition))
                if not supported:
                    findings.append(self._intent_inconclusive(
                        file_path, stmt.name, line_no, spec,
                        "A path guard uses unsupported or dynamically typed semantics.", start_ns,
                    ))
                    continue

                z_ret = _ast_to_z3_val(ret_expr, z3_vars, _z3_mod, pctx)
                if z_ret is None or z_ret.kind not in ("INT", "BOOL"):
                    findings.append(self._intent_inconclusive(
                        file_path, stmt.name, line_no, spec,
                        "The return expression is not proven to be a supported numeric Python value.", start_ns,
                    ))
                    continue
                numeric_return = pctx.numeric(z_ret)
                if spec.constraint_kind == "NON_NEGATIVE_RETURN":
                    solver.add(numeric_return < spec.bound_value)
                elif spec.constraint_kind == "STRICT_POSITIVE_RETURN":
                    solver.add(numeric_return <= spec.bound_value)
                elif spec.constraint_kind == "UPPER_BOUND_RETURN":
                    solver.add(numeric_return > spec.bound_value)
                else:
                    findings.append(self._intent_inconclusive(
                        file_path, stmt.name, line_no, spec,
                        f"Unsupported postcondition kind: {spec.constraint_kind}", start_ns,
                    ))
                    continue

                status = solver.check()
                elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                if status == _z3_mod.unknown:
                    findings.append(self._intent_inconclusive(
                        file_path, stmt.name, line_no, spec,
                        f"Z3 returned UNKNOWN for intent postcondition: {solver.reason_unknown()}.", start_ns,
                    ))
                    continue
                if status != _z3_mod.sat:
                    continue

                model = solver.model()
                witness_inputs: dict[str, str | int | float | bool | None] = {}
                witness_ok = True
                for param_name, symbolic_value in z3_vars.items():
                    value = model.eval(symbolic_value.term, model_completion=True)
                    if _z3_mod.is_true(model.eval(pctx.pyval.is_mk_none(value), model_completion=True)):
                        witness_inputs[param_name] = None
                    elif _z3_mod.is_true(model.eval(pctx.pyval.is_mk_bool(value), model_completion=True)):
                        witness_inputs[param_name] = _z3_mod.is_true(
                            model.eval(pctx.pyval.bool_val(value), model_completion=True)
                        )
                    elif _z3_mod.is_true(model.eval(pctx.pyval.is_mk_int(value), model_completion=True)):
                        raw_int = model.eval(pctx.pyval.int_val(value), model_completion=True)
                        if not _z3_mod.is_int_value(raw_int):
                            witness_ok = False
                            break
                        witness_inputs[param_name] = raw_int.as_long()
                    elif _z3_mod.is_true(model.eval(pctx.pyval.is_mk_str(value), model_completion=True)):
                        raw_str = model.eval(pctx.pyval.str_val(value), model_completion=True)
                        if not _z3_mod.is_string_value(raw_str):
                            witness_ok = False
                            break
                        try:
                            witness_inputs[param_name] = raw_str.as_string()
                        except Exception:
                            witness_ok = False
                            break
                    else:
                        witness_ok = False
                        break
                if not witness_ok:
                    findings.append(self._intent_inconclusive(
                        file_path, stmt.name, line_no, spec,
                        "SAT model could not be materialized into concrete Python inputs.", start_ns,
                    ))
                    continue

                if not self._evaluate_func_violates(
                    stmt, witness_inputs, spec.bound_value, spec.constraint_kind
                ):
                    findings.append(self._intent_inconclusive(
                        file_path, stmt.name, line_no, spec,
                        "A candidate SAT model failed concrete witness validation.", start_ns,
                    ))
                    continue

                fid = content_digest_hex(
                    f"INTENT:{file_path}:{stmt.name}:{line_no}:{spec.smt_lib_expr}",
                    domain="verifyci.v2.finding",
                )[:16]
                findings.append(VerificationFinding(
                    finding_id=fid,
                    rule_id="VC2-INTENT-POSTCONDITION-VIOLATION",
                    severity="HIGH", verdict="FAIL", file_path=file_path,
                    start_line=line_no, end_line=line_no,
                    message=(f"Function '{stmt.name}' violates compiled intent postcondition "
                             f"{spec.smt_lib_expr} for inputs {witness_inputs}."),
                    witness=CounterexampleWitness(
                        checker_id="VC2-INTENT-POSTCONDITION-VIOLATION",
                        smt_status="SAT", input_assignments=witness_inputs,
                        base_return_state=spec.smt_lib_expr,
                        head_return_state=(
                            "return_val < 0" if spec.bound_value == 0
                            else f"return_val < {spec.bound_value}"
                            if spec.constraint_kind != "UPPER_BOUND_RETURN"
                            else f"return_val > {spec.bound_value}"
                        ),
                        proof_time_ms=round(elapsed_ms, 3),
                    ),
                ))
        return tuple(findings)

    @staticmethod
    def _intent_inconclusive(
        file_path: str,
        function_name: str,
        line_no: int,
        spec: CompiledSMTPostcondition,
        reason: str,
        start_ns: int,
        *,
        witness: CounterexampleWitness | None = None,
    ) -> VerificationFinding:
        fid = content_digest_hex(
            f"INTENT_INCONCLUSIVE:{file_path}:{function_name}:{line_no}:{spec.smt_lib_expr}:{reason}",
            domain="verifyci.v2.finding",
        )[:16]
        return VerificationFinding(
            finding_id=fid,
            rule_id="VC2-INTENT-POSTCONDITION-UNRESOLVED",
            severity="HIGH", verdict="INCONCLUSIVE", file_path=file_path,
            start_line=line_no, end_line=line_no,
            message=f"Cannot establish intent postcondition for '{function_name}': {reason}",
            witness=witness,
        )

    @classmethod
    def _collect_paths(
        cls,
        stmts: list[ast.stmt],
        incoming_guards: list[tuple[ast.AST, bool]],
        local_env: dict[str, ast.AST],
    ) -> list[tuple[list[tuple[ast.AST, bool]], ast.AST, int]]:
        paths: list[tuple[list[tuple[ast.AST, bool]], ast.AST, int]] = []
        current_guards = list(incoming_guards)
        env = dict(local_env)

        for stmt in stmts:
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
            ):
                expanded_val = _InlineAssignTransformer(env).visit(stmt.value)
                env[stmt.targets[0].id] = expanded_val
            elif isinstance(stmt, ast.Return):
                if stmt.value is not None:
                    expanded_val = _InlineAssignTransformer(env).visit(stmt.value)
                else:
                    expanded_val = ast.copy_location(ast.Constant(value=None), stmt)
                paths.append((list(current_guards), expanded_val, stmt.lineno))
                break
            elif isinstance(stmt, ast.If):
                expanded_test = _InlineAssignTransformer(env).visit(stmt.test)
                body_paths = cls._collect_paths(
                    stmt.body, current_guards + [(expanded_test, True)], env
                )
                paths.extend(body_paths)
                body_always_exits = cls._always_exits(stmt.body)

                if stmt.orelse:
                    orelse_paths = cls._collect_paths(
                        stmt.orelse, current_guards + [(expanded_test, False)], env
                    )
                    paths.extend(orelse_paths)
                    orelse_always_exits = cls._always_exits(stmt.orelse)
                    if body_always_exits and orelse_always_exits:
                        break
                    if body_always_exits:
                        current_guards.append((expanded_test, False))
                    elif orelse_always_exits:
                        current_guards.append((expanded_test, True))
                else:
                    if body_always_exits:
                        current_guards.append((expanded_test, False))

        return paths

    @staticmethod
    def _always_exits(stmts: list[ast.stmt]) -> bool:
        if not stmts:
            return False
        last = stmts[-1]
        if isinstance(last, (ast.Return, ast.Raise)):
            return True
        if isinstance(last, ast.If):
            return (
                bool(last.orelse)
                and IntentToSMTCompiler._always_exits(last.body)
                and IntentToSMTCompiler._always_exits(last.orelse)
            )
        return False

    @staticmethod
    def _can_produce_violation(
        ret_expr: ast.AST, params: list[str], spec: CompiledSMTPostcondition
    ) -> bool:
        if isinstance(ret_expr, (ast.BinOp, ast.Name, ast.UnaryOp)):
            # Without Z3, non-literal arithmetic/unary expressions cannot be
            # proven safe. This includes ``return -1`` and should abstain rather
            # than disappearing as an empty finding set.
            return True
        if isinstance(ret_expr, ast.Constant) and isinstance(
            ret_expr.value, (int, float)
        ):
            if spec.constraint_kind == "NON_NEGATIVE_RETURN":
                return ret_expr.value < spec.bound_value
            if spec.constraint_kind == "STRICT_POSITIVE_RETURN":
                return ret_expr.value <= spec.bound_value
            if spec.constraint_kind == "UPPER_BOUND_RETURN":
                return ret_expr.value > spec.bound_value
        return bool(params)

    @classmethod
    def _evaluate_func_violates(
        cls,
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        witness_inputs: dict[str, str | int | float | bool | None],
        bound_val: int,
        constraint_kind: str,
    ) -> bool:
        """Independently validate a concrete witness using the typed value model."""
        if _z3_mod is None:
            return False
        try:
            from verifyci_v2.symbolic.z3_prover import _Z3ProofContext
            pctx = _Z3ProofContext(timeout_ms=1000)
            param_names = [a.arg for a in (*fn_node.args.posonlyargs, *fn_node.args.args, *fn_node.args.kwonlyargs)]
            z3_vars: dict[str, Any] = {}
            for name in param_names:
                value = witness_inputs.get(name, 0)
                if value is None:
                    z3_vars[name] = pctx.none()
                elif isinstance(value, bool):
                    z3_vars[name] = pctx.boolean(value)
                elif isinstance(value, int):
                    z3_vars[name] = pctx.integer(value)
                elif isinstance(value, str):
                    z3_vars[name] = pctx.string(value)
                else:
                    return False
            paths = cls._collect_paths(fn_node.body, incoming_guards=[], local_env={})
            for guards, ret_expr, _line in paths:
                solver = pctx.solver()
                feasible = True
                for guard_ast, branch_bool in guards:
                    guard = _ast_to_z3_val(guard_ast, z3_vars, _z3_mod, pctx)
                    if guard is None:
                        feasible = False
                        break
                    condition = pctx.truth(guard)
                    solver.add(condition if branch_bool else _z3_mod.Not(condition))
                if not feasible:
                    continue
                ret = _ast_to_z3_val(ret_expr, z3_vars, _z3_mod, pctx)
                if ret is None or ret.kind not in ("INT", "BOOL"):
                    continue
                numeric = pctx.numeric(ret)
                if constraint_kind == "NON_NEGATIVE_RETURN":
                    solver.add(numeric < bound_val)
                elif constraint_kind == "STRICT_POSITIVE_RETURN":
                    solver.add(numeric <= bound_val)
                elif constraint_kind == "UPPER_BOUND_RETURN":
                    solver.add(numeric > bound_val)
                else:
                    continue
                if solver.check() == _z3_mod.sat:
                    return True
            return False
        except Exception:
            return False

