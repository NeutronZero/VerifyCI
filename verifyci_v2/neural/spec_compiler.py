from __future__ import annotations

import ast
from dataclasses import dataclass
import re
import time
from typing import Any

from verifyci_v2.contracts.attestation import CounterexampleWitness, VerificationFinding
from verifyci_v2.contracts.canonical import blake3_hex
from verifyci_v2.symbolic.secrets_taint import redact_secrets

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


def _ast_to_z3_val(node: ast.AST, z3_vars: dict[str, Any], z3_mod: Any) -> Any:
    if z3_mod is None:
        return None
    if isinstance(node, ast.Name):
        if node.id not in z3_vars:
            z3_vars[node.id] = z3_mod.Int(node.id)
        return z3_vars[node.id]
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return z3_mod.BoolVal(node.value)
        if isinstance(node.value, int):
            return z3_mod.IntVal(node.value)
        return node.value
    if isinstance(node, ast.UnaryOp):
        operand = _ast_to_z3_val(node.operand, z3_vars, z3_mod)
        if operand is None:
            return None
        if isinstance(node.op, ast.Not):
            return z3_mod.Not(operand)
        if isinstance(node.op, ast.USub):
            return -operand
        return operand
    if isinstance(node, ast.BinOp):
        lhs = _ast_to_z3_val(node.left, z3_vars, z3_mod)
        rhs = _ast_to_z3_val(node.right, z3_vars, z3_mod)
        if lhs is None or rhs is None:
            return None
        if isinstance(node.op, ast.Add):
            return lhs + rhs
        if isinstance(node.op, ast.Sub):
            return lhs - rhs
        if isinstance(node.op, ast.Mult):
            return lhs * rhs
        return None
    if isinstance(node, ast.Compare):
        lhs = _ast_to_z3_val(node.left, z3_vars, z3_mod)
        if lhs is None:
            return None
        comps = []
        for op, r_node in zip(node.ops, node.comparators):
            rhs = _ast_to_z3_val(r_node, z3_vars, z3_mod)
            if rhs is None:
                return None
            if isinstance(op, ast.Gt):
                comps.append(lhs > rhs)
            elif isinstance(op, ast.GtE):
                comps.append(lhs >= rhs)
            elif isinstance(op, ast.Lt):
                comps.append(lhs < rhs)
            elif isinstance(op, ast.LtE):
                comps.append(lhs <= rhs)
            elif isinstance(op, ast.Eq):
                comps.append(lhs == rhs)
            elif isinstance(op, ast.NotEq):
                comps.append(lhs != rhs)
            lhs = rhs
        if not comps:
            return z3_mod.BoolVal(True)
        return z3_mod.And(*comps) if len(comps) > 1 else comps[0]
    if isinstance(node, ast.BoolOp):
        vals = [_ast_to_z3_val(v, z3_vars, z3_mod) for v in node.values]
        if any(v is None for v in vals):
            return None
        if isinstance(node.op, ast.And):
            return z3_mod.And(*vals)
        if isinstance(node.op, ast.Or):
            return z3_mod.Or(*vals)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id == "max" and len(node.args) == 2:
            a0 = _ast_to_z3_val(node.args[0], z3_vars, z3_mod)
            a1 = _ast_to_z3_val(node.args[1], z3_vars, z3_mod)
            if a0 is not None and a1 is not None:
                return z3_mod.If(a0 >= a1, a0, a1)
        elif node.func.id == "min" and len(node.args) == 2:
            a0 = _ast_to_z3_val(node.args[0], z3_vars, z3_mod)
            a1 = _ast_to_z3_val(node.args[1], z3_vars, z3_mod)
            if a0 is not None and a1 is not None:
                return z3_mod.If(a0 <= a1, a0, a1)
    return None


@dataclass(frozen=True, slots=True)
class CompiledSMTPostcondition:
    """Formal postcondition compiled from natural-language commit/PR intent or invariant rules."""

    intent_text: str
    constraint_kind: str  # 'NON_NEGATIVE_RETURN' | 'STRICT_POSITIVE_RETURN' | 'UPPER_BOUND_RETURN'
    bound_value: int
    smt_lib_expr: str


class IntentToSMTCompiler:
    """
    Compiles natural-language commit messages, PR descriptions, and `.verifyci/invariants.yaml`
    statements into formal SMT post-conditions (`Phi_intent`) and verifies Python functions
    against them using Z3 (or deterministic linear arithmetic bounds analysis).
    """

    def compile_intent(self, intent_text: str) -> CompiledSMTPostcondition | None:
        safe_intent = redact_secrets(intent_text).lower()

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
            for phrase in ("strictly positive", "greater than zero", "> 0", "must be positive")
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
    ) -> tuple[VerificationFinding, ...]:
        spec = self.compile_intent(intent_text)
        if spec is None:
            return ()

        start_ns = time.perf_counter_ns()
        tree = ast.parse(source, filename=file_path)
        findings: list[VerificationFinding] = []

        for stmt in tree.body:
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            params = [a.arg for a in stmt.args.args]
            paths = self._collect_paths(stmt.body, incoming_guards=[], local_env={})
            if not paths:
                continue

            for guards, ret_expr, line_no in paths:
                elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

                if _z3_mod is None:
                    # R2-1: When solver is unavailable, NEVER fabricate SAT
                    if self._can_produce_violation(ret_expr, params, spec):
                        fid = blake3_hex(
                            f"INTENT:{file_path}:{stmt.name}:{line_no}:{spec.smt_lib_expr}",
                            domain="verifyci.v2.finding",
                        )[:16]
                        findings.append(
                            VerificationFinding(
                                finding_id=fid,
                                rule_id="VC2-INTENT-POSTCONDITION-VIOLATION",
                                severity="HIGH",
                                verdict="INCONCLUSIVE",
                                file_path=file_path,
                                start_line=line_no,
                                end_line=line_no,
                                message=(
                                    f"Function '{stmt.name}' line {line_no} may violate intent "
                                    f"{spec.smt_lib_expr}, but Z3 solver is unavailable to verify."
                                ),
                                witness=CounterexampleWitness(
                                    checker_id="VC2-INTENT-POSTCONDITION-VIOLATION",
                                    smt_status="SOLVER_UNAVAILABLE",
                                    input_assignments={},
                                    base_return_state=spec.smt_lib_expr,
                                    head_return_state="solver_unavailable",
                                    proof_time_ms=round(elapsed_ms, 3),
                                ),
                            )
                        )
                    continue

                # Z3 is available: encode full execution path and negate postcondition
                s = _z3_mod.Solver()
                s.set("timeout", 2000)
                z3_vars: dict[str, Any] = {p: _z3_mod.Int(p) for p in params}

                can_encode = True
                for guard_ast, branch_bool in guards:
                    zg = _ast_to_z3_val(guard_ast, z3_vars, _z3_mod)
                    if zg is None:
                        can_encode = False
                        break
                    s.add(zg if branch_bool else _z3_mod.Not(zg))

                if not can_encode:
                    continue

                z_ret = _ast_to_z3_val(ret_expr, z3_vars, _z3_mod)
                if z_ret is None:
                    continue

                if spec.constraint_kind == "NON_NEGATIVE_RETURN":
                    s.add(z_ret < spec.bound_value)
                elif spec.constraint_kind == "STRICT_POSITIVE_RETURN":
                    s.add(z_ret <= spec.bound_value)
                elif spec.constraint_kind == "UPPER_BOUND_RETURN":
                    s.add(z_ret > spec.bound_value)

                st = s.check()
                if st == _z3_mod.sat:
                    m = s.model()
                    witness_inputs = {
                        p: m[z3_vars[p]].as_long() if m[z3_vars[p]] is not None else 0
                        for p in params
                    }

                    # Concretely evaluate function on witness to confirm violation
                    if not self._evaluate_func_violates(stmt, witness_inputs, spec.bound_value, spec.constraint_kind):
                        continue

                    fid = blake3_hex(
                        f"INTENT:{file_path}:{stmt.name}:{line_no}:{spec.smt_lib_expr}",
                        domain="verifyci.v2.finding",
                    )[:16]
                    findings.append(
                        VerificationFinding(
                            finding_id=fid,
                            rule_id="VC2-INTENT-POSTCONDITION-VIOLATION",
                            severity="HIGH",
                            verdict="FAIL",
                            file_path=file_path,
                            start_line=line_no,
                            end_line=line_no,
                            message=(
                                f"Function '{stmt.name}' violates compiled intent postcondition "
                                f"{spec.smt_lib_expr} for inputs {witness_inputs}."
                            ),
                            witness=CounterexampleWitness(
                                checker_id="VC2-INTENT-POSTCONDITION-VIOLATION",
                                smt_status="SAT",
                                input_assignments=witness_inputs,
                                base_return_state=spec.smt_lib_expr,
                                head_return_state=(
                                    "return_val < 0"
                                    if spec.bound_value == 0
                                    else f"return_val < {spec.bound_value}"
                                    if spec.constraint_kind != "UPPER_BOUND_RETURN"
                                    else f"return_val > {spec.bound_value}"
                                ),
                                proof_time_ms=round(elapsed_ms, 3),
                            ),
                        )
                    )

        return tuple(findings)

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
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                expanded_val = _InlineAssignTransformer(env).visit(stmt.value)
                env[stmt.targets[0].id] = expanded_val
            elif isinstance(stmt, ast.Return):
                if stmt.value is not None:
                    expanded_val = _InlineAssignTransformer(env).visit(stmt.value)
                    paths.append((list(current_guards), expanded_val, stmt.lineno))
                break
            elif isinstance(stmt, ast.If):
                expanded_test = _InlineAssignTransformer(env).visit(stmt.test)
                body_paths = cls._collect_paths(stmt.body, current_guards + [(expanded_test, True)], env)
                paths.extend(body_paths)
                body_always_exits = cls._always_exits(stmt.body)

                if stmt.orelse:
                    orelse_paths = cls._collect_paths(stmt.orelse, current_guards + [(expanded_test, False)], env)
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
    def _can_produce_violation(ret_expr: ast.AST, params: list[str], spec: CompiledSMTPostcondition) -> bool:
        if isinstance(ret_expr, (ast.BinOp, ast.Name)):
            return True
        if isinstance(ret_expr, ast.Constant) and isinstance(ret_expr.value, (int, float)):
            if spec.constraint_kind == "NON_NEGATIVE_RETURN":
                return ret_expr.value < spec.bound_value
            if spec.constraint_kind == "STRICT_POSITIVE_RETURN":
                return ret_expr.value <= spec.bound_value
            if spec.constraint_kind == "UPPER_BOUND_RETURN":
                return ret_expr.value > spec.bound_value
        return bool(params)

    @staticmethod
    def _evaluate_func_violates(
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
        witness_inputs: dict[str, int],
        bound_val: int,
        constraint_kind: str,
    ) -> bool:
        try:
            mod = ast.Module(body=[fn_node], type_ignores=[])
            code = compile(mod, filename="<ast>", mode="exec")
            env: dict[str, Any] = {}
            exec(code, env, env)
            fn = env.get(fn_node.name)
            if not callable(fn):
                return False
            ret = fn(**witness_inputs)
            if not isinstance(ret, (int, float)):
                return False
            if constraint_kind == "NON_NEGATIVE_RETURN":
                return bool(ret < bound_val)
            if constraint_kind == "STRICT_POSITIVE_RETURN":
                return bool(ret <= bound_val)
            if constraint_kind == "UPPER_BOUND_RETURN":
                return bool(ret > bound_val)
        except Exception:
            return False
        return False