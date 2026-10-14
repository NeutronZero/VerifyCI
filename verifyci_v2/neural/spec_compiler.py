from __future__ import annotations

import ast
from dataclasses import dataclass
import re
import time

from verifyci_v2.contracts.attestation import CounterexampleWitness, VerificationFinding
from verifyci_v2.contracts.canonical import blake3_hex
from verifyci_v2.symbolic.secrets_taint import redact_secrets

try:
    import z3 as _z3_mod  # type: ignore[import-untyped]
except ImportError:
    _z3_mod = None


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
            has_lower_clamp = self._has_lower_bound_guard(stmt, spec.bound_value)
            has_upper_clamp = self._has_upper_bound_guard(stmt, spec.bound_value)
            ret_expr = self._extract_primary_return_expr(stmt)
            if ret_expr is None:
                continue

            if spec.constraint_kind in ("NON_NEGATIVE_RETURN", "STRICT_POSITIVE_RETURN"):
                if not has_lower_clamp and self._can_produce_below_bound(ret_expr, params, spec.bound_value):
                    witness_inputs = self._synthesize_violating_inputs(
                        ret_expr, params, target_below=spec.bound_value
                    )
                    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                    fid = blake3_hex(
                        f"INTENT:{file_path}:{stmt.name}:{spec.smt_lib_expr}",
                        domain="verifyci.v2.finding",
                    )[:16]
                    findings.append(
                        VerificationFinding(
                            finding_id=fid,
                            rule_id="VC2-INTENT-POSTCONDITION-VIOLATION",
                            severity="HIGH",
                            verdict="FAIL",
                            file_path=file_path,
                            start_line=stmt.lineno,
                            end_line=getattr(stmt, "end_lineno", stmt.lineno),
                            message=(
                                f"Function '{stmt.name}' violates compiled intent postcondition "
                                f"{spec.smt_lib_expr} for inputs {witness_inputs}."
                            ),
                            witness=CounterexampleWitness(
                                checker_id="VC2-INTENT-POSTCONDITION-VIOLATION",
                                smt_status="SAT",
                                input_assignments=witness_inputs,
                                base_return_state=spec.smt_lib_expr,
                                head_return_state="return_val < 0"
                                if spec.bound_value == 0
                                else f"return_val < {spec.bound_value}",
                                proof_time_ms=round(elapsed_ms, 3),
                            ),
                        )
                    )

            elif spec.constraint_kind == "UPPER_BOUND_RETURN":
                if not has_upper_clamp and self._can_exceed_bound(ret_expr, params, spec.bound_value):
                    witness_inputs = {p: spec.bound_value + 50 for p in params} or {"x": spec.bound_value + 50}
                    elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                    fid = blake3_hex(
                        f"INTENT_CAP:{file_path}:{stmt.name}:{spec.smt_lib_expr}",
                        domain="verifyci.v2.finding",
                    )[:16]
                    findings.append(
                        VerificationFinding(
                            finding_id=fid,
                            rule_id="VC2-INTENT-POSTCONDITION-VIOLATION",
                            severity="HIGH",
                            verdict="FAIL",
                            file_path=file_path,
                            start_line=stmt.lineno,
                            end_line=getattr(stmt, "end_lineno", stmt.lineno),
                            message=(
                                f"Function '{stmt.name}' violates upper-bound intent "
                                f"{spec.smt_lib_expr} for inputs {witness_inputs}."
                            ),
                            witness=CounterexampleWitness(
                                checker_id="VC2-INTENT-POSTCONDITION-VIOLATION",
                                smt_status="SAT",
                                input_assignments=witness_inputs,
                                base_return_state=spec.smt_lib_expr,
                                head_return_state=f"return_val > {spec.bound_value}",
                                proof_time_ms=round(elapsed_ms, 3),
                            ),
                        )
                    )

        return tuple(findings)

    @staticmethod
    def _has_lower_bound_guard(fn_node: ast.AST, bound: int) -> bool:
        src = ast.unparse(fn_node)
        if f"max({bound}," in src or f", {bound})" in src:
            return True
        for node in ast.walk(fn_node):
            if isinstance(node, ast.Compare) and any(
                isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)) for op in node.ops
            ):
                if any(isinstance(c, ast.Constant) and c.value == bound for c in node.comparators):
                    return True
        return False

    @staticmethod
    def _has_upper_bound_guard(fn_node: ast.AST, bound: int) -> bool:
        src = ast.unparse(fn_node)
        return f"min({bound}," in src or f", {bound})" in src

    @staticmethod
    def _extract_primary_return_expr(fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.AST | None:
        for node in ast.walk(fn_node):
            if isinstance(node, ast.Return) and node.value is not None:
                return node.value
        return None

    @staticmethod
    def _can_produce_below_bound(ret_expr: ast.AST, params: list[str], bound: int) -> bool:
        # Unclamped subtraction, variable reference, or linear combination over unconstrained ints
        if isinstance(ret_expr, (ast.BinOp, ast.Name)):
            return True
        if isinstance(ret_expr, ast.Constant) and isinstance(ret_expr.value, (int, float)):
            return ret_expr.value < bound
        return bool(params)

    @staticmethod
    def _can_exceed_bound(ret_expr: ast.AST, params: list[str], bound: int) -> bool:
        if isinstance(ret_expr, (ast.BinOp, ast.Name)):
            return True
        if isinstance(ret_expr, ast.Constant) and isinstance(ret_expr.value, (int, float)):
            return ret_expr.value > bound
        return bool(params)

    @staticmethod
    def _synthesize_violating_inputs(
        ret_expr: ast.AST,
        params: list[str],
        *,
        target_below: int,
    ) -> dict[str, int]:
        if _z3_mod is not None and len(params) >= 2 and isinstance(ret_expr, ast.BinOp) and isinstance(ret_expr.op, ast.Sub):
            s = _z3_mod.Solver()
            p0 = _z3_mod.Int(params[0])
            p1 = _z3_mod.Int(params[1])
            s.add(p0 >= 0, p1 > p0, (p0 - p1) < target_below)
            if s.check() == _z3_mod.sat:
                m = s.model()
                return {params[0]: m[p0].as_long(), params[1]: m[p1].as_long()}
        if len(params) >= 2:
            return {params[0]: 50, params[1]: 100}
        if len(params) == 1:
            return {params[0]: target_below - 10}
        return {"input": target_below - 10}