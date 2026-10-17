"""Lazy Z3 SMT Prover Adapter implementing SymbolicProverProtocol."""

from __future__ import annotations

import ast
import time
from typing import Any, Mapping, Sequence

from verifyci.contracts.verdict import (
    FindingReason,
    Severity,
    VerificationFinding,
    VerificationVerdict,
)
from verifyci.core.canonical import content_digest_hex
from verifyci.extensions.protocols import (
    EquivalenceStatus,
    SymbolicProverProtocol,
    SymbolicResult,
)


def _get_z3() -> Any:
    """Lazy import of z3-solver to avoid startup penalty."""
    try:
        import z3  # type: ignore[import-untyped]
        return z3
    except ImportError:
        return None


class Z3ProverAdapter(SymbolicProverProtocol):
    """Formal SMT equivalence prover and counterexample generator powered by Z3.

    Zero import-time overhead: Z3 native binaries are loaded on demand when
    symbolic proofs are actually invoked.
    """

    def __init__(self, default_timeout_ms: int = 3000) -> None:
        self.default_timeout_ms = default_timeout_ms

    def prove_function_diff(
        self,
        file_path: str,
        base_source: str,
        head_source: str,
        timeout_ms: int | None = None,
    ) -> Sequence[SymbolicResult]:
        timeout = timeout_ms if timeout_ms is not None else self.default_timeout_ms
        t0 = time.perf_counter()

        # Parse ASTs
        try:
            base_tree = ast.parse(base_source, filename=file_path)
            head_tree = ast.parse(head_source, filename=file_path)
        except SyntaxError as exc:
            duration = (time.perf_counter() - t0) * 1000
            return [
                SymbolicResult(
                    status=EquivalenceStatus.ERROR,
                    target_symbol="<syntax_error>",
                    proof_trace=f"AST parse failure: {exc}",
                    duration_ms=duration,
                )
            ]

        base_funcs = {
            node.name: node
            for node in ast.walk(base_tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        head_funcs = {
            node.name: node
            for node in ast.walk(head_tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }

        results: list[SymbolicResult] = []

        for name, head_fn in head_funcs.items():
            base_fn = base_funcs.get(name)
            if base_fn is None:
                continue

            # Check if AST of body is identical (fast path)
            if ast.dump(base_fn) == ast.dump(head_fn):
                results.append(
                    SymbolicResult(
                        status=EquivalenceStatus.PROVEN_EQUIVALENT,
                        target_symbol=name,
                        proof_trace="Syntactic AST isomorphism verified",
                        duration_ms=(time.perf_counter() - t0) * 1000,
                    )
                )
                continue

            # AST differs: run SMT equivalence proof
            res = self._prove_function_pair(file_path, name, base_fn, head_fn, timeout)
            results.append(res)

        return results

    def _prove_function_pair(
        self,
        file_path: str,
        func_name: str,
        base_fn: ast.FunctionDef | ast.AsyncFunctionDef,
        head_fn: ast.FunctionDef | ast.AsyncFunctionDef,
        timeout_ms: int,
    ) -> SymbolicResult:
        z3 = _get_z3()
        t0 = time.perf_counter()

        if z3 is None:
            # Solver unavailable fails closed to INCONCLUSIVE
            finding = VerificationFinding(
                finding_id=content_digest_hex(f"z3_unavail:{file_path}:{func_name}")[:16],
                rule_id="VC-SYMBOLIC-SOLVER-UNAVAILABLE",
                severity=Severity.HIGH,
                verdict=VerificationVerdict.INCONCLUSIVE,
                reason=FindingReason.CAPABILITY_UNAVAILABLE,
                message=f"Z3 SMT solver is unavailable to verify '{func_name}' in '{file_path}'; failing closed.",
                file_path=file_path,
                start_line=getattr(head_fn, "lineno", 1),
                end_line=getattr(head_fn, "end_lineno", 1),
            )
            return SymbolicResult(
                status=EquivalenceStatus.UNAVAILABLE,
                target_symbol=func_name,
                duration_ms=(time.perf_counter() - t0) * 1000,
                findings=(finding,),
            )

        # Extract scalar return expressions
        base_ret = self._extract_return_expr(base_fn)
        head_ret = self._extract_return_expr(head_fn)

        if base_ret is None or head_ret is None:
            # Complex control flow or unsupported statements
            finding = VerificationFinding(
                finding_id=content_digest_hex(f"z3_unsupported:{file_path}:{func_name}")[:16],
                rule_id="VC-SYMBOLIC-UNSUPPORTED-CONTROL-FLOW",
                severity=Severity.MEDIUM,
                verdict=VerificationVerdict.INCONCLUSIVE,
                reason=FindingReason.SMT_TIMEOUT,
                message=f"Function '{func_name}' has non-scalar control flow outside SMT decidable fragment.",
                file_path=file_path,
                start_line=getattr(head_fn, "lineno", 1),
                end_line=getattr(head_fn, "end_lineno", 1),
            )
            return SymbolicResult(
                status=EquivalenceStatus.UNKNOWN,
                target_symbol=func_name,
                duration_ms=(time.perf_counter() - t0) * 1000,
                findings=(finding,),
            )

        # Build SMT context and variables
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)

        # Collect argument names
        args = [arg.arg for arg in head_fn.args.args]
        env: dict[str, Any] = {a: z3.Int(a) for a in args}

        try:
            z_base = self._ast_to_z3(base_ret, env, z3)
            z_head = self._ast_to_z3(head_ret, env, z3)
        except Exception as exc:
            finding = VerificationFinding(
                finding_id=content_digest_hex(f"z3_encode_err:{file_path}:{func_name}")[:16],
                rule_id="VC-SYMBOLIC-ENCODING-ERROR",
                severity=Severity.MEDIUM,
                verdict=VerificationVerdict.INCONCLUSIVE,
                reason=FindingReason.SMT_TIMEOUT,
                message=f"Could not encode '{func_name}' return expression into SMT theory: {exc}",
                file_path=file_path,
                start_line=getattr(head_fn, "lineno", 1),
                end_line=getattr(head_fn, "end_lineno", 1),
            )
            return SymbolicResult(
                status=EquivalenceStatus.UNKNOWN,
                target_symbol=func_name,
                duration_ms=(time.perf_counter() - t0) * 1000,
                findings=(finding,),
            )

        # Query: does there exist an input where base != head?
        solver.add(z_base != z_head)
        check_res = solver.check()
        duration_ms = (time.perf_counter() - t0) * 1000

        if check_res == z3.unsat:
            # Equivalence proven!
            return SymbolicResult(
                status=EquivalenceStatus.PROVEN_EQUIVALENT,
                target_symbol=func_name,
                proof_trace="SMT UNSAT: No counterexample exists where return values diverge",
                duration_ms=duration_ms,
            )
        elif check_res == z3.sat:
            # Divergence proven with counterexample
            model = solver.model()
            cex = {str(d): int(str(model[d])) if z3.is_int(model[d]) else str(model[d]) for d in model}
            finding = VerificationFinding(
                finding_id=content_digest_hex(f"z3_diverge:{file_path}:{func_name}")[:16],
                rule_id="VC-SYMBOLIC-SEMANTIC-DIVERGENCE",
                severity=Severity.HIGH,
                verdict=VerificationVerdict.FAIL,
                reason=FindingReason.SEMANTIC_DIVERGENCE,
                message=f"Z3 proved semantic divergence in '{func_name}' with counterexample: {cex}",
                file_path=file_path,
                start_line=getattr(head_fn, "lineno", 1),
                end_line=getattr(head_fn, "end_lineno", 1),
                details={"counterexample": cex},
            )
            return SymbolicResult(
                status=EquivalenceStatus.PROVEN_DIVERGENT,
                target_symbol=func_name,
                counterexamples=(cex,),
                proof_trace="SMT SAT: Counterexample witness found",
                duration_ms=duration_ms,
                findings=(finding,),
            )
        else:
            # solver check returned unknown or timeout -> INCONCLUSIVE
            reason = solver.reason_unknown()
            finding_reason = FindingReason.SMT_TIMEOUT if "timeout" in reason.lower() else FindingReason.SMT_TIMEOUT
            finding = VerificationFinding(
                finding_id=content_digest_hex(f"z3_unknown:{file_path}:{func_name}")[:16],
                rule_id="VC-SYMBOLIC-SMT-UNDECIDED",
                severity=Severity.HIGH,
                verdict=VerificationVerdict.INCONCLUSIVE,
                reason=finding_reason,
                message=f"Z3 solver returned {reason} for '{func_name}'; failing closed.",
                file_path=file_path,
                start_line=getattr(head_fn, "lineno", 1),
                end_line=getattr(head_fn, "end_lineno", 1),
            )
            return SymbolicResult(
                status=EquivalenceStatus.TIMEOUT if "timeout" in reason.lower() else EquivalenceStatus.UNKNOWN,
                target_symbol=func_name,
                proof_trace=f"SMT UNKNOWN: {reason}",
                duration_ms=duration_ms,
                findings=(finding,),
            )

    def _extract_return_expr(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.expr | None:
        """Extract simple return expression if function is a scalar computation."""
        # Find all return statements
        returns = [stmt for stmt in fn.body if isinstance(stmt, ast.Return)]
        if len(returns) == 1 and isinstance(returns[0].value, ast.expr):
            return returns[0].value
        return None

    def _ast_to_z3(self, node: ast.expr, env: Mapping[str, Any], z3: Any) -> Any:
        """Translate supported AST arithmetic and comparison expressions into Z3."""
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            return z3.Int(node.id)
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, int):
                return z3.IntVal(node.value)
            elif isinstance(node.value, bool):
                return z3.BoolVal(node.value)
        elif isinstance(node, ast.BinOp):
            left = self._ast_to_z3(node.left, env, z3)
            right = self._ast_to_z3(node.right, env, z3)
            if isinstance(node.op, ast.Add):
                return left + right
            elif isinstance(node.op, ast.Sub):
                return left - right
            elif isinstance(node.op, ast.Mult):
                return left * right
            elif isinstance(node.op, ast.FloorDiv):
                return left / right
        elif isinstance(node, ast.UnaryOp):
            operand = self._ast_to_z3(node.operand, env, z3)
            if isinstance(node.op, ast.USub):
                return -operand
            elif isinstance(node.op, ast.Not):
                return z3.Not(operand)
        elif isinstance(node, ast.IfExp):
            cond = self._ast_to_z3(node.test, env, z3)
            body = self._ast_to_z3(node.body, env, z3)
            orelse = self._ast_to_z3(node.orelse, env, z3)
            return z3.If(cond, body, orelse)
        elif isinstance(node, ast.Compare):
            left = self._ast_to_z3(node.left, env, z3)
            if len(node.ops) == 1 and len(node.comparators) == 1:
                op = node.ops[0]
                right = self._ast_to_z3(node.comparators[0], env, z3)
                if isinstance(op, ast.Eq):
                    return left == right
                elif isinstance(op, ast.NotEq):
                    return left != right
                elif isinstance(op, ast.Lt):
                    return left < right
                elif isinstance(op, ast.LtE):
                    return left <= right
                elif isinstance(op, ast.Gt):
                    return left > right
                elif isinstance(op, ast.GtE):
                    return left >= right

        raise ValueError(f"AST node '{type(node).__name__}' outside supported SMT subset")
