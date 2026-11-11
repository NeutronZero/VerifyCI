"""Symbolic path condition extraction and AST helpers for semantic analysis."""

from __future__ import annotations

import ast
import hashlib
import time
from typing import Any
import z3

from verifyci.runtime.budget import WorkBudget


class UnsupportedExpressionError(Exception):
    def __init__(self, node: ast.AST, msg: str = "unsupported_expression") -> None:
        self.node = node
        self.msg = msg
        self.lineno = getattr(node, "lineno", 0)
        super().__init__(f"{msg} at line {self.lineno}: {type(node).__name__}")


class UnsupportedControlFlowError(Exception):
    def __init__(self, node: ast.AST, msg: str = "unsupported_control_flow") -> None:
        self.node = node
        self.msg = msg
        self.lineno = getattr(node, "lineno", 0)
        super().__init__(f"{msg} at line {self.lineno}: {type(node).__name__}")


class BudgetExhaustedError(Exception):
    pass


class SymbolicContext:
    """Symbolic execution variable tracking context.

    Note on soundness boundary:
    The type inference in get_var() (inferring Bool vs String vs Int from identifier naming
    patterns) is an abstract interpretation heuristic for candidate witness generation and
    path constraint derivation. It does not constitute a sound static type system. All candidate
    witnesses derived by Z3 using these symbolic variables are subject to mandatory concrete
    replay execution in an isolated subprocess before any finding is emitted. Any unconfirmed
    witness fails closed to Outcome.INCONCLUSIVE with Coverage.PARTIAL.
    """

    def __init__(self) -> None:
        self.vars: dict[str, z3.ExprRef] = {}

    def get_var(self, name: str, vtype: str = "auto") -> z3.ExprRef:
        if name in self.vars:
            return self.vars[name]
        lower = name.lower()
        if vtype == "bool" or any(
            k in lower for k in ("is_", "has_", "valid", "blocked", "flag", "admin", "none")
        ):
            var = z3.Bool(name)
        elif vtype == "string" or any(
            k in lower for k in ("role", "name", "token", "status")
        ):
            var = z3.String(name)
        else:
            var = z3.Int(name)
        self.vars[name] = var
        return var


def ast_to_z3(node: ast.AST, ctx: SymbolicContext) -> z3.ExprRef:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return z3.BoolVal(node.value)
        if isinstance(node.value, int):
            return z3.IntVal(node.value)
        if isinstance(node.value, str):
            return z3.StringVal(node.value)
        if node.value is None:
            return ctx.get_var("__none_val__", "string")
        raise UnsupportedExpressionError(node, f"unsupported constant type: {type(node.value).__name__}")

    if isinstance(node, ast.Name):
        return ctx.get_var(node.id)

    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        curr: ast.AST = node
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
            return ctx.get_var(".".join(reversed(parts)))
        raise UnsupportedExpressionError(node, "unsupported complex attribute target")

    if isinstance(node, ast.UnaryOp):
        operand = ast_to_z3(node.operand, ctx)
        if isinstance(node.op, ast.Not):
            if z3.is_bool(operand):
                return z3.Not(operand)
            if z3.is_string(operand):
                return operand == z3.StringVal("")
            return operand == z3.IntVal(0)
        if isinstance(node.op, ast.USub):
            return -operand  # ty: ignore[unsupported-operator]
        raise UnsupportedExpressionError(node, f"unsupported unary operator: {type(node.op).__name__}")

    if isinstance(node, ast.BinOp):
        left = ast_to_z3(node.left, ctx)
        right = ast_to_z3(node.right, ctx)
        if isinstance(node.op, ast.Add):
            return left + right  # ty: ignore[unsupported-operator]
        if isinstance(node.op, ast.Sub):
            return left - right  # ty: ignore[unsupported-operator]
        if isinstance(node.op, ast.Mult):
            return left * right  # ty: ignore[unsupported-operator]
        raise UnsupportedExpressionError(node, f"unsupported binary operator: {type(node.op).__name__}")

    if isinstance(node, ast.BoolOp):
        values = [ast_to_z3(v, ctx) for v in node.values]
        bool_values = [v if z3.is_bool(v) else v != 0 for v in values]
        if isinstance(node.op, ast.And):
            return z3.And(*bool_values)
        if isinstance(node.op, ast.Or):
            return z3.Or(*bool_values)
        raise UnsupportedExpressionError(node, f"unsupported boolean operator: {type(node.op).__name__}")

    if isinstance(node, ast.Compare):
        curr_left = ast_to_z3(node.left, ctx)
        comparisons = []
        for op, comparator in zip(node.ops, node.comparators):
            right = ast_to_z3(comparator, ctx)
            if z3.is_bool(curr_left) and z3.is_int(right):
                right = right != 0
            elif z3.is_int(curr_left) and z3.is_bool(right):
                curr_left = curr_left != 0

            if isinstance(op, (ast.Eq, ast.Is)):
                comparisons.append(curr_left == right)
            elif isinstance(op, (ast.NotEq, ast.IsNot)):
                comparisons.append(curr_left != right)
            elif isinstance(op, ast.Lt):
                comparisons.append(curr_left < right)  # ty: ignore[unsupported-operator]
            elif isinstance(op, ast.LtE):
                comparisons.append(curr_left <= right)  # ty: ignore[unsupported-operator]
            elif isinstance(op, ast.Gt):
                comparisons.append(curr_left > right)  # ty: ignore[unsupported-operator]
            elif isinstance(op, ast.GtE):
                comparisons.append(curr_left >= right)  # ty: ignore[unsupported-operator]
            else:
                raise UnsupportedExpressionError(node, f"unsupported comparison operator: {type(op).__name__}")
            curr_left = right

        if len(comparisons) == 1:
            return comparisons[0]
        return z3.And(*comparisons)

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "bool" and node.args:
            arg = ast_to_z3(node.args[0], ctx)
            return arg if z3.is_bool(arg) else arg != 0
        raise UnsupportedExpressionError(node, f"unsupported call in expression: {getattr(node.func, 'id', 'call')}")

    raise UnsupportedExpressionError(node, f"unsupported expression node: {type(node).__name__}")


class TargetSite:
    def __init__(
        self,
        kind: str,
        target_name: str,
        line: int,
        token: str,
        condition: z3.ExprRef,
        node: ast.AST,
        enclosing_conditions: list[z3.ExprRef],
    ) -> None:
        self.kind = kind
        self.target_name = target_name
        self.line = line
        self.token = token
        self.condition = condition
        self.node = node
        self.enclosing_conditions = enclosing_conditions

    def __repr__(self) -> str:
        return f"TargetSite({self.kind}, {self.target_name}, line={self.line})"


def collect_target_sites(
    stmts: list[ast.stmt],
    ctx: SymbolicContext,
    initial_cond: z3.ExprRef | None = None,
    budget: WorkBudget | None = None,
    path_counter: list[int] | None = None,
    deadline: float | None = None,
) -> list[TargetSite]:
    if initial_cond is None:
        initial_cond = z3.BoolVal(True)

    sites: list[TargetSite] = []

    def walk_block(
        block: list[ast.stmt], current_cond: z3.ExprRef, enclosing_conds: list[z3.ExprRef]
    ) -> z3.ExprRef:
        if deadline is not None and time.monotonic() > deadline:
            raise BudgetExhaustedError("cold_deadline_seconds exceeded")
        cont_cond = current_cond
        for stmt in block:
            if deadline is not None and time.monotonic() > deadline:
                raise BudgetExhaustedError("cold_deadline_seconds exceeded")
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                callee = getattr(call.func, "id", "")
                if not callee and isinstance(call.func, ast.Attribute):
                    callee = call.func.attr
                sites.append(
                    TargetSite("call", callee, stmt.lineno, "", cont_cond, call, list(enclosing_conds))
                )
            elif isinstance(stmt, ast.Raise):
                exc_name = ""
                if isinstance(stmt.exc, ast.Call):
                    exc_name = getattr(stmt.exc.func, "id", "")
                elif isinstance(stmt.exc, ast.Name):
                    exc_name = stmt.exc.id
                sites.append(
                    TargetSite("raise", exc_name, stmt.lineno, "", cont_cond, stmt, list(enclosing_conds))
                )
                cont_cond = z3.BoolVal(False)
                break
            elif isinstance(stmt, ast.Return):
                sites.append(
                    TargetSite("return", "return", stmt.lineno, "", cont_cond, stmt, list(enclosing_conds))
                )
                cont_cond = z3.BoolVal(False)
                break
            elif isinstance(stmt, ast.If):
                if path_counter is not None and budget is not None:
                    path_counter[0] += 1
                    if path_counter[0] > budget.max_symbolic_paths:
                        raise BudgetExhaustedError(
                            f"max_symbolic_paths limit exceeded ({path_counter[0]} > {budget.max_symbolic_paths})"
                        )
                test_cond = ast_to_z3(stmt.test, ctx)
                then_cond = z3.And(cont_cond, test_cond)
                else_cond = z3.And(cont_cond, z3.Not(test_cond))

                then_exit = walk_block(stmt.body, then_cond, enclosing_conds + [test_cond])
                else_exit = (
                    walk_block(stmt.orelse, else_cond, enclosing_conds + [z3.Not(test_cond)])
                    if stmt.orelse
                    else else_cond
                )
                cont_cond = z3.Or(then_exit, else_exit)
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Pass)):
                continue
            elif isinstance(stmt, ast.Expr):
                if isinstance(stmt.value, ast.Constant):
                    continue
                raise UnsupportedControlFlowError(
                    stmt, f"unsupported expression statement {type(stmt.value).__name__}"
                )
            elif isinstance(
                stmt,
                (
                    ast.While,
                    ast.For,
                    ast.AsyncFor,
                    ast.Try,
                    *([ast.TryStar] if hasattr(ast, "TryStar") else []),
                    ast.With,
                    ast.AsyncWith,
                ),
            ):
                raise UnsupportedControlFlowError(stmt, f"unsupported control flow {type(stmt).__name__}")
            else:
                raise UnsupportedControlFlowError(stmt, f"unsupported statement {type(stmt).__name__}")

        return cont_cond

    walk_block(stmts, initial_cond, [])
    return sites


def ast_body_digest(tree: ast.AST) -> str:
    """Compute structural AST digest excluding docstrings without full AST deepcopy."""
    restorations: list[tuple[ast.AST, list[ast.stmt]]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                restorations.append((node, node.body))
                node.body = node.body[1:]
    try:
        dump = ast.dump(tree, annotate_fields=False, include_attributes=False)
        return hashlib.sha256(dump.encode("utf-8")).hexdigest()
    finally:
        for node, orig_body in reversed(restorations):
            node.body = orig_body


def build_enclosing_function_map(tree: ast.AST) -> dict[int, str]:
    """Map each AST node id to its outermost enclosing function name."""
    mapping: dict[int, str] = {}
    stack: list[tuple[ast.AST, str]] = [(tree, "")]
    while stack:
        node, current_fn = stack.pop()
        outer_fn = current_fn
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not outer_fn:
                outer_fn = node.name
            mapping[id(node)] = outer_fn
        elif outer_fn:
            mapping[id(node)] = outer_fn
        for child in ast.iter_child_nodes(node):
            stack.append((child, outer_fn))
    return mapping


def node_to_var_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        val = node_to_var_name(node.value)
        return f"{val}.{node.attr}" if val else node.attr
    if isinstance(node, ast.Constant):
        return str(node.value)
    return ""


def extract_model_dict(z3_model: z3.ModelRef) -> dict[str, Any]:
    """Extract variables and concrete values from a Z3 solver model."""
    model_dict: dict[str, Any] = {}
    for d in z3_model.decls():
        name = d.name()
        val = z3_model[d]
        if z3.is_bool(val):
            model_dict[name] = bool(val)
        elif z3.is_int(val):
            model_dict[name] = val.as_long()
        elif z3.is_string(val):
            model_dict[name] = val.as_string()
    return model_dict


def has_null_check(fn: ast.AST) -> tuple[bool, str]:
    """Inspect AST for explicit None checks on variable access paths."""
    for n in ast.walk(fn):
        if isinstance(n, ast.Compare):
            for op, comp in zip(n.ops, n.comparators):
                if isinstance(op, (ast.IsNot, ast.Is)) and isinstance(comp, ast.Constant) and comp.value is None:
                    var_name = node_to_var_name(n.left)
                    if var_name and var_name != "None":
                        return True, var_name
                if isinstance(op, (ast.IsNot, ast.Is)) and isinstance(n.left, ast.Constant) and n.left.value is None:
                    for c in n.comparators:
                        var_name = node_to_var_name(c)
                        if var_name and var_name != "None":
                            return True, var_name
    return False, ""


__all__ = [
    "BudgetExhaustedError",
    "SymbolicContext",
    "TargetSite",
    "UnsupportedControlFlowError",
    "UnsupportedExpressionError",
    "ast_body_digest",
    "ast_to_z3",
    "build_enclosing_function_map",
    "collect_target_sites",
    "extract_model_dict",
    "has_null_check",
    "node_to_var_name",
]
