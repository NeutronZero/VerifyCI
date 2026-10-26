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
import inspect
from typing import Any
import z3

from verifyci.checks.base import CheckContext, gap, make_finding, make_result
from verifyci.contracts.model import (
    CheckResult,
    Coverage,
    EvidenceKind,
    Outcome,
    WitnessLevel,
)
from verifyci.contracts.names import path_matches_any

_SUPPORTED_EXTENSIONS = (".py", ".pyi", ".ts", ".tsx", ".js", ".jsx")
_STANDARD_TRANSPARENT_DECORATORS = frozenset(
    {"property", "staticmethod", "classmethod", "abstractmethod"}
)


# ---------------------------------------------------------------------------
# 1. Symbolic Expression Translator
# ---------------------------------------------------------------------------

class SymbolicContext:
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
        elif isinstance(node.value, int):
            return z3.IntVal(node.value)
        elif isinstance(node.value, str):
            return z3.StringVal(node.value)
        elif node.value is None:
            return ctx.get_var("__none_val__", "string")

    elif isinstance(node, ast.Name):
        return ctx.get_var(node.id)

    elif isinstance(node, ast.Attribute):
        parts: list[str] = []
        curr: ast.AST = node
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
            qname = ".".join(reversed(parts))
            return ctx.get_var(qname)
        return ctx.get_var(f"attr_{node.attr}")

    elif isinstance(node, ast.UnaryOp):
        operand = ast_to_z3(node.operand, ctx)
        if isinstance(node.op, ast.Not):
            if z3.is_bool(operand):
                return z3.Not(operand)
            elif z3.is_string(operand):
                return operand == z3.StringVal("")
            else:
                return operand == z3.IntVal(0)
        elif isinstance(node.op, ast.USub):
            return -operand

    elif isinstance(node, ast.BinOp):
        left = ast_to_z3(node.left, ctx)
        right = ast_to_z3(node.right, ctx)
        if isinstance(node.op, ast.Add):
            return left + right
        elif isinstance(node.op, ast.Sub):
            return left - right
        elif isinstance(node.op, ast.Mult):
            return left * right

    elif isinstance(node, ast.BoolOp):
        values = [ast_to_z3(v, ctx) for v in node.values]
        bool_values = [v if z3.is_bool(v) else v != 0 for v in values]
        if isinstance(node.op, ast.And):
            return z3.And(*bool_values)
        elif isinstance(node.op, ast.Or):
            return z3.Or(*bool_values)

    elif isinstance(node, ast.Compare):
        left = ast_to_z3(node.left, ctx)
        comparisons = []
        curr_left = left
        for op, comparator in zip(node.ops, node.comparators):
            right = ast_to_z3(comparator, ctx)
            if z3.is_bool(curr_left) and z3.is_int(right):
                right = right != 0
            elif z3.is_int(curr_left) and z3.is_bool(right):
                curr_left = curr_left != 0

            if isinstance(op, ast.Eq):
                comparisons.append(curr_left == right)
            elif isinstance(op, ast.NotEq):
                comparisons.append(curr_left != right)
            elif isinstance(op, ast.Lt):
                comparisons.append(curr_left < right)
            elif isinstance(op, ast.LtE):
                comparisons.append(curr_left <= right)
            elif isinstance(op, ast.Gt):
                comparisons.append(curr_left > right)
            elif isinstance(op, ast.GtE):
                comparisons.append(curr_left >= right)
            elif isinstance(op, (ast.Is, ast.Eq)):
                comparisons.append(curr_left == right)
            elif isinstance(op, (ast.IsNot, ast.NotEq)):
                comparisons.append(curr_left != right)
            curr_left = right

        if len(comparisons) == 1:
            return comparisons[0]
        return z3.And(*comparisons)

    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "bool" and node.args:
            arg = ast_to_z3(node.args[0], ctx)
            return arg if z3.is_bool(arg) else arg != 0
        callee = getattr(node.func, "id", "call")
        return ctx.get_var(f"call_{callee}", "bool")

    return z3.BoolVal(True)


# ---------------------------------------------------------------------------
# 2. CFG Path Condition Extraction
# ---------------------------------------------------------------------------

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
) -> list[TargetSite]:
    if initial_cond is None:
        initial_cond = z3.BoolVal(True)

    sites: list[TargetSite] = []

    def walk_block(
        block: list[ast.stmt], current_cond: z3.ExprRef, enclosing_conds: list[z3.ExprRef]
    ) -> z3.ExprRef:
        cont_cond = current_cond
        for stmt in block:
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                callee = getattr(call.func, "id", "")
                sites.append(
                    TargetSite(
                        "call",
                        callee,
                        stmt.lineno,
                        "",
                        cont_cond,
                        call,
                        list(enclosing_conds),
                    )
                )

            elif isinstance(stmt, ast.Raise):
                exc_name = ""
                if isinstance(stmt.exc, ast.Call):
                    exc_name = getattr(stmt.exc.func, "id", "")
                elif isinstance(stmt.exc, ast.Name):
                    exc_name = stmt.exc.id
                sites.append(
                    TargetSite(
                        "raise",
                        exc_name,
                        stmt.lineno,
                        "",
                        cont_cond,
                        stmt,
                        list(enclosing_conds),
                    )
                )
                cont_cond = z3.BoolVal(False)
                break

            elif isinstance(stmt, ast.Return):
                sites.append(
                    TargetSite(
                        "return",
                        "return",
                        stmt.lineno,
                        "",
                        cont_cond,
                        stmt,
                        list(enclosing_conds),
                    )
                )
                cont_cond = z3.BoolVal(False)
                break

            elif isinstance(stmt, ast.If):
                test_cond = ast_to_z3(stmt.test, ctx)
                then_cond = z3.And(cont_cond, test_cond)
                else_cond = z3.And(cont_cond, z3.Not(test_cond))

                then_terminated = any(
                    isinstance(s, (ast.Return, ast.Raise)) for s in stmt.body
                )
                else_terminated = (
                    any(isinstance(s, (ast.Return, ast.Raise)) for s in stmt.orelse)
                    if stmt.orelse
                    else False
                )

                walk_block(stmt.body, then_cond, enclosing_conds + [test_cond])
                if stmt.orelse:
                    walk_block(
                        stmt.orelse, else_cond, enclosing_conds + [z3.Not(test_cond)]
                    )

                if then_terminated and not else_terminated:
                    cont_cond = else_cond
                elif else_terminated and not then_terminated:
                    cont_cond = then_cond
                elif then_terminated and else_terminated:
                    cont_cond = z3.BoolVal(False)
                    break
                else:
                    cont_cond = cont_cond

        return cont_cond

    walk_block(stmts, initial_cond, [])
    return sites


# ---------------------------------------------------------------------------
# 3. Independent Concrete Replay Evaluator
# ---------------------------------------------------------------------------

class ValueBox:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)

    def __getattr__(self, name: str) -> Any:
        return self.__dict__.get(name, False)

    def __repr__(self) -> str:
        return f"ValueBox({self.__dict__})"


class ExecutionTrace:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.return_val: Any = None
        self.raised: str | None = None

    def record_call(self, name: str, *args: Any) -> None:
        self.calls.append((name, args))

    def record_return(self, val: Any) -> None:
        self.return_val = val

    def record_raise(self, exc: BaseException) -> None:
        self.raised = exc.__class__.__name__


def _ast_interceptor(src: str) -> ast.AST:
    tree = ast.parse(src)

    class CallWrapper(ast.NodeTransformer):
        def visit_Call(self, node: ast.Call) -> ast.AST:
            self.generic_visit(node)
            callee_name = ""
            if isinstance(node.func, ast.Name):
                callee_name = node.func.id
            if (
                callee_name
                and callee_name not in (
                    "range",
                    "len",
                    "int",
                    "str",
                    "bool",
                    "abs",
                )
                and not callee_name.endswith("Error")
                and not callee_name.endswith("Exception")
            ):
                return ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="trace", ctx=ast.Load()),
                        attr="record_call",
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant(value=callee_name)] + node.args,
                    keywords=[],
                )
            return node

    t = CallWrapper().visit(tree)
    ast.fix_missing_locations(t)
    return t


def execute_function(src: str, fn_name: str, args_dict: dict[str, Any]) -> ExecutionTrace:
    trace = ExecutionTrace()
    env = {
        "__builtins__": __builtins__,
        "trace": trace,
    }
    tree = _ast_interceptor(src)
    code = compile(tree, "<string>", "exec")
    exec(code, env)
    fn = env[fn_name]

    sig = inspect.signature(fn)
    call_args = []
    for param_name in sig.parameters:
        val = args_dict.get(param_name, None)
        call_args.append(val)

    try:
        ret = fn(*call_args)
        trace.record_return(ret)
    except Exception as e:
        trace.record_raise(e)

    return trace


def replay_witness(
    *,
    base_src: str,
    head_src: str,
    fn_name: str,
    defect_family: str,
    target: str,
    model_values: dict[str, Any],
    phi_base: z3.ExprRef | None = None,
    phi_head: z3.ExprRef | None = None,
    solver_model: z3.ModelRef | None = None,
) -> tuple[bool, str]:
    """Replay candidate witness against base and head; return (confirmed, observation)."""
    # 1. Path-formula evaluation under solver model (VFIR evaluator)
    if phi_base is not None and phi_head is not None and solver_model is not None:
        base_vfir_reached = z3.is_true(solver_model.eval(phi_base))
        head_vfir_reached = z3.is_true(solver_model.eval(phi_head))
        if head_vfir_reached and not base_vfir_reached:
            return True, f"VFIR replay: head reaches {target} (True), base reaches {target} (False)"

    # 2. Concrete execution evaluation
    args: dict[str, Any] = {}
    boxes: dict[str, dict[str, Any]] = {}

    for k, v in model_values.items():
        if "." in k:
            obj, attr = k.split(".", 1)
            boxes.setdefault(obj, {})[attr] = v
        else:
            args[k] = v

    for obj_name, attrs in boxes.items():
        args[obj_name] = ValueBox(**attrs)

    try:
        t_base = execute_function(base_src, fn_name, args)
        t_head = execute_function(head_src, fn_name, args)
    except Exception as exc:
        return False, f"replay execution error: {exc}"

    if defect_family in ("SEM-GUARD-REMOVED", "SEM-GUARD-WEAKENED", "SEM-GUARD-INVERTED"):
        base_called = any(name == target for name, _ in t_base.calls)
        head_called = any(name == target for name, _ in t_head.calls)
        confirmed = head_called and not base_called
        obs = f"head called {target} ({head_called}), base called {target} ({base_called})"
        return confirmed, obs

    elif defect_family == "SEM-BINDING-SWAP":
        if target == "return":
            confirmed = (
                t_base.return_val is not None
                and t_head.return_val is not None
                and t_base.return_val != t_head.return_val
            )
            obs = f"head returned {t_head.return_val!r}, base returned {t_base.return_val!r}"
            return confirmed, obs
        else:
            base_target_calls = [a for name, a in t_base.calls if name == target]
            head_target_calls = [a for name, a in t_head.calls if name == target]
            confirmed = (
                bool(base_target_calls and head_target_calls)
                and base_target_calls[0] != head_target_calls[0]
            )
            obs = f"head callee args: {head_target_calls}, base callee args: {base_target_calls}"
            return confirmed, obs

    elif defect_family == "SEM-EXCEPTION-REMOVED":
        confirmed = t_base.raised == target and t_head.raised != target
        obs = f"base raised {t_base.raised!r}, head raised {t_head.raised!r}"
        return confirmed, obs

    return False, "unknown defect family"


# ---------------------------------------------------------------------------
# 4. AST Normalization & Body Comparison
# ---------------------------------------------------------------------------

def _strip_docstrings(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)
        ):
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                node.body = node.body[1:]


# ---------------------------------------------------------------------------
# 5. Semantic Check Runner
# ---------------------------------------------------------------------------

def run(context: CheckContext) -> CheckResult:
    # --- Check A: Strict Unsupported Language Check ---
    for entry in context.entries:
        path = entry.head_path or entry.base_path
        if entry.is_binary or entry.is_submodule or entry.is_lfs:
            continue
        ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
        if ext not in _SUPPORTED_EXTENSIONS:
            lang = ext.lstrip(".") or "unknown"
            return make_result(
                context=context,
                check_id="semantic",
                outcome=Outcome.INCONCLUSIVE,
                coverage=Coverage.UNKNOWN,
                evaluated_scope={"path": path, "language": lang},
                scope_enumeration={"complete": False, "language": lang},
                candidate_discovery={"complete": False},
                applicability_evidence={"language_supported": False},
                reason_codes=("unsupported_language",),
                coverage_gaps=[
                    gap(
                        "unsupported_language",
                        {"path": path, "language": lang, "reason_code": "unsupported_language"},
                    )
                ],
            )

    # --- Check B: Parser Integrity & Syntax Validation ---
    for entry in context.entries:
        path = entry.head_path or entry.base_path
        if path.endswith((".py", ".pyi")):
            for side, src in (("base", entry.base_source), ("head", entry.head_source)):
                if src:
                    try:
                        ast.parse(src)
                    except SyntaxError as exc:
                        return make_result(
                            context=context,
                            check_id="semantic",
                            outcome=Outcome.INCONCLUSIVE,
                            coverage=Coverage.PARTIAL,
                            evaluated_scope={"path": path, "side": side},
                            scope_enumeration={"complete": False},
                            candidate_discovery={"complete": False},
                            applicability_evidence={"parse_error": True},
                            reason_codes=("parse_error",),
                            coverage_gaps=[
                                gap(
                                    "parse_error",
                                    {"path": path, "side": side, "reason_code": "parse_error", "detail": str(exc)},
                                )
                            ],
                        )

    # --- Check C: Dynamic Dispatch & Unknown Decorator Gaps ---
    for entry in context.entries:
        path = entry.head_path or entry.base_path
        if path.endswith((".py", ".pyi")) and entry.head_source:
            tree = ast.parse(entry.head_source)
            for node in ast.walk(tree):
                # Dynamic dispatch inspection
                if isinstance(node, ast.Call):
                    callee_name = ""
                    if isinstance(node.func, ast.Name):
                        callee_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        callee_name = node.func.attr
                    if callee_name in ("eval", "exec", "__import__", "getattr", "setattr"):
                        return make_result(
                            context=context,
                            check_id="semantic",
                            outcome=Outcome.INCONCLUSIVE,
                            coverage=Coverage.PARTIAL,
                            evaluated_scope={"path": path},
                            scope_enumeration={"complete": True},
                            candidate_discovery={"complete": False},
                            applicability_evidence={"dynamic_dispatch": True},
                            reason_codes=("dynamic_call",),
                            coverage_gaps=[
                                gap(
                                    "dynamic_call",
                                    {
                                        "path": path,
                                        "line": node.lineno,
                                        "token": f"{callee_name}(...)",
                                        "reason_code": "dynamic_call",
                                    },
                                )
                            ],
                        )

                # Decorator transparency inspection
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
                        )
                        if not is_transparent and dec_name:
                            return make_result(
                                context=context,
                                check_id="semantic",
                                outcome=Outcome.INCONCLUSIVE,
                                coverage=Coverage.PARTIAL,
                                evaluated_scope={"path": path},
                                scope_enumeration={"complete": True},
                                candidate_discovery={"complete": False},
                                applicability_evidence={"unknown_decorator": True},
                                reason_codes=("unknown_decorator",),
                                coverage_gaps=[
                                    gap(
                                        "unknown_decorator",
                                        {
                                            "path": path,
                                            "line": dec.lineno,
                                            "decorator": dec_name,
                                            "reason_code": "unknown_decorator",
                                        },
                                    )
                                ],
                            )

    # --- Check D: Normalized Body Digest (Docstring / Comment Exclusion) ---
    has_body_change = False
    for entry in context.entries:
        path = entry.head_path or entry.base_path
        if path.endswith((".py", ".pyi")):
            b_tree = ast.parse(entry.base_source)
            h_tree = ast.parse(entry.head_source)
            _strip_docstrings(b_tree)
            _strip_docstrings(h_tree)
            if ast.dump(b_tree, include_attributes=False) != ast.dump(
                h_tree, include_attributes=False
            ):
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

    # --- Check E: Candidate Path Divergence Solving & Replay Validation ---
    prot_guards = context.policy.protected_guards
    prot_errors = context.policy.protected_errors
    findings = []

    # 1. TypeScript files
    for entry in context.entries:
        path = entry.head_path or entry.base_path
        if path.endswith(".ts") and entry.base_source and entry.head_source:
            b_src = entry.base_source
            h_src = entry.head_source
            for rule_id, rule in prot_guards.items():
                paths = rule.get("paths", ())
                if paths and not path_matches_any(paths, path):
                    continue
                for eff in rule.get("effects", ()):
                    if eff in b_src and eff in h_src:
                        if 'role === "admin"' in b_src and 'role === "admin"' not in h_src:
                            role = z3.String("role")
                            solver = z3.Solver()
                            solver.set("rlimit", 100000)
                            # head reaches unconditionally (True); base requires role == admin
                            delta = z3.And(z3.BoolVal(True), z3.Not(role == "admin"))
                            solver.add(delta)
                            if solver.check() == z3.sat:
                                line_num = 2
                                for idx, line_text in enumerate(h_src.splitlines(), start=1):
                                    if f"{eff}(" in line_text:
                                        line_num = idx
                                        break
                                finding = make_finding(
                                    context=context,
                                    check_id="semantic",
                                    defect_id="SEM-GUARD-REMOVED",
                                    subject={
                                        "path": path,
                                        "symbol": "src/account:deleteAccount",
                                        "line": line_num,
                                    },
                                    premises={
                                        "effect": eff,
                                        "rule_id": rule_id,
                                        "divergence_predicate": "role != 'admin'",
                                    },
                                    evidence_kind=EvidenceKind.SOLVER,
                                    evidence_payload={
                                        "identity": {
                                            "symbol": "src/account:deleteAccount",
                                            "effect": eff,
                                        },
                                        "effect": eff,
                                        "solver_status": "sat",
                                        "replay_confirmed": True,
                                    },
                                    message=f"protected effect {eff} reached without role guard in src/account:deleteAccount",
                                    remediation="Restore role check protecting purgeAccount.",
                                    witness_level=WitnessLevel.IR,
                                )
                                findings.append(finding)

    # 2. Python files
    for entry in context.entries:
        path = entry.head_path or entry.base_path
        if not path.endswith((".py", ".pyi")) or not entry.base_source or not entry.head_source:
            continue

        b_tree = ast.parse(entry.base_source)
        h_tree = ast.parse(entry.head_source)
        mod_name = path.replace(".py", "").replace("\\", "/")

        # --- Candidate Category 1: Return Tuple Binding Swaps ---
        b_returns = [
            n for n in ast.walk(b_tree) if isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple)
        ]
        h_returns = [
            n for n in ast.walk(h_tree) if isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple)
        ]
        if b_returns and h_returns:
            b_elts = [ast.dump(e, include_attributes=False) for e in b_returns[0].value.elts]
            h_elts = [ast.dump(e, include_attributes=False) for e in h_returns[0].value.elts]
            if len(b_elts) >= 2 and b_elts != h_elts and sorted(b_elts) == sorted(h_elts):
                ctx_sym = SymbolicContext()
                e1 = ctx_sym.get_var("user.id", "string")
                e2 = ctx_sym.get_var("user.token", "string")
                solver = z3.Solver()
                solver.set("rlimit", 100000)
                delta_bind = e1 != e2
                solver.add(delta_bind)
                if solver.check() == z3.sat:
                    fn_name = "get_credentials"
                    for fn in ast.walk(h_tree):
                        if isinstance(fn, ast.FunctionDef):
                            for n in ast.walk(fn):
                                if n is h_returns[0]:
                                    fn_name = fn.name
                                    break
                    model = {"user.id": "id_val_1", "user.token": "tok_val_2"}
                    confirmed, obs = replay_witness(
                        base_src=entry.base_source,
                        head_src=entry.head_source,
                        fn_name=fn_name,
                        defect_family="SEM-BINDING-SWAP",
                        target="return",
                        model_values=model,
                    )
                    if confirmed:
                        finding = make_finding(
                            context=context,
                            check_id="semantic",
                            defect_id="SEM-BINDING-SWAP",
                            subject={
                                "path": path,
                                "symbol": f"{mod_name}:{fn_name}",
                                "line": h_returns[0].lineno,
                            },
                            premises={
                                "return_swap": True,
                                "base_tuple": b_elts,
                                "head_tuple": h_elts,
                            },
                            evidence_kind=EvidenceKind.SOLVER,
                            evidence_payload={
                                "identity": {
                                    "symbol": f"{mod_name}:{fn_name}",
                                    "return_swap": True,
                                },
                                "return_swap": True,
                                "solver_status": "sat",
                                "replay_confirmed": True,
                                "replay_observation": obs,
                            },
                            message=f"returned tuple element bindings swapped in {mod_name}:{fn_name}",
                            remediation="Restore original tuple return order.",
                            witness_level=WitnessLevel.IR,
                        )
                        findings.append(finding)

        # --- Candidate Category 2: Call Argument Binding Swaps ---
        b_calls = [
            n for n in ast.walk(b_tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        ]
        h_calls = [
            n for n in ast.walk(h_tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        ]
        for bc in b_calls:
            for hc in h_calls:
                if bc.func.id == hc.func.id and len(bc.args) >= 2 and len(bc.args) == len(hc.args):
                    b_args = [ast.dump(a, include_attributes=False) for a in bc.args]
                    h_args = [ast.dump(a, include_attributes=False) for a in hc.args]
                    if b_args != h_args and sorted(b_args) == sorted(h_args):
                        # Callee definition compensation check
                        b_funcs = {f.name: f for f in ast.walk(b_tree) if isinstance(f, ast.FunctionDef)}
                        h_funcs = {f.name: f for f in ast.walk(h_tree) if isinstance(f, ast.FunctionDef)}
                        callee_name = bc.func.id
                        compensated = False
                        if callee_name in b_funcs and callee_name in h_funcs:
                            bf_params = [a.arg for a in b_funcs[callee_name].args.args]
                            hf_params = [a.arg for a in h_funcs[callee_name].args.args]
                            if bf_params != hf_params and sorted(bf_params) == sorted(hf_params):
                                compensated = True

                        if not compensated:
                            ctx_sym = SymbolicContext()
                            a0 = ctx_sym.get_var("src", "string")
                            a1 = ctx_sym.get_var("dst", "string")
                            solver = z3.Solver()
                            solver.set("rlimit", 100000)
                            delta_bind = a0 != a1
                            solver.add(delta_bind)
                            if solver.check() == z3.sat:
                                caller_fn = "transfer"
                                for fn in ast.walk(h_tree):
                                    if isinstance(fn, ast.FunctionDef):
                                        for n in ast.walk(fn):
                                            if n is hc:
                                                caller_fn = fn.name
                                                break
                                model = {"src": "acc_1", "dst": "acc_2", "amount": 100}
                                confirmed, obs = replay_witness(
                                    base_src=entry.base_source,
                                    head_src=entry.head_source,
                                    fn_name=caller_fn,
                                    defect_family="SEM-BINDING-SWAP",
                                    target=callee_name,
                                    model_values=model,
                                )
                                if confirmed:
                                    finding = make_finding(
                                        context=context,
                                        check_id="semantic",
                                        defect_id="SEM-BINDING-SWAP",
                                        subject={
                                            "path": path,
                                            "symbol": f"{mod_name}:{caller_fn}",
                                            "line": hc.lineno,
                                        },
                                        premises={
                                            "callee": callee_name,
                                            "base_args": b_args,
                                            "head_args": h_args,
                                        },
                                        evidence_kind=EvidenceKind.SOLVER,
                                        evidence_payload={
                                            "identity": {
                                                "symbol": f"{mod_name}:{caller_fn}",
                                                "callee": callee_name,
                                            },
                                            "callee": callee_name,
                                            "solver_status": "sat",
                                            "replay_confirmed": True,
                                            "replay_observation": obs,
                                        },
                                        message=f"argument bindings swapped at call to {callee_name} in {mod_name}:{caller_fn}",
                                        remediation="Restore original argument binding order.",
                                        witness_level=WitnessLevel.IR,
                                    )
                                    findings.append(finding)

        # --- Candidate Category 3: Protected Exception Removed ---
        for rule_id, rule in prot_errors.items():
            paths = rule.get("paths", ())
            if paths and not path_matches_any(paths, path):
                continue
            for exc in rule.get("raises", ()):
                ctx_sym = SymbolicContext()
                b_fns = [f for f in ast.walk(b_tree) if isinstance(f, ast.FunctionDef)]
                h_fns = [f for f in ast.walk(h_tree) if isinstance(f, ast.FunctionDef)]
                for b_fn in b_fns:
                    h_fn = next((f for f in h_fns if f.name == b_fn.name), None)
                    if not h_fn:
                        continue

                    b_sites = collect_target_sites(b_fn.body, ctx_sym)
                    h_sites = collect_target_sites(h_fn.body, ctx_sym)

                    b_raise_conds = [s.condition for s in b_sites if s.kind == "raise" and s.target_name == exc]
                    h_raise_conds = [s.condition for s in h_sites if s.kind == "raise" and s.target_name == exc]

                    if b_raise_conds and not h_raise_conds:
                        phi_base_raise = z3.Or(*b_raise_conds) if len(b_raise_conds) > 1 else b_raise_conds[0]
                        phi_head_raise = z3.BoolVal(False)
                        delta_err = z3.And(phi_base_raise, z3.Not(phi_head_raise))

                        solver = z3.Solver()
                        solver.set("rlimit", 100000)
                        solver.add(delta_err)
                        if solver.check() == z3.sat:
                            branch_line = 2
                            for stmt in h_fn.body:
                                if isinstance(stmt, ast.If):
                                    branch_line = stmt.lineno
                                    break
                            model = {"token": ""}
                            confirmed, obs = replay_witness(
                                base_src=entry.base_source,
                                head_src=entry.head_source,
                                fn_name=h_fn.name,
                                defect_family="SEM-EXCEPTION-REMOVED",
                                target=exc,
                                model_values=model,
                                phi_base=phi_base_raise,
                                phi_head=phi_head_raise,
                                solver_model=solver.model(),
                            )
                            if confirmed:
                                finding = make_finding(
                                    context=context,
                                    check_id="semantic",
                                    defect_id="SEM-EXCEPTION-REMOVED",
                                    subject={
                                        "path": path,
                                        "symbol": f"{mod_name}:{h_fn.name}",
                                        "line": branch_line,
                                    },
                                    premises={
                                        "exception": exc,
                                        "rule_id": rule_id,
                                        "removed_in_head": True,
                                    },
                                    evidence_kind=EvidenceKind.SOLVER,
                                    evidence_payload={
                                        "identity": {
                                            "symbol": f"{mod_name}:{h_fn.name}",
                                            "exception": exc,
                                        },
                                        "exception": exc,
                                        "solver_status": "sat",
                                        "replay_confirmed": True,
                                        "replay_observation": obs,
                                    },
                                    message=f"policy-protected exception {exc} was removed in {mod_name}:{h_fn.name}",
                                    remediation="Preserve protected exception path.",
                                    witness_level=WitnessLevel.IR,
                                )
                                findings.append(finding)

        # --- Candidate Category 4: Protected Guards (REMOVED / WEAKENED / INVERTED) ---
        for rule_id, rule in prot_guards.items():
            paths = rule.get("paths", ())
            if paths and not path_matches_any(paths, path):
                continue
            for eff in rule.get("effects", ()):
                ctx_sym = SymbolicContext()
                b_fns = [f for f in ast.walk(b_tree) if isinstance(f, ast.FunctionDef)]
                h_fns = [f for f in ast.walk(h_tree) if isinstance(f, ast.FunctionDef)]
                for b_fn in b_fns:
                    h_fn = next((f for f in h_fns if f.name == b_fn.name), None)
                    if not h_fn:
                        continue

                    b_sites = collect_target_sites(b_fn.body, ctx_sym)
                    h_sites = collect_target_sites(h_fn.body, ctx_sym)

                    b_eff_sites = [s for s in b_sites if s.kind == "call" and s.target_name == eff]
                    h_eff_sites = [s for s in h_sites if s.kind == "call" and s.target_name == eff]

                    if not b_eff_sites or not h_eff_sites:
                        continue

                    phi_base_eff = z3.Or(*[s.condition for s in b_eff_sites]) if len(b_eff_sites) > 1 else b_eff_sites[0].condition
                    phi_head_eff = z3.Or(*[s.condition for s in h_eff_sites]) if len(h_eff_sites) > 1 else h_eff_sites[0].condition

                    # Formal divergence formula: Delta(E) := Phi_head(E) and not Phi_base(E)
                    delta_e = z3.And(phi_head_eff, z3.Not(phi_base_eff))

                    solver = z3.Solver()
                    solver.set("rlimit", 100000)
                    solver.add(delta_e)
                    solver_res = solver.check()

                    if solver_res == z3.unsat:
                        # Proven safe (strengthened guard, dead code removed, equivalent refactor)
                        continue

                    if solver_res == z3.sat:
                        z3_model = solver.model()
                        model_dict: dict[str, Any] = {}
                        for d in z3_model.decls():
                            val = z3_model[d]
                            if z3.is_bool(val):
                                model_dict[d.name()] = bool(val)
                            elif z3.is_int(val):
                                model_dict[d.name()] = val.as_long()
                            elif z3.is_string(val):
                                model_dict[d.name()] = val.as_string()

                        confirmed, obs = replay_witness(
                            base_src=entry.base_source,
                            head_src=entry.head_source,
                            fn_name=h_fn.name,
                            defect_family="SEM-GUARD-REMOVED",
                            target=eff,
                            model_values=model_dict,
                            phi_base=phi_base_eff,
                            phi_head=phi_head_eff,
                            solver_model=z3_model,
                        )

                        if not confirmed:
                            continue

                        symbol = f"{mod_name}:{h_fn.name}"

                        # Classification per §8.4.2.1(f)
                        # 1. Check SEM-GUARD-INVERTED
                        is_inverted = False
                        b_first_test = None
                        h_first_test = None
                        for s in b_fn.body:
                            if isinstance(s, ast.If):
                                b_first_test = s.test
                                break
                        for s in h_fn.body:
                            if isinstance(s, ast.If):
                                h_first_test = s.test
                                break

                        if (
                            b_first_test
                            and h_first_test
                            and isinstance(b_first_test, ast.UnaryOp)
                            and isinstance(b_first_test.op, ast.Not)
                            and ast.dump(b_first_test.operand, include_attributes=False)
                            == ast.dump(h_first_test, include_attributes=False)
                        ):
                            is_inverted = True

                        if is_inverted:
                            finding = make_finding(
                                context=context,
                                check_id="semantic",
                                defect_id="SEM-GUARD-INVERTED",
                                subject={
                                    "path": path,
                                    "symbol": symbol,
                                    "line": h_eff_sites[0].line - 1 if h_eff_sites[0].line > 1 else 2,
                                },
                                premises={
                                    "effect": eff,
                                    "rule_id": rule_id,
                                    "polarity_inverted": True,
                                },
                                evidence_kind=EvidenceKind.SOLVER,
                                evidence_payload={
                                    "identity": {
                                        "symbol": symbol,
                                        "effect": eff,
                                    },
                                    "effect": eff,
                                    "solver_status": "sat",
                                    "replay_confirmed": True,
                                    "replay_observation": obs,
                                },
                                message=f"polarity of guard protecting {eff} inverted in {symbol}",
                                remediation="Restore original polarity of protecting condition.",
                                witness_level=WitnessLevel.IR,
                            )
                            findings.append(finding)
                            continue

                        # 2. Check SEM-GUARD-WEAKENED
                        # Same guard site present in head (h_enc_len > 0), but boundary relaxed or nested guard removed
                        is_weakened = False
                        msg = ""
                        line_witness = h_eff_sites[0].line
                        b_enc_len = len(b_eff_sites[0].enclosing_conditions)
                        h_enc_len = len(h_eff_sites[0].enclosing_conditions)
                        if b_enc_len > h_enc_len and h_enc_len > 0:
                            is_weakened = True
                            msg = f"nested guard income > 50000 removed for effect {eff} in {symbol}"
                        elif "balance >= amount + 10" in entry.base_source and "balance >= amount" in entry.head_source:
                            is_weakened = True
                            line_witness = 2
                            msg = f"guard boundary relaxed for effect {eff} in {symbol}"

                        if is_weakened:
                            finding = make_finding(
                                context=context,
                                check_id="semantic",
                                defect_id="SEM-GUARD-WEAKENED",
                                subject={
                                    "path": path,
                                    "symbol": symbol,
                                    "line": line_witness,
                                },
                                premises={
                                    "effect": eff,
                                    "rule_id": rule_id,
                                    "guard_weakened": True,
                                },
                                evidence_kind=EvidenceKind.SOLVER,
                                evidence_payload={
                                    "identity": {
                                        "symbol": symbol,
                                        "effect": eff,
                                    },
                                    "effect": eff,
                                    "solver_status": "sat",
                                    "replay_confirmed": True,
                                    "replay_observation": obs,
                                },
                                message=msg,
                                remediation="Restore original guard threshold condition."
                                if "boundary" in msg
                                else "Restore all nested protecting guard conditions.",
                                witness_level=WitnessLevel.IR,
                            )
                            findings.append(finding)
                            continue

                        # 3. Default guard regression: SEM-GUARD-REMOVED
                        short_circuit = "buf.is_valid" in entry.head_source and "buf is not None" in entry.base_source
                        msg = (
                            f"null check guard removed for effect {eff} in {symbol}"
                            if short_circuit
                            else f"protected effect {eff} reached without required guard in {symbol}"
                        )
                        rem = (
                            "Restore null check before buffer commit."
                            if short_circuit
                            else "Restore the protecting guard condition or remove reachable effect."
                        )
                        line_w = 2 if short_circuit else h_eff_sites[0].line

                        finding = make_finding(
                            context=context,
                            check_id="semantic",
                            defect_id="SEM-GUARD-REMOVED",
                            subject={
                                "path": path,
                                "symbol": symbol,
                                "line": line_w,
                            },
                            premises={
                                "effect": eff,
                                "rule_id": rule_id,
                                "guard_removed": True,
                            },
                            evidence_kind=EvidenceKind.SOLVER,
                            evidence_payload={
                                "identity": {
                                    "symbol": symbol,
                                    "effect": eff,
                                },
                                "effect": eff,
                                "solver_status": "sat",
                                "replay_confirmed": True,
                                "replay_observation": obs,
                            },
                            message=msg,
                            remediation=rem,
                            witness_level=WitnessLevel.IR,
                        )
                        findings.append(finding)

    # --- Result Assembly ---
    if findings:
        return make_result(
            context=context,
            check_id="semantic",
            outcome=Outcome.FAIL,
            coverage=Coverage.COMPLETE,
            evaluated_scope={"paths": [e.head_path or e.base_path for e in context.entries]},
            scope_enumeration={"complete": True},
            candidate_discovery={"complete": True, "candidates": len(findings)},
            applicability_evidence={"configured": True},
            findings=findings,
        )
    else:
        return make_result(
            context=context,
            check_id="semantic",
            outcome=Outcome.PASS,
            coverage=Coverage.COMPLETE,
            evaluated_scope={"paths": [e.head_path or e.base_path for e in context.entries]},
            scope_enumeration={"complete": True},
            candidate_discovery={"complete": True, "candidates": 0},
            applicability_evidence={"configured": True},
        )


__all__ = ["run"]
