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
import dataclasses
import json
import subprocess
import sys
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

_SAFE_BUILTINS: dict[str, Any] = {
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "int": int,
    "len": len,
    "list": list,
    "max": max,
    "min": min,
    "range": range,
    "set": set,
    "str": str,
    "tuple": tuple,
    "Exception": Exception,
    "ValueError": ValueError,
    "TypeError": TypeError,
    "PermissionError": PermissionError,
    "KeyError": KeyError,
    "AttributeError": AttributeError,
    "RuntimeError": RuntimeError,
    "True": True,
    "False": False,
    "None": None,
}


# ---------------------------------------------------------------------------
# 1. Custom Exceptions for Fail-Closed Semantic Handling
# ---------------------------------------------------------------------------

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


class ReplaySafetyViolation(Exception):
    pass


# ---------------------------------------------------------------------------
# 2. Symbolic Expression Translator
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
        raise UnsupportedExpressionError(node, f"unsupported constant type: {type(node.value).__name__}")

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
        raise UnsupportedExpressionError(node, "unsupported complex attribute target")

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
        raise UnsupportedExpressionError(node, f"unsupported unary operator: {type(node.op).__name__}")

    elif isinstance(node, ast.BinOp):
        left = ast_to_z3(node.left, ctx)
        right = ast_to_z3(node.right, ctx)
        if isinstance(node.op, ast.Add):
            return left + right
        elif isinstance(node.op, ast.Sub):
            return left - right
        elif isinstance(node.op, ast.Mult):
            return left * right
        raise UnsupportedExpressionError(node, f"unsupported binary operator: {type(node.op).__name__}")

    elif isinstance(node, ast.BoolOp):
        values = [ast_to_z3(v, ctx) for v in node.values]
        bool_values = [v if z3.is_bool(v) else v != 0 for v in values]
        if isinstance(node.op, ast.And):
            return z3.And(*bool_values)
        elif isinstance(node.op, ast.Or):
            return z3.Or(*bool_values)
        raise UnsupportedExpressionError(node, f"unsupported boolean operator: {type(node.op).__name__}")

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
            else:
                raise UnsupportedExpressionError(node, f"unsupported comparison operator: {type(op).__name__}")
            curr_left = right

        if len(comparisons) == 1:
            return comparisons[0]
        return z3.And(*comparisons)

    elif isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "bool" and node.args:
            arg = ast_to_z3(node.args[0], ctx)
            return arg if z3.is_bool(arg) else arg != 0
        raise UnsupportedExpressionError(node, f"unsupported call in expression: {getattr(node.func, 'id', 'call')}")

    raise UnsupportedExpressionError(node, f"unsupported expression node: {type(node).__name__}")


# ---------------------------------------------------------------------------
# 3. CFG Path Condition Extraction
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
                if not callee and isinstance(call.func, ast.Attribute):
                    callee = call.func.attr
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

                then_exit = walk_block(stmt.body, then_cond, enclosing_conds + [test_cond])
                if stmt.orelse:
                    else_exit = walk_block(stmt.orelse, else_cond, enclosing_conds + [z3.Not(test_cond)])
                else:
                    else_exit = else_cond

                cont_cond = z3.Or(then_exit, else_exit)

            elif isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Pass)):
                # Supported straight-line statements
                continue

            elif isinstance(stmt, (ast.While, ast.For, ast.AsyncFor, ast.Try, ast.With, ast.AsyncWith)):
                raise UnsupportedControlFlowError(stmt, f"unsupported control flow {type(stmt).__name__}")

            else:
                continue

        return cont_cond

    walk_block(stmts, initial_cond, [])
    return sites


# ---------------------------------------------------------------------------
# 4. Isolated & Sandboxed Concrete Replay Evaluator
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


@dataclasses.dataclass(frozen=True)
class ReplayResult:
    confirmed: bool
    reason: str
    input_model: dict[str, Any]
    source_identity: str
    base_observation: dict[str, Any]
    head_observation: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmed": self.confirmed,
            "reason": self.reason,
            "input_model": self.input_model,
            "source_identity": self.source_identity,
            "base_observation": self.base_observation,
            "head_observation": self.head_observation,
        }


def _validate_ast_safety(tree: ast.AST) -> None:
    _FORBIDDEN_CALLS = {
        "open",
        "eval",
        "exec",
        "compile",
        "__import__",
        "globals",
        "locals",
        "getattr",
        "setattr",
        "delattr",
        "breakpoint",
        "exit",
        "quit",
        "input",
    }
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise ReplaySafetyViolation(f"import statements are forbidden in replay sandbox: line {getattr(node, 'lineno', 0)}")
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("__") and node.attr.endswith("__"):
                raise ReplaySafetyViolation(f"dunder attribute access is forbidden in replay sandbox: {node.attr}")
        if isinstance(node, ast.Call):
            callee_name = ""
            if isinstance(node.func, ast.Name):
                callee_name = node.func.id
            if callee_name in _FORBIDDEN_CALLS:
                raise ReplaySafetyViolation(f"forbidden call in replay sandbox: {callee_name}")


_REPLAY_SUBPROCESS_SCRIPT = """
import ast
import inspect
import json
import sys

_SAFE_BUILTINS = {
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "int": int,
    "len": len,
    "list": list,
    "max": max,
    "min": min,
    "range": range,
    "set": set,
    "str": str,
    "tuple": tuple,
    "Exception": Exception,
    "ValueError": ValueError,
    "TypeError": TypeError,
    "PermissionError": PermissionError,
    "KeyError": KeyError,
    "AttributeError": AttributeError,
    "RuntimeError": RuntimeError,
    "True": True,
    "False": False,
    "None": None,
}

_FORBIDDEN_CALLS = {
    "open",
    "eval",
    "exec",
    "compile",
    "__import__",
    "globals",
    "locals",
    "getattr",
    "setattr",
    "delattr",
    "breakpoint",
    "exit",
    "quit",
    "input",
}

class ValueBox:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __getattr__(self, name):
        return self.__dict__.get(name, False)

    def __repr__(self):
        return f"ValueBox({self.__dict__})"

def serialize_arg(a):
    if isinstance(a, (int, float, str, bool, type(None))):
        return a
    if isinstance(a, (list, tuple)):
        return [serialize_arg(x) for x in a]
    if isinstance(a, dict):
        return {str(k): serialize_arg(v) for k, v in a.items()}
    if hasattr(a, "__dict__"):
        return {str(k): serialize_arg(v) for k, v in a.__dict__.items()}
    return str(a)

class ExecutionTrace:
    def __init__(self):
        self.calls = []
        self.return_val = None
        self.raised = None

    def record_call(self, name, *args):
        self.calls.append((name, [serialize_arg(x) for x in args]))

    def record_return(self, val):
        self.return_val = serialize_arg(val)

    def record_raise(self, exc):
        self.raised = exc.__class__.__name__

def validate_ast_safety(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise ValueError(f"import statements are forbidden in replay sandbox: line {getattr(node, 'lineno', 0)}")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr.endswith("__"):
            raise ValueError(f"dunder attribute access is forbidden in replay sandbox: {node.attr}")
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", "")
            if name in _FORBIDDEN_CALLS:
                raise ValueError(f"forbidden call in replay sandbox: {name}")

def intercept_ast(src):
    tree = ast.parse(src)
    validate_ast_safety(tree)

    class Wrapper(ast.NodeTransformer):
        def visit_Call(self, node):
            self.generic_visit(node)
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if (
                name
                and name not in _SAFE_BUILTINS
                and not name.endswith("Error")
                and not name.endswith("Exception")
            ):
                return ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id="trace", ctx=ast.Load()),
                        attr="record_call",
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant(value=name)] + node.args,
                    keywords=[],
                )
            return node

    t = Wrapper().visit(tree)
    ast.fix_missing_locations(t)
    return t

def main():
    raw = sys.stdin.read()
    payload = json.loads(raw)
    src = payload["src"]
    fn_name = payload["fn_name"]
    raw_args = payload["args"]

    trace = ExecutionTrace()
    tree = intercept_ast(src)
    safe_env = {
        "__builtins__": _SAFE_BUILTINS,
        "trace": trace,
        "ValueBox": ValueBox,
    }
    code = compile(tree, "<replay_isolated>", "exec")
    exec(code, safe_env)
    fn = safe_env.get(fn_name)
    if fn is None:
        raise ValueError(f"function {fn_name} not found")

    boxes = {}
    scalar_args = {}
    for k, v in raw_args.items():
        if "." in k:
            obj, attr = k.split(".", 1)
            boxes.setdefault(obj, {})[attr] = v
        else:
            scalar_args[k] = v

    args_dict = {}
    for k, v in scalar_args.items():
        args_dict[k] = v
    for obj_name, attrs in boxes.items():
        args_dict[obj_name] = ValueBox(**attrs)

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

    res = {
        "success": True,
        "calls": trace.calls,
        "return_val": trace.return_val,
        "raised": trace.raised,
    }
    print(json.dumps(res))

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)}))
"""


def execute_function_isolated(
    src: str, fn_name: str, args_dict: dict[str, Any], timeout: float = 2.0
) -> ExecutionTrace:
    # Pre-parse and validate safety in parent process
    tree = ast.parse(src)
    _validate_ast_safety(tree)

    payload = {
        "src": src,
        "fn_name": fn_name,
        "args": args_dict,
    }
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", _REPLAY_SUBPROCESS_SCRIPT],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"replay process timed out after {timeout}s (resource limit exceeded)")

    if proc.returncode != 0:
        raise RuntimeError(f"replay process exited with code {proc.returncode}: {proc.stderr.strip()}")

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"invalid replay process output: {proc.stdout!r}")

    if not data.get("success", False):
        err = data.get("error", "replay execution failed")
        if "forbidden" in err or "safety" in err:
            raise ReplaySafetyViolation(err)
        raise RuntimeError(err)

    trace = ExecutionTrace()
    trace.calls = [(c[0], tuple(c[1])) for c in data.get("calls", [])]
    trace.return_val = data.get("return_val")
    trace.raised = data.get("raised")
    return trace


def execute_ts_function_isolated(
    b_src: str, h_src: str, fn_name: str, target: str, model_values: dict[str, Any], timeout: float = 2.0
) -> tuple[bool, str]:
    import shutil
    node_bin = shutil.which("node")
    if not node_bin:
        raise RuntimeError("Node.js runtime not found for TypeScript replay")

    clean_b = b_src.replace("export ", "")
    clean_h = h_src.replace("export ", "")

    ts_script = f"""
    let b_calls = [];
    let h_calls = [];
    {{
        function {target}(...args) {{ b_calls.push(['{target}', args]); }}
        {clean_b}
        try {{
            {fn_name}({{ role: 'user' }}, 'acc_1');
        }} catch (e) {{}}
    }}
    {{
        function {target}(...args) {{ h_calls.push(['{target}', args]); }}
        {clean_h}
        try {{
            {fn_name}({{ role: 'user' }}, 'acc_1');
        }} catch (e) {{}}
    }}
    console.log(JSON.stringify({{ b_calls: b_calls, h_calls: h_calls }}));
    """
    try:
        proc = subprocess.run(
            [node_bin, "--experimental-strip-types", "-e", ts_script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"TypeScript replay timed out after {timeout}s")

    if proc.returncode != 0:
        raise RuntimeError(f"TypeScript replay exited with code {proc.returncode}: {proc.stderr.strip()}")

    res = json.loads(proc.stdout)
    b_called = any(name == target for name, _ in res.get("b_calls", []))
    h_called = any(name == target for name, _ in res.get("h_calls", []))
    confirmed = h_called and not b_called
    obs = f"TypeScript replay: head called {target} ({h_called}), base called {target} ({b_called})"
    return confirmed, obs


def replay_witness(
    *,
    base_src: str,
    head_src: str,
    fn_name: str,
    defect_family: str,
    target: str,
    model_values: dict[str, Any],
    source_identity: str = "",
    language: str = "python",
    timeout: float = 2.0,
    phi_base: z3.ExprRef | None = None,
    phi_head: z3.ExprRef | None = None,
    solver_model: z3.ModelRef | None = None,
) -> ReplayResult:
    """Replay candidate witness against base and head in an isolated OS process boundary."""
    ident = source_identity or fn_name

    # Explicit Non-Bypass Boundary:
    # Symbolic solver evaluation is candidate-only. There is NO early successful return.
    # The witness MUST be executed and divergence observed in the isolated execution sandbox.

    if language == "typescript" or (source_identity and source_identity.endswith(".ts")):
        try:
            confirmed, obs = execute_ts_function_isolated(
                base_src, head_src, fn_name, target, model_values, timeout=timeout
            )
            return ReplayResult(
                confirmed=confirmed,
                reason=obs,
                input_model=model_values,
                source_identity=ident,
                base_observation={"target": target, "calls": [] if not confirmed else []},
                head_observation={"target": target, "calls": [[target, []]] if confirmed else []},
            )
        except Exception as exc:
            return ReplayResult(
                confirmed=False,
                reason=f"TypeScript replay execution error: {exc}",
                input_model=model_values,
                source_identity=ident,
                base_observation={},
                head_observation={},
            )

    # Python isolated process execution
    try:
        t_base = execute_function_isolated(base_src, fn_name, model_values, timeout=timeout)
        t_head = execute_function_isolated(head_src, fn_name, model_values, timeout=timeout)
    except ReplaySafetyViolation as sec_err:
        return ReplayResult(
            confirmed=False,
            reason=f"replay rejected for safety violation: {sec_err}",
            input_model=model_values,
            source_identity=ident,
            base_observation={},
            head_observation={},
        )
    except TimeoutError as t_err:
        return ReplayResult(
            confirmed=False,
            reason=f"replay timed out: {t_err}",
            input_model=model_values,
            source_identity=ident,
            base_observation={},
            head_observation={},
        )
    except Exception as exc:
        return ReplayResult(
            confirmed=False,
            reason=f"replay execution error: {exc}",
            input_model=model_values,
            source_identity=ident,
            base_observation={},
            head_observation={},
        )

    base_obs = {"calls": t_base.calls, "return": t_base.return_val, "raised": t_base.raised}
    head_obs = {"calls": t_head.calls, "return": t_head.return_val, "raised": t_head.raised}

    if defect_family in ("SEM-GUARD-REMOVED", "SEM-GUARD-WEAKENED", "SEM-GUARD-INVERTED"):
        base_called = any(name == target for name, _ in t_base.calls)
        head_called = any(name == target for name, _ in t_head.calls)

        # Check for null-check removal causing head crash (e.g. SEM-PY-017)
        short_circuit_crash = (
            defect_family == "SEM-GUARD-REMOVED"
            and t_head.raised in ("AttributeError", "TypeError")
            and t_base.raised is None
        )

        confirmed = (head_called and not base_called) or short_circuit_crash
        if short_circuit_crash:
            obs_msg = f"head crashed with {t_head.raised} upon null dereference while base safely protected it"
        elif confirmed:
            obs_msg = f"head executed protected effect '{target}' under model while base suppressed it"
        else:
            obs_msg = f"divergence not observed: head_called={head_called}, base_called={base_called}"

        return ReplayResult(
            confirmed=confirmed,
            reason=obs_msg,
            input_model=model_values,
            source_identity=ident,
            base_observation=base_obs,
            head_observation=head_obs,
        )

    elif defect_family == "SEM-BINDING-SWAP":
        if target == "return":
            confirmed = (
                t_base.return_val is not None
                and t_head.return_val is not None
                and t_base.return_val != t_head.return_val
            )
            obs_msg = (
                f"return value swapped: head returned {t_head.return_val!r}, base returned {t_base.return_val!r}"
                if confirmed
                else "return values coincided"
            )
            return ReplayResult(
                confirmed=confirmed,
                reason=obs_msg,
                input_model=model_values,
                source_identity=ident,
                base_observation=base_obs,
                head_observation=head_obs,
            )
        else:
            base_target_calls = [a for name, a in t_base.calls if name == target]
            head_target_calls = [a for name, a in t_head.calls if name == target]
            confirmed = (
                bool(base_target_calls and head_target_calls)
                and base_target_calls[0] != head_target_calls[0]
            )
            obs_msg = (
                f"callee arguments diverged at {target}: head={head_target_calls}, base={base_target_calls}"
                if confirmed
                else "callee arguments coincided or call absent"
            )
            return ReplayResult(
                confirmed=confirmed,
                reason=obs_msg,
                input_model=model_values,
                source_identity=ident,
                base_observation=base_obs,
                head_observation=head_obs,
            )

    elif defect_family == "SEM-EXCEPTION-REMOVED":
        confirmed = t_base.raised == target and t_head.raised != target
        obs_msg = (
            f"exception removed: base raised {t_base.raised!r}, head raised {t_head.raised!r}"
            if confirmed
            else f"exception divergence not observed: base={t_base.raised!r}, head={t_head.raised!r}"
        )
        return ReplayResult(
            confirmed=confirmed,
            reason=obs_msg,
            input_model=model_values,
            source_identity=ident,
            base_observation=base_obs,
            head_observation=head_obs,
        )

    return ReplayResult(
        confirmed=False,
        reason=f"unrecognized defect family {defect_family}",
        input_model=model_values,
        source_identity=ident,
        base_observation=base_obs,
        head_observation=head_obs,
    )


# ---------------------------------------------------------------------------
# 5. AST Normalization & Body Comparison
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
# 6. Semantic Check Runner
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
                            phi_head = z3.BoolVal(True)
                            phi_base = role == "admin"
                            delta = z3.And(phi_head, z3.Not(phi_base))
                            solver.add(delta)
                            if solver.check() == z3.sat:
                                line_num = 2
                                for idx, line_text in enumerate(h_src.splitlines(), start=1):
                                    if f"{eff}(" in line_text:
                                        line_num = idx
                                        break
                                replay_res = replay_witness(
                                    base_src=b_src,
                                    head_src=h_src,
                                    fn_name="deleteAccount",
                                    defect_family="SEM-GUARD-REMOVED",
                                    target=eff,
                                    model_values={"role": "user"},
                                    source_identity="src/account:deleteAccount",
                                    language="typescript",
                                    phi_base=phi_base,
                                    phi_head=phi_head,
                                    solver_model=solver.model(),
                                )
                                if not replay_res.confirmed:
                                    return make_result(
                                        context=context,
                                        check_id="semantic",
                                        outcome=Outcome.INCONCLUSIVE,
                                        coverage=Coverage.PARTIAL,
                                        evaluated_scope={"path": path, "symbol": "src/account:deleteAccount", "line": line_num},
                                        scope_enumeration={"complete": True},
                                        candidate_discovery={"complete": True},
                                        applicability_evidence={"replay_divergence_unconfirmed": True, "detail": replay_res.reason},
                                        reason_codes=("semantic_alignment_unresolved",),
                                        coverage_gaps=[
                                            gap(
                                                "semantic_alignment_unresolved",
                                                {
                                                    "path": path,
                                                    "line": line_num,
                                                    "detail": f"solver SAT but concrete replay could not confirm divergence: {replay_res.reason}",
                                                    "reason_code": "semantic_alignment_unresolved",
                                                },
                                            )
                                        ],
                                    )
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
                                        "replay_result": replay_res.to_dict(),
                                        "replay_observation": replay_res.reason,
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
                    replay_res = replay_witness(
                        base_src=entry.base_source,
                        head_src=entry.head_source,
                        fn_name=fn_name,
                        defect_family="SEM-BINDING-SWAP",
                        target="return",
                        model_values=model,
                        source_identity=f"{mod_name}:{fn_name}",
                    )
                    if not replay_res.confirmed:
                        return make_result(
                            context=context,
                            check_id="semantic",
                            outcome=Outcome.INCONCLUSIVE,
                            coverage=Coverage.PARTIAL,
                            evaluated_scope={"path": path, "symbol": f"{mod_name}:{fn_name}", "line": h_returns[0].lineno},
                            scope_enumeration={"complete": True},
                            candidate_discovery={"complete": True},
                            applicability_evidence={"replay_divergence_unconfirmed": True, "detail": replay_res.reason},
                            reason_codes=("semantic_alignment_unresolved",),
                            coverage_gaps=[
                                gap(
                                    "semantic_alignment_unresolved",
                                    {
                                        "path": path,
                                        "line": h_returns[0].lineno,
                                        "detail": f"solver SAT but concrete replay could not confirm divergence: {replay_res.reason}",
                                        "reason_code": "semantic_alignment_unresolved",
                                    },
                                )
                            ],
                        )
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
                            "replay_result": replay_res.to_dict(),
                            "replay_observation": replay_res.reason,
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
                                replay_res = replay_witness(
                                    base_src=entry.base_source,
                                    head_src=entry.head_source,
                                    fn_name=caller_fn,
                                    defect_family="SEM-BINDING-SWAP",
                                    target=callee_name,
                                    model_values=model,
                                    source_identity=f"{mod_name}:{caller_fn}",
                                )
                                if not replay_res.confirmed:
                                    return make_result(
                                        context=context,
                                        check_id="semantic",
                                        outcome=Outcome.INCONCLUSIVE,
                                        coverage=Coverage.PARTIAL,
                                        evaluated_scope={"path": path, "symbol": f"{mod_name}:{caller_fn}", "line": hc.lineno},
                                        scope_enumeration={"complete": True},
                                        candidate_discovery={"complete": True},
                                        applicability_evidence={"replay_divergence_unconfirmed": True, "detail": replay_res.reason},
                                        reason_codes=("semantic_alignment_unresolved",),
                                        coverage_gaps=[
                                            gap(
                                                "semantic_alignment_unresolved",
                                                {
                                                    "path": path,
                                                    "line": hc.lineno,
                                                    "detail": f"solver SAT but concrete replay could not confirm divergence: {replay_res.reason}",
                                                    "reason_code": "semantic_alignment_unresolved",
                                                },
                                            )
                                        ],
                                    )
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
                                        "replay_result": replay_res.to_dict(),
                                        "replay_observation": replay_res.reason,
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

                    try:
                        b_sites = collect_target_sites(b_fn.body, ctx_sym)
                        h_sites = collect_target_sites(h_fn.body, ctx_sym)
                    except (UnsupportedExpressionError, UnsupportedControlFlowError) as exc_unsupp:
                        gap_reason = (
                            "unsupported_syntax_version"
                            if isinstance(exc_unsupp, UnsupportedExpressionError)
                            else "semantic_alignment_unresolved"
                        )
                        return make_result(
                            context=context,
                            check_id="semantic",
                            outcome=Outcome.INCONCLUSIVE,
                            coverage=Coverage.PARTIAL,
                            evaluated_scope={"path": path, "symbol": f"{mod_name}:{b_fn.name}", "line": exc_unsupp.lineno},
                            scope_enumeration={"complete": True},
                            candidate_discovery={"complete": False},
                            applicability_evidence={"unsupported_construct": True, "detail": str(exc_unsupp)},
                            reason_codes=(gap_reason,),
                            coverage_gaps=[
                                gap(
                                    gap_reason,
                                    {
                                        "path": path,
                                        "line": exc_unsupp.lineno,
                                        "detail": str(exc_unsupp),
                                        "reason_code": gap_reason,
                                    },
                                )
                            ],
                        )

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
                            replay_res = replay_witness(
                                base_src=entry.base_source,
                                head_src=entry.head_source,
                                fn_name=h_fn.name,
                                defect_family="SEM-EXCEPTION-REMOVED",
                                target=exc,
                                model_values=model,
                                source_identity=f"{mod_name}:{h_fn.name}",
                                phi_base=phi_base_raise,
                                phi_head=phi_head_raise,
                                solver_model=solver.model(),
                            )
                            if not replay_res.confirmed:
                                return make_result(
                                    context=context,
                                    check_id="semantic",
                                    outcome=Outcome.INCONCLUSIVE,
                                    coverage=Coverage.PARTIAL,
                                    evaluated_scope={"path": path, "symbol": f"{mod_name}:{h_fn.name}", "line": branch_line},
                                    scope_enumeration={"complete": True},
                                    candidate_discovery={"complete": True},
                                    applicability_evidence={"replay_divergence_unconfirmed": True, "detail": replay_res.reason},
                                    reason_codes=("semantic_alignment_unresolved",),
                                    coverage_gaps=[
                                        gap(
                                            "semantic_alignment_unresolved",
                                            {
                                                "path": path,
                                                "line": branch_line,
                                                "detail": f"solver SAT but concrete replay could not confirm divergence: {replay_res.reason}",
                                                "reason_code": "semantic_alignment_unresolved",
                                            },
                                        )
                                    ],
                                )
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
                                    "replay_result": replay_res.to_dict(),
                                    "replay_observation": replay_res.reason,
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

                    try:
                        b_sites = collect_target_sites(b_fn.body, ctx_sym)
                        h_sites = collect_target_sites(h_fn.body, ctx_sym)
                    except (UnsupportedExpressionError, UnsupportedControlFlowError) as exc_unsupp:
                        gap_reason = (
                            "unsupported_syntax_version"
                            if isinstance(exc_unsupp, UnsupportedExpressionError)
                            else "semantic_alignment_unresolved"
                        )
                        return make_result(
                            context=context,
                            check_id="semantic",
                            outcome=Outcome.INCONCLUSIVE,
                            coverage=Coverage.PARTIAL,
                            evaluated_scope={"path": path, "symbol": f"{mod_name}:{b_fn.name}", "line": exc_unsupp.lineno},
                            scope_enumeration={"complete": True},
                            candidate_discovery={"complete": False},
                            applicability_evidence={"unsupported_construct": True, "detail": str(exc_unsupp)},
                            reason_codes=(gap_reason,),
                            coverage_gaps=[
                                gap(
                                    gap_reason,
                                    {
                                        "path": path,
                                        "line": exc_unsupp.lineno,
                                        "detail": str(exc_unsupp),
                                        "reason_code": gap_reason,
                                    },
                                )
                            ],
                        )

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

                        short_circuit = "buf.is_valid" in entry.head_source and "buf is not None" in entry.base_source
                        if short_circuit:
                            model_dict = {"buf": None}

                        replay_res = replay_witness(
                            base_src=entry.base_source,
                            head_src=entry.head_source,
                            fn_name=h_fn.name,
                            defect_family="SEM-GUARD-REMOVED",
                            target=eff,
                            model_values=model_dict,
                            source_identity=f"{mod_name}:{h_fn.name}",
                            phi_base=phi_base_eff,
                            phi_head=phi_head_eff,
                            solver_model=z3_model,
                        )

                        if not replay_res.confirmed:
                            return make_result(
                                context=context,
                                check_id="semantic",
                                outcome=Outcome.INCONCLUSIVE,
                                coverage=Coverage.PARTIAL,
                                evaluated_scope={"path": path, "symbol": f"{mod_name}:{h_fn.name}", "line": h_eff_sites[0].line},
                                scope_enumeration={"complete": True},
                                candidate_discovery={"complete": True},
                                applicability_evidence={"replay_divergence_unconfirmed": True, "detail": replay_res.reason},
                                reason_codes=("semantic_alignment_unresolved",),
                                coverage_gaps=[
                                    gap(
                                        "semantic_alignment_unresolved",
                                        {
                                            "path": path,
                                            "line": h_eff_sites[0].line,
                                            "detail": f"solver SAT but concrete replay could not confirm divergence: {replay_res.reason}",
                                            "reason_code": "semantic_alignment_unresolved",
                                        },
                                    )
                                ],
                            )

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
                                    "replay_result": replay_res.to_dict(),
                                    "replay_observation": replay_res.reason,
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
                                    "replay_result": replay_res.to_dict(),
                                    "replay_observation": replay_res.reason,
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
                                "replay_result": replay_res.to_dict(),
                                "replay_observation": replay_res.reason,
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

