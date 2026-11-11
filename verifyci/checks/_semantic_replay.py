"""Isolated subprocess witness replay for Python and TypeScript semantic candidates."""

from __future__ import annotations

import ast
import dataclasses
import json
import os
import re
import subprocess
import sys
from typing import Any
import z3


class ReplaySafetyViolation(Exception):
    pass


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


_FORBIDDEN_CALLS = frozenset(
    {
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
)


def validate_ast_safety(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise ReplaySafetyViolation(
                f"import statements are forbidden in replay sandbox: line {getattr(node, 'lineno', 0)}"
            )
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("__") and node.attr.endswith("__"):
                raise ReplaySafetyViolation(
                    f"dunder attribute access is forbidden in replay sandbox: {node.attr}"
                )
        if isinstance(node, ast.Call):
            callee_name = node.func.id if isinstance(node.func, ast.Name) else ""
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

def validate_ast_safety(tree, forbidden_calls):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise ValueError(f"import statements are forbidden in replay sandbox: line {getattr(node, 'lineno', 0)}")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr.endswith("__"):
            raise ValueError(f"dunder attribute access is forbidden in replay sandbox: {node.attr}")
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", "")
            if name in forbidden_calls:
                raise ValueError(f"forbidden call in replay sandbox: {name}")

def intercept_ast(src, forbidden_calls):
    tree = ast.parse(src)
    validate_ast_safety(tree, forbidden_calls)

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
    payload = json.loads(sys.stdin.read())
    src = payload["src"]
    fn_name = payload["fn_name"]
    raw_args = payload["args"]
    forbidden_calls = set(payload["forbidden_calls"])

    trace = ExecutionTrace()
    tree = intercept_ast(src, forbidden_calls)
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

    args_dict = dict(scalar_args)
    for obj_name, attrs in boxes.items():
        if obj_name not in scalar_args or scalar_args[obj_name] is not None:
            args_dict[obj_name] = ValueBox(**attrs)

    sig = inspect.signature(fn)
    call_args = [args_dict.get(param_name, None) for param_name in sig.parameters]

    try:
        ret = fn(*call_args)
        trace.record_return(ret)
    except Exception as e:
        trace.record_raise(e)

    print(
        json.dumps(
            {
                "success": True,
                "calls": trace.calls,
                "return_val": trace.return_val,
                "raised": trace.raised,
            }
        )
    )

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"success": False, "error": str(exc)}))
"""


class ExecutionTrace:
    """Observation returned from the isolated replay subprocess."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.return_val: Any = None
        self.raised: str | None = None


_JS_CALLABLE_RE = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$")

_REPLAY_ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "TEMP",
    "TMP",
    "LANG",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
)


def _replay_env() -> dict[str, str]:
    env = {key: os.environ[key] for key in _REPLAY_ENV_ALLOWLIST if key in os.environ}
    env["NODE_OPTIONS"] = ""
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def execute_function_isolated(
    src: str, fn_name: str, args_dict: dict[str, Any], timeout: float = 2.0
) -> ExecutionTrace:
    """Execute target function in a dedicated Python subprocess (`sys.executable -I`)."""
    tree = ast.parse(src)
    validate_ast_safety(tree)

    payload = {
        "src": src,
        "fn_name": fn_name,
        "args": args_dict,
        "forbidden_calls": sorted(_FORBIDDEN_CALLS),
    }
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", _REPLAY_SUBPROCESS_SCRIPT],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_replay_env(),
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"replay process timed out after {timeout}s (execution timeout exceeded)")

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
    b_src: str, h_src: str, fn_name: str, target: str, model_values: dict[str, Any], timeout: float = 5.0
) -> tuple[bool, str, dict[str, Any], dict[str, Any]]:
    """Execute base and head TypeScript functions in an isolated Node.js subprocess."""
    import shutil

    node_bin = shutil.which("node")
    if not node_bin:
        raise RuntimeError("Node.js runtime not found for TypeScript replay")

    if not _JS_CALLABLE_RE.match(fn_name or "") or not _JS_CALLABLE_RE.match(target or ""):
        raise RuntimeError("TypeScript replay target is not a plain identifier")

    clean_b = b_src.replace("export ", "")
    clean_h = h_src.replace("export ", "")
    arg_obj = json.dumps(model_values, ensure_ascii=True)

    ts_script = f"""
    let b_calls = [];
    let h_calls = [];
    {{
        function {target}(...args) {{ b_calls.push(['{target}', args]); }}
        {clean_b}
        try {{
            {fn_name}({arg_obj}, 'acc_1');
        }} catch (e) {{}}
    }}
    {{
        function {target}(...args) {{ h_calls.push(['{target}', args]); }}
        {clean_h}
        try {{
            {fn_name}({arg_obj}, 'acc_1');
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
            env=_replay_env(),
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"TypeScript replay timed out after {timeout}s")

    if proc.returncode != 0:
        raise RuntimeError(f"TypeScript replay exited with code {proc.returncode}: {proc.stderr.strip()}")

    res = json.loads(proc.stdout)
    b_calls = res.get("b_calls", [])
    h_calls = res.get("h_calls", [])
    b_called = any(name == target for name, _ in b_calls)
    h_called = any(name == target for name, _ in h_calls)
    confirmed = h_called and not b_called
    obs = f"TypeScript replay: head called {target} ({h_called}), base called {target} ({b_called})"
    return (
        confirmed,
        obs,
        {"target": target, "calls": b_calls},
        {"target": target, "calls": h_calls},
    )


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
    timeout: float = 5.0,
    phi_base: z3.ExprRef | None = None,
    phi_head: z3.ExprRef | None = None,
    solver_model: z3.ModelRef | None = None,
) -> ReplayResult:
    """Replay candidate witness against base and head in an isolated OS process boundary."""
    ident = source_identity or fn_name

    def _fail(reason: str, base_obs: dict[str, Any] | None = None, head_obs: dict[str, Any] | None = None) -> ReplayResult:
        return ReplayResult(
            confirmed=False,
            reason=reason,
            input_model=model_values,
            source_identity=ident,
            base_observation=base_obs or {},
            head_observation=head_obs or {},
        )

    if language == "typescript" or (source_identity and source_identity.endswith(".ts")):
        try:
            confirmed, obs, base_obs, head_obs = execute_ts_function_isolated(
                base_src, head_src, fn_name, target, model_values, timeout=max(timeout, 5.0)
            )
            return ReplayResult(
                confirmed=confirmed,
                reason=obs,
                input_model=model_values,
                source_identity=ident,
                base_observation=base_obs,
                head_observation=head_obs,
            )
        except Exception as exc:
            return _fail(f"TypeScript replay execution error: {exc}")

    try:
        t_base = execute_function_isolated(base_src, fn_name, model_values, timeout=timeout)
        t_head = execute_function_isolated(head_src, fn_name, model_values, timeout=timeout)
    except ReplaySafetyViolation as sec_err:
        return _fail(f"replay rejected for safety violation: {sec_err}")
    except TimeoutError as t_err:
        return _fail(f"replay timed out: {t_err}")
    except Exception as exc:
        return _fail(f"replay execution error: {exc}")

    base_obs = {"calls": t_base.calls, "return": t_base.return_val, "raised": t_base.raised}
    head_obs = {"calls": t_head.calls, "return": t_head.return_val, "raised": t_head.raised}

    if defect_family in ("SEM-GUARD-REMOVED", "SEM-GUARD-WEAKENED", "SEM-GUARD-INVERTED"):
        base_called = any(name == target for name, _ in t_base.calls)
        head_called = any(name == target for name, _ in t_head.calls)
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
    elif defect_family == "SEM-EXCEPTION-REMOVED":
        confirmed = t_base.raised == target and t_head.raised != target
        obs_msg = (
            f"exception removed: base raised {t_base.raised!r}, head raised {t_head.raised!r}"
            if confirmed
            else f"exception divergence not observed: base={t_base.raised!r}, head={t_head.raised!r}"
        )
    else:
        return _fail(f"unrecognized defect family {defect_family}", base_obs, head_obs)

    return ReplayResult(
        confirmed=confirmed,
        reason=obs_msg,
        input_model=model_values,
        source_identity=ident,
        base_observation=base_obs,
        head_observation=head_obs,
    )


__all__ = [
    "ExecutionTrace",
    "ReplayResult",
    "ReplaySafetyViolation",
    "execute_function_isolated",
    "execute_ts_function_isolated",
    "replay_witness",
    "validate_ast_safety",
]
