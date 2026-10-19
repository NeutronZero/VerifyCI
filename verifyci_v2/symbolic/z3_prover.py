from __future__ import annotations

import ast
import msgspec
import time
from dataclasses import dataclass
from collections import deque
from typing import Any

from verifyci_v2.contracts.attestation import (
    CounterexampleWitness,
    EquivalenceProofResult,
    SMTStatus,
    VerificationFinding,
)
from verifyci_v2.contracts.canonical import content_digest_hex
from verifyci_v2.contracts.ssa_ir import CPGEdge, FunctionUSSA, USSABasicBlock
from verifyci_v2.symbolic.egglog_engine import EgglogEquivalenceEngine

try:
    import z3 as _z3_mod  # type: ignore[import-untyped]
except ImportError:
    _z3_mod = None


_COMPARE_OPS = frozenset({"Gt", "GtE", "Lt", "LtE", "Eq", "NotEq", "Is", "IsNot"})
_BIN_OPS = frozenset(
    {"Add", "Sub", "Mult", "FloorDiv", "Div", "Mod", "BitAnd", "BitOr", "BitXor"}
)
_UNARY_OPS = frozenset({"Not", "USub", "UAdd", "Invert"})
_BOOL_OPS = frozenset({"And", "Or"})

_UNSUPPORTED_AST_TYPES = (
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.Yield,
    ast.YieldFrom,
    ast.AsyncFunctionDef,
    ast.ListComp,
    ast.DictComp,
    ast.SetComp,
    ast.GeneratorExp,
    ast.Await,
)

_UNSUPPORTED_USSA_OPCODES = {
    "LOOP_FOR": "For",
    "LOOP_ASYNCFOR": "AsyncFor",
    "LOOP_WHILE": "While",
    "TRY_BLOCK": "Try",
    "STORE_SUBSCRIPT": "SubscriptAssignment",
}


def _supported_fragment_doc() -> str:
    """Non-normative helper describing the current supported fragment.

    This exists so the supported-subset documentation can be mechanically reflected
    in tests without coupling those tests to internal encoding details.
    """
    return (
        "Z3SymbolicProver supported semantic subset (verifyci.v2):\n"
        "- pure scalar arithmetic and comparisons over finite bit-vectors, ints, floats,\n"
        "  booleans, and None used only as sentinel values.\n"
        "- preserved control-flow shape between base and head.\n"
        "- Referentially transparent calls to known pure primitives such as len().\n"
        "- Deterministic conditional dispatch whose guard expressions reduce to Z3.\n"
        "- no side effects: no I/O, no global mutation, no exception throwing paths.\n"
        "\nUnsupported cases are reported as INCONCLUSIVE with\n"
        "Witness.smt_status == 'UNKNOWN' and are escalated rather than passed.\n"
        "When UNSAT is returned, the two sides are provably equivalent under this\n"
        "fragment. When SAT is returned, a concrete counterexample witness is attached.\n"
    )


def _split_kwarg(arg_s: str) -> tuple[str, str] | None:
    """Splits a `name=value` call argument into `(name, value)`.

    Returns None when the argument is not a keyword binding. Requiring the
    name to be an identifier keeps a literal such as `'a=b'` from being read as
    a binding it never expressed.
    """
    if "=" not in arg_s or arg_s.startswith("("):
        return None
    name, _, value = arg_s.partition("=")
    name = name.strip()
    if not name.isidentifier():
        return None
    return name, value.strip()


def _z3_context_of(value: Any = None, ctx: Any = None) -> Any:
    if ctx is not None:
        return ctx
    try:
        return value.ctx
    except Exception:
        return None


def _z3_make(constructor: Any, *args: Any, ctx: Any = None) -> Any:
    """Construct a Z3 object in the requested context when one is supplied."""
    if ctx is not None:
        try:
            return constructor(*args, ctx=ctx)
        except TypeError:
            pass
    return constructor(*args)


def _to_z3_int(val: Any, *, ctx: Any = None) -> Any:
    if _z3_mod is None or val is None:
        return None
    ctx = _z3_context_of(val, ctx)
    int_sort = _z3_make(_z3_mod.IntSort, ctx=ctx)
    if _z3_mod.is_int_value(val) or (hasattr(val, "sort") and val.sort() == int_sort):
        return val
    if _z3_mod.is_bool(val):
        return _z3_mod.If(val, _z3_make(_z3_mod.IntVal, 1, ctx=ctx), _z3_make(_z3_mod.IntVal, 0, ctx=ctx))
    if isinstance(val, bool):
        return _z3_make(_z3_mod.IntVal, 1 if val else 0, ctx=ctx)
    if isinstance(val, int):
        return _z3_make(_z3_mod.IntVal, val, ctx=ctx)
    return None


def _to_z3_bool(val: Any, *, ctx: Any = None) -> Any:
    if _z3_mod is None or val is None:
        return None
    ctx = _z3_context_of(val, ctx)
    if _z3_mod.is_bool(val):
        return val
    if hasattr(val, "sort") and val.sort() == _z3_make(_z3_mod.IntSort, ctx=ctx):
        return val != _z3_make(_z3_mod.IntVal, 0, ctx=ctx)
    if isinstance(val, bool):
        return _z3_make(_z3_mod.BoolVal, val, ctx=ctx)
    if isinstance(val, int):
        return _z3_make(_z3_mod.BoolVal, val != 0, ctx=ctx)
    return None


def _split_top_level(text: str, sep: str = " ") -> list[str]:
    """Splits `text` by `sep` only at top-level parenthesis/bracket/quote depth."""
    if not any(c in text for c in ("(", "[", ")", "]", "'", '"')):
        if sep in text:
            return [p.strip() for p in text.split(sep) if p.strip()]
        s = text.strip()
        return [s] if s else []

    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    in_quote: str | None = None

    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_quote is not None:
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                i += 1
                buf.append(text[i])
            elif ch == in_quote:
                in_quote = None
        else:
            if ch in ("'", '"'):
                in_quote = ch
                buf.append(ch)
            elif ch in ("(", "["):
                depth += 1
                buf.append(ch)
            elif ch in (")", "]"):
                depth = max(0, depth - 1)
                buf.append(ch)
            elif depth == 0 and text.startswith(sep, i):
                token = "".join(buf).strip()
                if token:
                    parts.append(token)
                buf = []
                i += len(sep)
                continue
            else:
                buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _strip_ssa_suffix(var_name: str, parameters: set[str]) -> str:
    if "_" in var_name:
        base, suffix = var_name.rsplit("_", 1)
        if suffix.isdigit():
            return base
    return var_name


def _normalize_ussa_expr(
    expr_str: str, expr_env: dict[str, str], parameters: set[str]
) -> str:
    """Rewrites SSA versioned operands into canonical parameter-relative expressions."""
    s = expr_str.strip()
    if not s:
        return s

    if s in expr_env:
        return expr_env[s]

    if s.startswith("NOT(") and s.endswith(")"):
        inner = _normalize_ussa_expr(s[4:-1], expr_env, parameters)
        return f"NOT({inner})"

    if s.startswith("CALL(") and s.endswith(")"):
        inner = s[5:-1]
        items = _split_top_level(inner, sep=",")
        if not items:
            return s
        callee = items[0].strip()
        norm_args = [
            _normalize_ussa_expr(arg.strip(), expr_env, parameters)
            for arg in items[1:]
            if arg.strip()
        ]
        return f"CALL({callee}, {', '.join(norm_args)})"

    if s.startswith("(") and s.endswith(")"):
        tokens = _split_top_level(s[1:-1], sep=" ")
        if len(tokens) == 2 and tokens[0] in _UNARY_OPS:
            op, arg = tokens[0], _normalize_ussa_expr(tokens[1], expr_env, parameters)
            if op == "Not":
                return f"NOT({arg})"
            return f"({op} {arg})"
        if len(tokens) == 3 and tokens[0] in _BIN_OPS:
            op = tokens[0]
            lhs = _normalize_ussa_expr(tokens[1], expr_env, parameters)
            rhs = _normalize_ussa_expr(tokens[2], expr_env, parameters)
            return f"({lhs} {op} {rhs})"
        if len(tokens) >= 3 and len(tokens) % 2 == 1 and tokens[1] in _COMPARE_OPS:
            norm_toks = [
                tok if idx % 2 == 1 else _normalize_ussa_expr(tok, expr_env, parameters)
                for idx, tok in enumerate(tokens)
            ]
            return "(" + " ".join(norm_toks) + ")"
        if len(tokens) >= 2 and tokens[0] in _BOOL_OPS:
            op = tokens[0]
            rest = [_normalize_ussa_expr(t, expr_env, parameters) for t in tokens[1:]]
            return f"({op} {' '.join(rest)})"

    base = _strip_ssa_suffix(s, parameters)
    if base in expr_env:
        return expr_env[base]
    return base


def _ast_expr_to_z3(node: ast.AST, z3_vars: dict[str, Any], *, ctx: Any = None) -> Any:
    """Fallback AST-to-Z3 translator for unparsed expressions."""
    if _z3_mod is None:
        return None
    if isinstance(node, ast.Name):
        if node.id not in z3_vars:
            z3_vars[node.id] = _z3_make(_z3_mod.Int, node.id, ctx=ctx)
        return z3_vars[node.id]
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return _z3_make(_z3_mod.BoolVal, node.value, ctx=ctx)
        if isinstance(node.value, int):
            return _z3_make(_z3_mod.IntVal, node.value, ctx=ctx)
        # Legacy integer-only structural analysis cannot represent these values.
        # Return unsupported rather than introduce an aliasing sentinel/hash.
        if node.value is None or isinstance(node.value, str):
            return None
        return None
    if isinstance(node, ast.UnaryOp):
        operand = _ast_expr_to_z3(node.operand, z3_vars, ctx=ctx)
        if operand is None:
            return None
        if isinstance(node.op, ast.Not):
            b_op = _to_z3_bool(operand, ctx=ctx)
            return _z3_mod.Not(b_op) if b_op is not None else None
        if isinstance(node.op, ast.USub):
            i_op = _to_z3_int(operand, ctx=ctx)
            return -i_op if i_op is not None else None
        if isinstance(node.op, ast.UAdd):
            return _to_z3_int(operand, ctx=ctx)
        return None
    if isinstance(node, ast.BinOp):
        lhs = _to_z3_int(_ast_expr_to_z3(node.left, z3_vars, ctx=ctx), ctx=ctx)
        rhs = _to_z3_int(_ast_expr_to_z3(node.right, z3_vars, ctx=ctx), ctx=ctx)
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
        lhs_raw = _ast_expr_to_z3(node.left, z3_vars, ctx=ctx)
        if lhs_raw is None:
            return None
        comps = []
        lhs = _to_z3_int(lhs_raw, ctx=ctx)
        for op, r_node in zip(node.ops, node.comparators):
            rhs_raw = _ast_expr_to_z3(r_node, z3_vars, ctx=ctx)
            rhs = _to_z3_int(rhs_raw, ctx=ctx)
            if lhs is None or rhs is None:
                return None
            if isinstance(op, ast.Gt):
                comps.append(lhs > rhs)
            elif isinstance(op, ast.GtE):
                comps.append(lhs >= rhs)
            elif isinstance(op, ast.Lt):
                comps.append(lhs < rhs)
            elif isinstance(op, ast.LtE):
                comps.append(lhs <= rhs)
            elif isinstance(op, (ast.Eq, ast.Is)):
                comps.append(lhs == rhs)
            elif isinstance(op, (ast.NotEq, ast.IsNot)):
                comps.append(lhs != rhs)
            else:
                return None
            lhs = rhs
        if not comps:
            return _z3_make(_z3_mod.BoolVal, True, ctx=ctx)
        return _z3_mod.And(*comps) if len(comps) > 1 else comps[0]
    if isinstance(node, ast.BoolOp):
        vals = [_to_z3_bool(_ast_expr_to_z3(v, z3_vars, ctx=ctx), ctx=ctx) for v in node.values]
        if any(v is None for v in vals):
            return None
        if isinstance(node.op, ast.And):
            return _z3_mod.And(*vals)
        if isinstance(node.op, ast.Or):
            return _z3_mod.Or(*vals)
    if isinstance(node, ast.Call):
        fn_name = ast.unparse(node.func)
        args_z3 = [_to_z3_int(_ast_expr_to_z3(a, z3_vars, ctx=ctx), ctx=ctx) for a in node.args]
        if any(a is None for a in args_z3):
            return None
        arg_sorts = [_z3_make(_z3_mod.IntSort, ctx=ctx) for _ in args_z3]
        f_sym = _z3_make(_z3_mod.Function, fn_name, *arg_sorts, _z3_make(_z3_mod.IntSort, ctx=ctx), ctx=ctx)
        return f_sym(*args_z3)
    return None


def _ussa_sexpr_to_z3(
    expr_str: str,
    ssa_env: dict[str, Any],
    z3_vars: dict[str, Any],
    parameters: set[str],
    *,
    ctx: Any = None,
) -> Any:
    """Translates a U-SSA operand expression string directly into a Z3 AST term."""
    if _z3_mod is None:
        return None
    s = expr_str.strip()
    if not s:
        return None

    if s in ssa_env and ssa_env[s] is not None:
        return ssa_env[s]

    if s == "True":
        return _z3_make(_z3_mod.BoolVal, True, ctx=ctx)
    if s == "False":
        return _z3_make(_z3_mod.BoolVal, False, ctx=ctx)
    if s == "None":
        return None  # typed handling lives in the PyVal equivalence encoder

    # Integer literal
    if s.lstrip("-").isdigit():
        try:
            return _z3_make(_z3_mod.IntVal, int(s), ctx=ctx)
        except ValueError:
            pass

    # String literal
    if (s.startswith("'") and s.endswith("'")) or (
        s.startswith('"') and s.endswith('"')
    ):
        return None  # never map strings into a collision-prone integer domain

    # Outer CFG negation wrapper: NOT(...)
    if s.startswith("NOT(") and s.endswith(")"):
        inner = _ussa_sexpr_to_z3(s[4:-1], ssa_env, z3_vars, parameters, ctx=ctx)
        b_inner = _to_z3_bool(inner, ctx=ctx)
        return _z3_mod.Not(b_inner) if b_inner is not None else None

    # U-SSA Call: CALL(callee, arg1, arg2, ...)
    if s.startswith("CALL(") and s.endswith(")"):
        inner = s[5:-1]
        items = _split_top_level(inner, sep=",")
        if not items:
            return None
        callee = items[0].strip()
        args_z3: list[Any] = []
        kw_names: list[str] = []
        for raw_arg in items[1:]:
            arg_s = raw_arg.strip()
            if not arg_s:
                continue
            kw = _split_kwarg(arg_s)
            if kw is not None:
                # Bound by keyword. Fold the name into the callee symbol so the
                # binding is part of the term: `f(a, k=x)` and `f(a, x)` are
                # different calls and must not encode to the same symbol, while
                # two sides that agree on the binding still encode congruently.
                kw_name, arg_s = kw
                kw_names.append(kw_name)
            z_arg = _to_z3_int(_ussa_sexpr_to_z3(arg_s, ssa_env, z3_vars, parameters, ctx=ctx), ctx=ctx)
            if z_arg is None:
                return None
            args_z3.append(z_arg)
        sym_name = callee + "".join(f"@kw:{n}" for n in kw_names)
        arg_sorts = [_z3_make(_z3_mod.IntSort, ctx=ctx) for _ in args_z3]
        f_sym = _z3_make(_z3_mod.Function, sym_name, *arg_sorts, _z3_make(_z3_mod.IntSort, ctx=ctx), ctx=ctx)
        return f_sym(*args_z3)

    # Parenthesized U-SSA S-expression
    if s.startswith("(") and s.endswith(")"):
        tokens = _split_top_level(s[1:-1], sep=" ")
        if not tokens:
            return None

        # Unary prefix: (Not x_0), (USub x_0), (UAdd x_0)
        if len(tokens) == 2 and tokens[0] in _UNARY_OPS:
            op = tokens[0]
            val = _ussa_sexpr_to_z3(tokens[1], ssa_env, z3_vars, parameters, ctx=ctx)
            if val is None:
                return None
            if op == "Not":
                b_val = _to_z3_bool(val, ctx=ctx)
                return _z3_mod.Not(b_val) if b_val is not None else None
            if op == "USub":
                i_val = _to_z3_int(val, ctx=ctx)
                return -i_val if i_val is not None else None
            if op == "UAdd":
                return _to_z3_int(val, ctx=ctx)
            return None

        # Binary prefix: (Add lhs rhs), (Sub lhs rhs), (Mult lhs rhs)
        if len(tokens) == 3 and tokens[0] in _BIN_OPS:
            op = tokens[0]
            lhs = _to_z3_int(_ussa_sexpr_to_z3(tokens[1], ssa_env, z3_vars, parameters, ctx=ctx), ctx=ctx)
            rhs = _to_z3_int(_ussa_sexpr_to_z3(tokens[2], ssa_env, z3_vars, parameters, ctx=ctx), ctx=ctx)
            if lhs is None or rhs is None:
                return None
            if op == "Add":
                return lhs + rhs
            if op == "Sub":
                return lhs - rhs
            if op == "Mult":
                return lhs * rhs
            if op in ("FloorDiv", "Div"):
                # Integer division; avoid Z3's nonlinear real division by
                # translating to multiplication-free QF_LIA when possible.
                return _z3_mod.If(
                    rhs != 0,
                    lhs / rhs,
                    _z3_make(_z3_mod.IntVal, 0, ctx=ctx),
                )
            if op == "Mod":
                return _z3_mod.If(
                    rhs != 0,
                    lhs % rhs,
                    _z3_make(_z3_mod.IntVal, 0, ctx=ctx),
                )
            if op == "BitAnd":
                f_sym = _z3_make(_z3_mod.Function,
                    "bitand_uninterp",
                    _z3_make(_z3_mod.IntSort, ctx=ctx),
                    _z3_make(_z3_mod.IntSort, ctx=ctx),
                    _z3_make(_z3_mod.IntSort, ctx=ctx),
                    ctx=ctx,
                )
                return f_sym(lhs, rhs)
            if op == "BitOr":
                f_sym = _z3_make(_z3_mod.Function,
                    "bitor_uninterp",
                    _z3_make(_z3_mod.IntSort, ctx=ctx),
                    _z3_make(_z3_mod.IntSort, ctx=ctx),
                    _z3_make(_z3_mod.IntSort, ctx=ctx),
                    ctx=ctx,
                )
                return f_sym(lhs, rhs)
            if op == "BitXor":
                f_sym = _z3_make(_z3_mod.Function,
                    "bitxor_uninterp",
                    _z3_make(_z3_mod.IntSort, ctx=ctx),
                    _z3_make(_z3_mod.IntSort, ctx=ctx),
                    _z3_make(_z3_mod.IntSort, ctx=ctx),
                    ctx=ctx,
                )
                return f_sym(lhs, rhs)
            return None

        # N-ary Boolean prefix: (And v1 v2 ...), (Or v1 v2 ...)
        if len(tokens) >= 2 and tokens[0] in _BOOL_OPS:
            op = tokens[0]
            b_vals = [
                _to_z3_bool(_ussa_sexpr_to_z3(t, ssa_env, z3_vars, parameters, ctx=ctx), ctx=ctx)
                for t in tokens[1:]
            ]
            if any(v is None for v in b_vals):
                return None
            return _z3_mod.And(*b_vals) if op == "And" else _z3_mod.Or(*b_vals)

        # Infix Comparison: (x_0 Gt 0) or chained (0 Lt x_0 Lt 10)
        if len(tokens) >= 3 and len(tokens) % 2 == 1 and tokens[1] in _COMPARE_OPS:
            lhs = _to_z3_int(_ussa_sexpr_to_z3(tokens[0], ssa_env, z3_vars, parameters, ctx=ctx), ctx=ctx)
            if lhs is None:
                return None
            comps = []
            for idx in range(1, len(tokens), 2):
                op_name = tokens[idx]
                rhs = _to_z3_int(
                    _ussa_sexpr_to_z3(tokens[idx + 1], ssa_env, z3_vars, parameters, ctx=ctx), ctx=ctx
                )
                if rhs is None:
                    return None
                if op_name == "Gt":
                    comps.append(lhs > rhs)
                elif op_name == "GtE":
                    comps.append(lhs >= rhs)
                elif op_name == "Lt":
                    comps.append(lhs < rhs)
                elif op_name == "LtE":
                    comps.append(lhs <= rhs)
                elif op_name in ("Eq", "Is"):
                    comps.append(lhs == rhs)
                elif op_name in ("NotEq", "IsNot"):
                    comps.append(lhs != rhs)
                else:
                    return None
                lhs = rhs
            return _z3_mod.And(*comps) if len(comps) > 1 else comps[0]

    # SSA variable or parameter lookup
    base_name = _strip_ssa_suffix(s, parameters)
    if base_name in ssa_env and ssa_env[base_name] is not None:
        return ssa_env[base_name]
    if base_name in z3_vars:
        return z3_vars[base_name]
    if s.isidentifier():
        z3_vars[base_name] = _z3_make(_z3_mod.Int, base_name, ctx=ctx)
        return z3_vars[base_name]

    # Do not parse source-expression fragments here: parsing belongs to the
    # compiler stage. Expressions outside the explicit U-SSA grammar abstain.
    return None


class _USSACallRecord(msgspec.Struct, frozen=True, kw_only=True):
    callee: str
    norm_args: tuple[str, ...]
    z3_args: tuple[Any, ...]
    path_guards_z3: tuple[Any, ...]
    source_line: int


class _USSAReturnRecord(msgspec.Struct, frozen=True, kw_only=True):
    norm_expr: str
    z3_expr: Any
    path_guards_z3: tuple[Any, ...]
    source_line: int


class _USSAGuardRecord(msgspec.Struct, frozen=True, kw_only=True):
    norm_cond: str
    z3_cond: Any
    then_summary: str
    else_summary: str
    path_guards_z3: tuple[Any, ...]
    source_line: int


class _USSAShadowRecord(msgspec.Struct, frozen=True, kw_only=True):
    param_name: str
    norm_val: str
    z3_val: Any
    source_line: int


class _USSASymbolicExtractor:
    """
    Executes symbolic path exploration directly over `FunctionUSSA` basic blocks,
    PhiNodes, and CFG edges to build Z3 path constraints and function summaries.
    """

    def __init__(
        self, func_ussa: FunctionUSSA, z3_vars: dict[str, Any] | None = None,
        *, ctx: Any = None,
    ) -> None:
        self.func = func_ussa
        self.param_set = set(func_ussa.parameters)
        if _z3_mod is not None and ctx is None:
            if z3_vars:
                first = next(iter(z3_vars.values()), None)
                ctx = getattr(first, "ctx", None)
            if ctx is None:
                ctx = _z3_mod.Context()
        self.ctx = ctx
        self.z3_vars: dict[str, Any] = (
            dict(z3_vars)
            if z3_vars is not None
            else (
                {p: _z3_make(_z3_mod.Int, p, ctx=self.ctx) for p in func_ussa.parameters}
                if _z3_mod is not None
                else {}
            )
        )
        self.calls: list[_USSACallRecord] = []
        self.returns: list[_USSAReturnRecord] = []
        self.guards: list[_USSAGuardRecord] = []
        self.shadowed_params: list[_USSAShadowRecord] = []
        self.unsupported_construct: str | None = None

        self._block_map: dict[str, USSABasicBlock] = {
            b.block_id: b for b in func_ussa.basic_blocks
        }
        self._cfg_out: dict[str, list[CPGEdge]] = {}
        for edge in func_ussa.cfg_edges:
            if edge.edge_kind == "CFG":
                self._cfg_out.setdefault(edge.src_node_uid, []).append(edge)

        self._explore()

    def _extract_calls_from_sexpr(
        self,
        expr_str: str,
        ssa_env: dict[str, Any],
        expr_env: dict[str, str],
        path_guards_z3: tuple[Any, ...],
        source_line: int,
    ) -> None:
        s = expr_str.strip()
        if s.startswith("CALL(") and s.endswith(")"):
            inner = s[5:-1]
            items = _split_top_level(inner, sep=",")
            if items:
                callee = items[0].strip()
                norm_args: list[str] = []
                z3_args: list[Any] = []
                for raw_arg in items[1:]:
                    arg_s = raw_arg.strip()
                    if not arg_s:
                        continue
                    kw_name = ""
                    kw = _split_kwarg(arg_s)
                    if kw is not None:
                        kw_name, arg_s = kw
                    # Recurse on nested call arguments first
                    self._extract_calls_from_sexpr(
                        arg_s, ssa_env, expr_env, path_guards_z3, source_line
                    )
                    norm_arg = _normalize_ussa_expr(arg_s, expr_env, self.param_set)
                    if kw_name:
                        # Keep the binding visible. Passing an argument
                        # positionally and passing the same argument by keyword
                        # are different calls; dropping the name made the two
                        # normalise identically and compare equal.
                        norm_arg = f"kw:{kw_name}={norm_arg}"
                    norm_args.append(norm_arg)
                    # A keyword binding has no positional encoding here, so it
                    # cannot be encoded as an int. Report None and let the
                    # caller fall back to comparing `norm_args`, which retains
                    # the binding, instead of silently ignoring it.
                    z3_args.append(
                        None
                        if kw_name
                        else _ussa_sexpr_to_z3(
                            arg_s, ssa_env, self.z3_vars, self.param_set, ctx=self.ctx
                        )
                    )
                self.calls.append(
                    _USSACallRecord(
                        callee=callee,
                        norm_args=tuple(norm_args),
                        z3_args=tuple(z3_args),
                        path_guards_z3=path_guards_z3,
                        source_line=source_line,
                    )
                )

    def _summarize_block_terminal(self, block_id: str) -> str:
        blk = self._block_map.get(block_id)
        if blk is None or not blk.instructions:
            return "pass"
        last = blk.instructions[-1]
        if last.opcode == "RETURN" and last.operands:
            return f"return {last.operands[0]}"
        if last.opcode == "ASSIGN" and last.target_var and last.operands:
            return f"{last.target_var} = {last.operands[0]}"
        if last.operands:
            return f"{last.opcode}({last.operands[0]})"
        return last.opcode

    def _validate_cfg(self) -> str | None:
        """Reject cyclic, malformed, duplicate-id, or disconnected CFGs."""
        block_ids = [b.block_id for b in self.func.basic_blocks]
        if len(block_ids) != len(set(block_ids)):
            return "MalformedCFG:DuplicateBlockId"
        ids = set(block_ids)
        if not block_ids:
            return "EmptyCFG"
        graph: dict[str, list[str]] = {bid: [] for bid in block_ids}
        for edge in self.func.cfg_edges:
            if edge.edge_kind != "CFG":
                continue
            if edge.src_node_uid not in ids or edge.dst_node_uid not in ids:
                return "MalformedCFG:UnknownEdgeEndpoint"
            graph[edge.src_node_uid].append(edge.dst_node_uid)
        color: dict[str, int] = {bid: 0 for bid in block_ids}
        reachable: set[str] = set()
        for root in block_ids:
            if color[root] != 0:
                continue
            stack: list[tuple[str, int]] = [(root, 0)]
            color[root] = 1
            while stack:
                node, next_child = stack[-1]
                children = graph[node]
                if next_child >= len(children):
                    color[node] = 2
                    stack.pop()
                    continue
                child = children[next_child]
                stack[-1] = (node, next_child + 1)
                if color[child] == 1:
                    return "CyclicCFG"
                if color[child] == 0:
                    color[child] = 1
                    stack.append((child, 0))
        entry = block_ids[0]
        todo = [entry]
        while todo:
            node = todo.pop()
            if node in reachable:
                continue
            reachable.add(node)
            todo.extend(graph[node])
        if reachable != ids:
            return "DisconnectedCFG"
        return None

    def _explore(self) -> None:
        if not self.func.basic_blocks:
            self.unsupported_construct = "EmptyCFG"
            return
        cfg_problem = self._validate_cfg()
        if cfg_problem is not None:
            self.unsupported_construct = cfg_problem
            return

        for blk in self.func.basic_blocks:
            for inst in blk.instructions:
                if inst.opcode in _UNSUPPORTED_USSA_OPCODES:
                    self.unsupported_construct = _UNSUPPORTED_USSA_OPCODES[inst.opcode]
                    return

        init_ssa_env: dict[str, Any] = {}
        init_expr_env: dict[str, str] = {}
        for p in self.func.parameters:
            if p in self.z3_vars:
                init_ssa_env[f"{p}_0"] = self.z3_vars[p]
                init_ssa_env[p] = self.z3_vars[p]
            init_expr_env[f"{p}_0"] = p
            init_expr_env[p] = p

        self._walk_dag(init_ssa_env, init_expr_env)

    def _walk_dag(
        self, initial_ssa: dict[str, Any], initial_expr: dict[str, str]
    ) -> None:
        """Encode each acyclic CFG block once with reachability and SSA merges.

        Cyclic and disconnected CFGs are rejected by ``_validate_cfg`` before
        this method runs. The algorithm therefore processes each block and edge
        a bounded number of times instead of enumerating root-to-exit paths.
        """
        if _z3_mod is None:
            self.unsupported_construct = "Z3Unavailable"
            return
        block_ids = [block.block_id for block in self.func.basic_blocks]
        entry_id = block_ids[0]
        blocks = self._block_map
        edges = [edge for edge in self.func.cfg_edges if edge.edge_kind == "CFG"]
        outgoing: dict[str, list[CPGEdge]] = {bid: [] for bid in block_ids}
        incoming: dict[str, list[CPGEdge]] = {bid: [] for bid in block_ids}
        for edge in edges:
            outgoing[edge.src_node_uid].append(edge)
            incoming[edge.dst_node_uid].append(edge)

        # Deterministic Kahn topological ordering.
        indegree = {bid: len(incoming[bid]) for bid in block_ids}
        ready = deque(bid for bid in block_ids if indegree[bid] == 0)
        order: list[str] = []
        while ready:
            bid = ready.popleft()
            order.append(bid)
            for edge in outgoing[bid]:
                indegree[edge.dst_node_uid] -= 1
                if indegree[edge.dst_node_uid] == 0:
                    ready.append(edge.dst_node_uid)
        if len(order) != len(block_ids):
            self.unsupported_construct = "CyclicCFG"
            return
        if order[0] != entry_id:
            self.unsupported_construct = "MalformedCFG:EntryNotRoot"
            return

        bool_true = _z3_make(_z3_mod.BoolVal, True, ctx=self.ctx)
        reach: dict[str, Any] = {entry_id: bool_true}
        out_ssa: dict[str, dict[str, Any]] = {}
        out_expr: dict[str, dict[str, str]] = {}
        edge_guard: dict[tuple[str, str, str | None], Any] = {}

        def get_edge_guard(edge: CPGEdge, ssa_env: dict[str, Any]) -> Any:
            label = edge.predicate_label
            if label is None or label == "fallthrough":
                return bool_true
            translated = _ussa_sexpr_to_z3(label, ssa_env, self.z3_vars, self.param_set, ctx=self.ctx)
            guard = _to_z3_bool(translated, ctx=self.ctx)
            if guard is None:
                self.unsupported_construct = "UnsupportedCFGGuard"
            return guard

        def merge_values(
            key: str,
            predecessor_edges: list[CPGEdge],
            envs: dict[str, dict[str, Any]],
            routes: dict[tuple[str, str, str | None], Any],
            *,
            is_expr: bool = False,
        ) -> Any:
            candidates: list[tuple[Any, Any]] = []
            for edge in predecessor_edges:
                src = edge.src_node_uid
                env = envs.get(src, {})
                if key not in env:
                    continue
                edge_condition = routes.get((edge.src_node_uid, edge.dst_node_uid, edge.predicate_label))
                source_reach = reach.get(src)
                if edge_condition is None or source_reach is None:
                    continue
                condition = _z3_mod.And(source_reach, edge_condition)
                candidates.append((condition, env[key]))
            if not candidates:
                return None
            values = [value for _condition, value in candidates]
            if is_expr:
                if all(value == values[0] for value in values[1:]):
                    return values[0]
                return "PHI(" + ",".join(str(value) for value in values) + ")"
            if all(
                (value is values[0]) or
                (value is not None and values[0] is not None and _z3_mod.eq(value, values[0]))
                for value in values[1:]
            ):
                return values[0]
            if any(value is None for value in values):
                return None
            try:
                first_sort = values[0].sort()
                if any(value.sort() != first_sort for value in values[1:]):
                    return None
                result = values[-1]
                for condition, value in reversed(candidates[:-1]):
                    result = _z3_mod.If(condition, value, result)
                return result
            except Exception:
                return None

        for bid in order:
            block = blocks[bid]
            pred_edges = incoming[bid]
            if bid == entry_id:
                block_reach = bool_true
                cur_ssa = dict(initial_ssa)
                cur_expr = dict(initial_expr)
            else:
                routes: list[Any] = []
                for edge in pred_edges:
                    src_reach = reach.get(edge.src_node_uid)
                    guard = edge_guard.get((edge.src_node_uid, edge.dst_node_uid, edge.predicate_label))
                    if src_reach is None or guard is None:
                        self.unsupported_construct = self.unsupported_construct or "MalformedCFG:MissingPredecessorState"
                        return
                    routes.append(_z3_mod.And(src_reach, guard))
                block_reach = _z3_mod.Or(*routes) if routes else None
                if block_reach is None:
                    self.unsupported_construct = "DisconnectedCFG"
                    return
                reach[bid] = block_reach
                cur_ssa = {}
                cur_expr = {}
                all_ssa_keys = set.intersection(*(set(out_ssa[e.src_node_uid]) for e in pred_edges)) if pred_edges else set()
                all_expr_keys = set.intersection(*(set(out_expr[e.src_node_uid]) for e in pred_edges)) if pred_edges else set()
                for key in all_ssa_keys:
                    value = merge_values(key, pred_edges, out_ssa, edge_guard)
                    if value is not None:
                        cur_ssa[key] = value
                for key in all_expr_keys:
                    value = merge_values(key, pred_edges, out_expr, edge_guard, is_expr=True)
                    if value is not None:
                        cur_expr[key] = value

            # Resolve each SSA phi exactly once from predecessor-specific values.
            for phi in block.phi_nodes:
                phi_inputs: list[tuple[Any, Any, str, str]] = []
                for pred_id, variable in phi.incoming_branches:
                    matching_edges = [e for e in pred_edges if e.src_node_uid == pred_id]
                    if len(matching_edges) != 1:
                        self.unsupported_construct = "MalformedPhiIncoming"
                        return
                    edge = matching_edges[0]
                    pred_env = out_ssa.get(pred_id, {})
                    if variable not in pred_env:
                        self.unsupported_construct = "MalformedPhiValue"
                        return
                    guard = edge_guard.get((edge.src_node_uid, edge.dst_node_uid, edge.predicate_label))
                    pred_reach = reach.get(pred_id)
                    if guard is None or pred_reach is None:
                        self.unsupported_construct = "MalformedPhiGuard"
                        return
                    phi_inputs.append((_z3_mod.And(pred_reach, guard), pred_env[variable], variable, pred_id))
                actual_preds = {edge.src_node_uid for edge in pred_edges}
                if {pred for pred, _var in phi.incoming_branches} != actual_preds:
                    self.unsupported_construct = "MalformedPhiPredecessorSet"
                    return
                if not phi_inputs:
                    self.unsupported_construct = "MalformedPhiIncoming"
                    return
                value = phi_inputs[-1][1]
                for condition, incoming_value, _var, _pred_id in reversed(phi_inputs[:-1]):
                    try:
                        if incoming_value.sort() != value.sort():
                            self.unsupported_construct = "MixedPhiSorts"
                            return
                    except Exception:
                        self.unsupported_construct = "UnsupportedPhiValue"
                        return
                    value = _z3_mod.If(condition, incoming_value, value)
                cur_ssa[phi.target_var] = value
                base_target = _strip_ssa_suffix(phi.target_var, self.param_set)
                cur_ssa[base_target] = value
                normalized_exprs = [out_expr.get(pred_id, {}).get(var) for _cond, _val, var, pred_id in phi_inputs]
                cur_expr[phi.target_var] = (
                    normalized_exprs[0]
                    if normalized_exprs and normalized_exprs[0] is not None and all(x == normalized_exprs[0] for x in normalized_exprs)
                    else f"PHI({phi.target_var})"
                )
                cur_expr[base_target] = cur_expr[phi.target_var]

            # All records use the block's single reachability predicate, not a
            # separate record for each root-to-block path.
            path_guards = (block_reach,)
            for inst in block.instructions:
                if inst.opcode in ("ASSIGN", "BINOP") and inst.target_var and inst.operands:
                    raw_rhs = inst.operands[0]
                    used_ssa = inst.operands[1:]
                    self._extract_calls_from_sexpr(raw_rhs, cur_ssa, cur_expr, path_guards, inst.source_line)
                    z3_rhs = _ussa_sexpr_to_z3(raw_rhs, cur_ssa, self.z3_vars, self.param_set, ctx=self.ctx)
                    norm_rhs = _normalize_ussa_expr(raw_rhs, cur_expr, self.param_set)
                    base_tgt = _strip_ssa_suffix(inst.target_var, self.param_set)
                    unconditional = _z3_mod.is_true(_z3_mod.simplify(block_reach))
                    if (inst.opcode == "ASSIGN" and base_tgt in self.param_set and
                        inst.target_var == f"{base_tgt}_1" and f"{base_tgt}_0" not in used_ssa and unconditional):
                        self.shadowed_params.append(_USSAShadowRecord(param_name=base_tgt, norm_val=norm_rhs, z3_val=z3_rhs, source_line=inst.source_line))
                    cur_ssa[inst.target_var] = z3_rhs
                    cur_expr[inst.target_var] = norm_rhs
                    cur_ssa[base_tgt] = z3_rhs
                    cur_expr[base_tgt] = norm_rhs
                elif inst.opcode == "CALL" and inst.operands:
                    self._extract_calls_from_sexpr(inst.operands[0], cur_ssa, cur_expr, path_guards, inst.source_line)
                elif inst.opcode == "BRANCH" and inst.operands:
                    raw_cond = inst.operands[0]
                    norm_cond = _normalize_ussa_expr(raw_cond, cur_expr, self.param_set)
                    cond_value = _ussa_sexpr_to_z3(raw_cond, cur_ssa, self.z3_vars, self.param_set, ctx=self.ctx)
                    z3_cond = _to_z3_bool(cond_value, ctx=self.ctx)
                    then_sum, else_sum = "pass", "pass"
                    for edge in outgoing[bid]:
                        if edge.predicate_label == raw_cond:
                            then_sum = self._summarize_block_terminal(edge.dst_node_uid)
                        elif edge.predicate_label == f"NOT({raw_cond})":
                            else_sum = self._summarize_block_terminal(edge.dst_node_uid)
                    self.guards.append(_USSAGuardRecord(norm_cond=norm_cond, z3_cond=z3_cond, then_summary=then_sum, else_summary=else_sum, path_guards_z3=path_guards, source_line=inst.source_line))
                elif inst.opcode == "RETURN":
                    raw_ret = inst.operands[0] if inst.operands else "None"
                    self._extract_calls_from_sexpr(raw_ret, cur_ssa, cur_expr, path_guards, inst.source_line)
                    norm_ret = _normalize_ussa_expr(raw_ret, cur_expr, self.param_set)
                    z3_ret = _ussa_sexpr_to_z3(raw_ret, cur_ssa, self.z3_vars, self.param_set, ctx=self.ctx)
                    self.returns.append(_USSAReturnRecord(norm_expr=norm_ret, z3_expr=z3_ret, path_guards_z3=path_guards, source_line=inst.source_line))
                elif inst.opcode == "RAISE":
                    # Raised paths do not contribute return values. Exception
                    # semantics are handled conservatively by the caller.
                    self.unsupported_construct = self.unsupported_construct or "RaisePathUnsupported"
                    return
                elif inst.opcode in _UNSUPPORTED_USSA_OPCODES:
                    self.unsupported_construct = _UNSUPPORTED_USSA_OPCODES[inst.opcode]
                    return

            out_ssa[bid] = cur_ssa
            out_expr[bid] = cur_expr
            for edge in outgoing[bid]:
                guard = get_edge_guard(edge, cur_ssa)
                if guard is None:
                    return
                edge_guard[(edge.src_node_uid, edge.dst_node_uid, edge.predicate_label)] = guard

    def build_return_ite(self) -> Any:
        """
        Composes all path return expressions and their branch guards into a single
        Z3 If-Then-Else (ITE) term representing the full function return semantics.
        """
        if _z3_mod is None or not self.returns:
            return None
        if any(r.z3_expr is None for r in self.returns):
            return None

        acc = _to_z3_int(self.returns[-1].z3_expr, ctx=self.ctx)
        if acc is None:
            return None

        for ret in reversed(self.returns[:-1]):
            val = _to_z3_int(ret.z3_expr, ctx=self.ctx)
            if val is None:
                return None
            if not ret.path_guards_z3:
                acc = val
            else:
                cond = (
                    _z3_mod.And(*ret.path_guards_z3)
                    if len(ret.path_guards_z3) > 1
                    else ret.path_guards_z3[0]
                )
                acc = _z3_mod.If(cond, val, acc)
        return acc


def _detect_unsupported_ast_construct(
    base_fn_node: ast.AST | None,
    head_fn_node: ast.AST | None,
    ext_base: _USSASymbolicExtractor,
    ext_head: _USSASymbolicExtractor,
) -> str | None:
    if ext_base.unsupported_construct:
        return ext_base.unsupported_construct
    if ext_head.unsupported_construct:
        return ext_head.unsupported_construct
    for fn_node in (base_fn_node, head_fn_node):
        if fn_node is not None:
            for n in ast.walk(fn_node):
                if isinstance(n, _UNSUPPORTED_AST_TYPES):
                    return type(n).__name__
    return None


def _extract_model_assignments(
    model: Any,
    z3_vars: dict[str, Any],
    parameters: tuple[str, ...],
    *,
    default_val: int = 0,
) -> dict[str, int | str | bool]:
    """Materialize model inputs; never invent fallback values for a witness."""
    if _z3_mod is None:
        return {}
    result: dict[str, int | str] = {}
    for name in parameters:
        sym = z3_vars.get(name)
        if sym is None:
            return {}
        value = model.eval(sym, model_completion=True)
        if _z3_mod.is_int_value(value):
            result[name] = value.as_long()
        elif _z3_mod.is_string_value(value):
            try:
                result[name] = value.as_string()
            except Exception:
                return {}
        elif _z3_mod.is_true(value) or _z3_mod.is_false(value):
            result[name] = _z3_mod.is_true(value)
        else:
            return {}
    return result


@dataclass(frozen=True)
class _PyVal:
    term: Any
    kind: str | None


class _UnsupportedSymbolicExpression(Exception):
    pass


class _UnsupportedInputDomain(_UnsupportedSymbolicExpression):
    """Raised when proving would require an unstated Python input-domain assumption.

    This exception must not fall through to the legacy integer-only U-SSA prover:
    that fallback would silently reinterpret arbitrary Python values as integers.
    """


class _Z3ProofContext:
    """Per-proof Z3 context and collision-free tagged Python scalar sort."""
    def __init__(self, timeout_ms: int = 2000) -> None:
        if _z3_mod is None:
            raise RuntimeError("z3-solver is not available")
        self.ctx = _z3_mod.Context()
        self.timeout_ms = timeout_ms
        dt = _z3_mod.Datatype("PyVal", ctx=self.ctx)
        dt.declare("mk_none")
        dt.declare("mk_bool", ("bool_val", _z3_mod.BoolSort(self.ctx)))
        dt.declare("mk_int", ("int_val", _z3_mod.IntSort(self.ctx)))
        dt.declare("mk_str", ("str_val", _z3_mod.StringSort(self.ctx)))
        self.pyval = dt.create()

    def none(self) -> _PyVal:
        # Z3Py exposes zero-arity datatype constructors as a value, unlike
        # constructors with fields which are called with their payloads.
        ctor = self.pyval.mk_none
        term = ctor() if callable(ctor) else ctor
        return _PyVal(term, "NONE")

    def boolean(self, value: Any) -> _PyVal:
        term = value if hasattr(value, "ctx") else _z3_mod.BoolVal(value, ctx=self.ctx)
        return _PyVal(self.pyval.mk_bool(term), "BOOL")

    def integer(self, value: Any) -> _PyVal:
        term = value if hasattr(value, "ctx") else _z3_mod.IntVal(value, ctx=self.ctx)
        return _PyVal(self.pyval.mk_int(term), "INT")

    def string(self, value: Any) -> _PyVal:
        term = value if hasattr(value, "ctx") else _z3_mod.StringVal(value, ctx=self.ctx)
        return _PyVal(self.pyval.mk_str(term), "STR")

    def solver(self) -> Any:
        solver = _z3_mod.Solver(ctx=self.ctx)
        solver.set("timeout", self.timeout_ms)
        return solver

    def is_true(self, expr: Any) -> bool:
        return _z3_mod.is_true(_z3_mod.simplify(expr))

    def is_false(self, expr: Any) -> bool:
        return _z3_mod.is_false(_z3_mod.simplify(expr))

    def truth(self, value: _PyVal) -> Any:
        pv = self.pyval
        term = value.term
        return _z3_mod.If(
            pv.is_mk_none(term),
            _z3_mod.BoolVal(False, ctx=self.ctx),
            _z3_mod.If(
                pv.is_mk_bool(term), pv.bool_val(term),
                _z3_mod.If(
                    pv.is_mk_int(term), pv.int_val(term) != _z3_mod.IntVal(0, ctx=self.ctx),
                    pv.str_val(term) != _z3_mod.StringVal("", ctx=self.ctx),
                ),
            ),
        )

    def numeric(self, value: _PyVal) -> Any:
        """Numeric projection for statically supported INT/BOOL terms."""
        pv = self.pyval
        return _z3_mod.If(
            pv.is_mk_bool(value.term),
            _z3_mod.If(pv.bool_val(value.term), _z3_mod.IntVal(1, ctx=self.ctx), _z3_mod.IntVal(0, ctx=self.ctx)),
            pv.int_val(value.term),
        )

    def py_eq(self, lhs: _PyVal, rhs: _PyVal) -> Any:
        """Python equality over supported scalar constructors, including bool/int coercion."""
        pv = self.pyval
        lhs_num = _z3_mod.Or(pv.is_mk_int(lhs.term), pv.is_mk_bool(lhs.term))
        rhs_num = _z3_mod.Or(pv.is_mk_int(rhs.term), pv.is_mk_bool(rhs.term))
        both_numeric = _z3_mod.And(lhs_num, rhs_num)
        numeric_eq = self.numeric(lhs) == self.numeric(rhs)
        # Datatype equality gives correct string payload equality and None
        # equality; the numeric branch overrides constructor inequality for
        # Python's bool/int equality rule.
        return _z3_mod.If(both_numeric, numeric_eq, lhs.term == rhs.term)


def _encode_py_eq(lhs: _PyVal, rhs: _PyVal, pctx: _Z3ProofContext) -> Any:
    """Canonical tested entry point for Python `==` over supported PyVal types."""
    return pctx.py_eq(lhs, rhs)


class _ASTPyValEvaluator:
    """Conservative symbolic executor for a side-effect-free scalar AST subset."""
    def __init__(self, pctx: _Z3ProofContext, fn: ast.FunctionDef | ast.AsyncFunctionDef, parameters: tuple[str, ...]) -> None:
        self.pctx = pctx
        self.fn = fn
        self.parameters = parameters
        self.return_term = pctx.none().term
        self.returned = _z3_mod.BoolVal(False, ctx=pctx.ctx)
        self.raw_parameters: dict[str, Any] = {}
        self.initial_env: dict[str, _PyVal] = {}
        self._build_parameters()

    def _build_parameters(self) -> None:
        """Create shared tagged inputs and record explicit supported type assumptions.

        Python annotations are not runtime-enforced. This prover therefore uses a
        recognized scalar annotation as an explicit verification-domain assumption,
        not as a claim that Python enforces the annotation. Unannotated or otherwise
        dynamic inputs remain unconstrained PyVal terms; operations requiring a
        narrower domain must abstain rather than project an arbitrary constructor
        through an unrelated datatype selector.
        """
        if self.fn.args.vararg is not None or self.fn.args.kwarg is not None:
            raise _UnsupportedSymbolicExpression("variadic function parameters are unsupported")
        args = [*self.fn.args.posonlyargs, *self.fn.args.args, *self.fn.args.kwonlyargs]
        if tuple(arg.arg for arg in args) != self.parameters:
            raise _UnsupportedSymbolicExpression("parameter signatures do not align")
        for arg in args:
            raw = _z3_make(_z3_mod.Const, arg.arg, self.pctx.pyval, ctx=self.pctx.ctx)
            self.raw_parameters[arg.arg] = raw
            kind = None
            if isinstance(arg.annotation, ast.Name):
                ann_str = arg.annotation.id
            elif isinstance(arg.annotation, ast.Constant) and isinstance(arg.annotation.value, str):
                # Also support ``from __future__ import annotations`` for simple
                # scalar names without evaluating annotation expressions.
                ann_str = arg.annotation.value.strip()
            else:
                ann_str = None
            if ann_str == "int":
                kind = "INT"
            elif ann_str == "bool":
                kind = "BOOL"
            elif ann_str == "str":
                kind = "STR"
            # Floats deliberately remain unsupported: PyVal has no Real/Float
            # constructor, so treating them as integers would be unsound.
            self.initial_env[arg.arg] = _PyVal(raw, kind)

    def _numeric(self, value: _PyVal, operation: str) -> Any:
        if value.kind not in ("INT", "BOOL"):
            raise _UnsupportedInputDomain(
                f"{operation} requires a declared INT/BOOL input domain; "
                "unannotated or mixed-type values are not coerced to integers"
            )
        return self.pctx.numeric(value)

    def _truth(self, value: _PyVal, operation: str) -> Any:
        if value.kind is None:
            raise _UnsupportedInputDomain(
                f"{operation} requires a supported scalar input domain; "
                "dynamic Python truthiness is not modeled"
            )
        return self.pctx.truth(value)

    def _is_singleton_expr(self, node: ast.AST, value: _PyVal) -> bool:
        # A statically typed bool parameter, like a bool literal, is a Python
        # singleton object at runtime; None is likewise a singleton constructor.
        return value.kind in ("NONE", "BOOL") or (
            isinstance(node, ast.Constant) and (node.value is None or isinstance(node.value, bool))
        )

    def eval_expr(self, node: ast.AST, env: dict[str, _PyVal]) -> _PyVal:
        pctx, pv = self.pctx, self.pctx.pyval
        if isinstance(node, ast.Constant):
            if node.value is None:
                return pctx.none()
            if isinstance(node.value, bool):
                return pctx.boolean(node.value)
            if isinstance(node.value, int):
                return pctx.integer(node.value)
            if isinstance(node.value, str):
                return pctx.string(node.value)
            raise _UnsupportedSymbolicExpression(f"unsupported literal type {type(node.value).__name__}")
        if isinstance(node, ast.Name):
            if node.id not in env:
                raise _UnsupportedSymbolicExpression(f"unbound or unsupported name {node.id}")
            return env[node.id]
        if isinstance(node, ast.UnaryOp):
            value = self.eval_expr(node.operand, env)
            if isinstance(node.op, ast.Not):
                return pctx.boolean(_z3_mod.Not(self._truth(value, "not")))
            n = self._numeric(value, "unary arithmetic")
            if isinstance(node.op, ast.USub):
                return pctx.integer(-n)
            if isinstance(node.op, ast.UAdd):
                return pctx.integer(n)
            raise _UnsupportedSymbolicExpression(f"unsupported unary operator {type(node.op).__name__}")
        if isinstance(node, ast.BinOp):
            left, right = self.eval_expr(node.left, env), self.eval_expr(node.right, env)
            if isinstance(node.op, ast.Add) and left.kind == right.kind == "STR":
                return pctx.string(_z3_mod.Concat(pv.str_val(left.term), pv.str_val(right.term)))
            if left.kind not in ("INT", "BOOL") or right.kind not in ("INT", "BOOL"):
                raise _UnsupportedInputDomain(
                    "arithmetic requires supported INT/BOOL operands; "
                    "string, None, unannotated, and mixed-type operands abstain"
                )
            a, b = self._numeric(left, "arithmetic"), self._numeric(right, "arithmetic")
            if isinstance(node.op, ast.Add):
                return pctx.integer(a + b)
            if isinstance(node.op, ast.Sub):
                return pctx.integer(a - b)
            if isinstance(node.op, ast.Mult):
                return pctx.integer(a * b)
            raise _UnsupportedSymbolicExpression(f"unsupported binary operator {type(node.op).__name__}")
        if isinstance(node, ast.Compare):
            left_node = node.left
            left = self.eval_expr(left_node, env)
            comparisons = []
            for op, right_node in zip(node.ops, node.comparators):
                right = self.eval_expr(right_node, env)
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    if left.kind is None or right.kind is None:
                        raise _UnsupportedInputDomain(
                            "Python equality on an unannotated or mixed-type value "
                            "requires unsupported runtime object semantics"
                        )
                    eq = _encode_py_eq(left, right, pctx)
                    comparisons.append(eq if isinstance(op, ast.Eq) else _z3_mod.Not(eq))
                elif isinstance(op, (ast.Is, ast.IsNot)):
                    if not (self._is_singleton_expr(left_node, left) or self._is_singleton_expr(right_node, right)):
                        raise _UnsupportedInputDomain("NonSingletonIdentityComparison")
                    ident = left.term == right.term
                    comparisons.append(ident if isinstance(op, ast.Is) else _z3_mod.Not(ident))
                elif isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
                    if left.kind == right.kind == "STR":
                        a, b = pv.str_val(left.term), pv.str_val(right.term)
                    elif left.kind in ("INT", "BOOL") and right.kind in ("INT", "BOOL"):
                        a, b = self._numeric(left, "ordering"), self._numeric(right, "ordering")
                    else:
                        raise _UnsupportedInputDomain("mixed or dynamic ordering is unsupported")
                    if isinstance(op, ast.Lt):
                        comparisons.append(a < b)
                    elif isinstance(op, ast.LtE):
                        comparisons.append(a <= b)
                    elif isinstance(op, ast.Gt):
                        comparisons.append(a > b)
                    else:
                        comparisons.append(a >= b)
                else:
                    raise _UnsupportedSymbolicExpression(f"unsupported comparison {type(op).__name__}")
                left_node, left = right_node, right
            return pctx.boolean(_z3_mod.And(*comparisons) if len(comparisons) > 1 else comparisons[0])
        if isinstance(node, ast.BoolOp):
            values = [self.eval_expr(v, env) for v in node.values]
            if not values:
                raise _UnsupportedSymbolicExpression("empty boolean operation")
            result = values[-1]
            for value in reversed(values[:-1]):
                cond = self._truth(value, "boolean operation")
                result = _PyVal(
                    _z3_mod.If(cond, result.term, value.term) if isinstance(node.op, ast.And)
                    else _z3_mod.If(cond, value.term, result.term),
                    result.kind if result.kind == value.kind else None,
                )
            return result
        if isinstance(node, ast.IfExp):
            cond = self._truth(self.eval_expr(node.test, env), "conditional expression")
            yes, no = self.eval_expr(node.body, env), self.eval_expr(node.orelse, env)
            return _PyVal(_z3_mod.If(cond, yes.term, no.term), yes.kind if yes.kind == no.kind else None)
        raise _UnsupportedSymbolicExpression(f"unsupported expression {type(node).__name__}")

    def execute(self) -> _PyVal:
        env = dict(self.initial_env)
        active = _z3_mod.BoolVal(True, ctx=self.pctx.ctx)
        active_after = self._exec_block(self.fn.body, env, active)
        # Python implicitly returns None when execution reaches the end.
        if not self.pctx.is_false(active_after):
            self.return_term = _z3_mod.If(active_after, self.pctx.none().term, self.return_term)
        return _PyVal(self.return_term, None)

    def _exec_block(self, statements: list[ast.stmt], env: dict[str, _PyVal], active: Any) -> Any:
        pctx = self.pctx
        for stmt in statements:
            if pctx.is_false(active):
                break
            if isinstance(stmt, ast.Return):
                value = self.pctx.none() if stmt.value is None else self.eval_expr(stmt.value, env)
                self.return_term = _z3_mod.If(active, value.term, self.return_term)
                self.returned = _z3_mod.Or(self.returned, active)
                active = _z3_mod.BoolVal(False, ctx=pctx.ctx)
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                value_node = stmt.value
                if value_node is None:
                    raise _UnsupportedSymbolicExpression("annotation-only assignment")
                value = self.eval_expr(value_node, env)
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                if any(not isinstance(t, ast.Name) for t in targets):
                    raise _UnsupportedSymbolicExpression("non-local/non-name assignment")
                for target in targets:
                    assert isinstance(target, ast.Name)
                    old = env.get(target.id)
                    if old is None:
                        # A value created only under a branch may be unbound on
                        # other paths. Preserve that uncertainty in its kind;
                        # subsequent arithmetic on it will abstain.
                        env[target.id] = _PyVal(_z3_mod.If(active, value.term, self.pctx.none().term), value.kind if pctx.is_true(active) else None)
                    else:
                        env[target.id] = _PyVal(_z3_mod.If(active, value.term, old.term), value.kind if value.kind == old.kind else None)
            elif isinstance(stmt, ast.AugAssign):
                if not isinstance(stmt.target, ast.Name) or stmt.target.id not in env:
                    raise _UnsupportedSymbolicExpression("unsupported augmented assignment target")
                left = env[stmt.target.id]
                right = self.eval_expr(stmt.value, env)
                if left.kind not in ("INT", "BOOL") or right.kind not in ("INT", "BOOL"):
                    raise _UnsupportedInputDomain(
                        "augmented arithmetic requires supported INT/BOOL operands"
                    )
                a, b = self._numeric(left, "augmented arithmetic"), self._numeric(right, "augmented arithmetic")
                if isinstance(stmt.op, ast.Add):
                    value = pctx.integer(a + b)
                elif isinstance(stmt.op, ast.Sub):
                    value = pctx.integer(a - b)
                elif isinstance(stmt.op, ast.Mult):
                    value = pctx.integer(a * b)
                else:
                    raise _UnsupportedSymbolicExpression("unsupported augmented operator")
                env[stmt.target.id] = _PyVal(_z3_mod.If(active, value.term, left.term), value.kind)
            elif isinstance(stmt, ast.If):
                condition = self._truth(self.eval_expr(stmt.test, env), "if statement")
                before = dict(env)
                then_env, else_env = dict(env), dict(env)
                then_active = self._exec_block(stmt.body, then_env, _z3_mod.And(active, condition))
                else_active = self._exec_block(stmt.orelse, else_env, _z3_mod.And(active, _z3_mod.Not(condition))) if stmt.orelse else _z3_mod.And(active, _z3_mod.Not(condition))
                if pctx.is_false(then_active):
                    env.clear()
                    env.update(else_env)
                elif pctx.is_false(else_active):
                    env.clear()
                    env.update(then_env)
                else:
                    merged: dict[str, _PyVal] = {}
                    for name in set(then_env) | set(else_env) | set(before):
                        yes = then_env.get(name)
                        no = else_env.get(name)
                        if yes is None or no is None:
                            raise _UnsupportedSymbolicExpression(f"conditional assignment to possibly-unbound local {name}")
                        merged[name] = _PyVal(_z3_mod.If(condition, yes.term, no.term), yes.kind if yes.kind == no.kind else None)
                    env.clear()
                    env.update(merged)
                active = _z3_mod.Or(then_active, else_active)
            elif isinstance(stmt, ast.Pass):
                continue
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                # Function docstring: no run-time effect for equivalence here.
                continue
            else:
                raise _UnsupportedSymbolicExpression(f"unsupported statement {type(stmt).__name__}")
        return active


class Z3SymbolicProver:
    """
    Layer 5 Stage 2 Z3 SMT Counterexample Prover (`verifyci_v2/symbolic/z3_prover.py`).
    Compiles `FunctionUSSA` basic blocks, PhiNodes, and CFG guards into Z3 SMT
    path formulas to prove or refute functional equivalence and extract concrete
    CounterexampleWitness assignments without `exec()`.
    """

    @staticmethod
    def supported_function_subset() -> str:
        return _supported_fragment_doc()

    def __init__(self, timeout_ms: int = 2000) -> None:
        self.timeout_ms = timeout_ms
        self.egglog = EgglogEquivalenceEngine()

    def _solve_distinct_pair_witness(
        self,
        z3_a: Any,
        z3_b: Any,
        var_a_name: str,
        var_b_name: str,
        z3_vars: dict[str, Any],
        path_guards_z3: tuple[Any, ...] = (),
        all_params: tuple[str, ...] = (),
    ) -> tuple[SMTStatus, dict[str, int | str]]:
        if _z3_mod is None:
            return "SOLVER_UNAVAILABLE", {}
        if z3_a is None or z3_b is None:
            return "UNKNOWN", {}
        try:
            ctx = getattr(z3_a, "ctx", None)
            if z3_a.sort() != _z3_make(_z3_mod.IntSort, ctx=ctx) or z3_b.sort() != _z3_make(_z3_mod.IntSort, ctx=ctx):
                return "UNKNOWN", {}
            solver = _z3_make(_z3_mod.Solver, ctx=ctx)
            solver.set("timeout", self.timeout_ms)
            for guard in path_guards_z3:
                if guard is not None:
                    solver.add(guard)
            solver.add(z3_a != z3_b)
            status = solver.check()
            if status == _z3_mod.unsat:
                return "UNSAT", {}
            if status != _z3_mod.sat:
                return "UNKNOWN", {}
            assignments = _extract_model_assignments(solver.model(), z3_vars, all_params)
            if all_params and len(assignments) != len(all_params):
                return "UNKNOWN", {}
            # The solver has established distinct operands. The model assignments
            # are concrete when parameters exist; zero-parameter witnesses are valid.
            return "SAT", assignments
        except Exception:
            return "UNKNOWN", {}

    def prove_function_diff(
        self,
        *,
        file_path: str,
        base_source: str,
        head_source: str,
        func_base: FunctionUSSA,
        func_head: FunctionUSSA,
        base_fn_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None,
        head_fn_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None,
    ) -> tuple[VerificationFinding, ...]:
        """Run structural defect checks without letting heuristics establish safety.

        Production callers pass AST nodes from CompiledFilePair. The compatibility
        path compiles a complete pair through the canonical compiler; this method
        never directly reparses source text.
        """
        start_ns = time.perf_counter_ns()
        if base_fn_node is None or head_fn_node is None:
            try:
                from verifyci_v2.pipeline import DiffFileEntry
                from verifyci_v2.ingestion.compile_context import compile_file_pair
                compiled = compile_file_pair(
                    DiffFileEntry.from_sources(file_path, base_source, head_source),
                    repo_id=func_base.repo_id,
                )
                if compiled.syntax_error is not None or compiled.base_ast is None or compiled.head_ast is None:
                    return ()
                base_fn_node = compiled.base_ast.functions_by_qname.get(func_base.qualified_name)
                head_fn_node = compiled.head_ast.functions_by_qname.get(func_head.qualified_name)
            except Exception:
                return ()
        if base_fn_node is None or head_fn_node is None:
            return ()

        # A malformed CFG cannot support structural witness extraction. Keep the
        # abstention visible; the caller still runs the independent typed prover,
        # which may discover a decisive counterexample and take precedence.
        if _z3_mod is None:
            return ()
        proof_ctx = _z3_mod.Context()
        shared_z3_vars: dict[str, Any] = {
            parameter: _z3_mod.Int(parameter, ctx=proof_ctx) for parameter in func_head.parameters
        }
        ext_base = _USSASymbolicExtractor(func_base, shared_z3_vars, ctx=proof_ctx)
        ext_head = _USSASymbolicExtractor(func_head, shared_z3_vars, ctx=proof_ctx)
        cfg_problem = ext_base.unsupported_construct or ext_head.unsupported_construct
        if cfg_problem is not None:
            elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            return (VerificationFinding(
                finding_id=content_digest_hex(f"UNSUPPORTED:{file_path}:{func_head.qualified_name}:{cfg_problem}", domain="verifyci.v2.finding")[:16],
                rule_id="VC2-Z3-UNSUPPORTED-AST", severity="MEDIUM", verdict="INCONCLUSIVE",
                file_path=file_path, start_line=func_head.start_line, end_line=func_head.end_line,
                message=f"Function '{func_head.qualified_name}' has unsupported CFG structure '{cfg_problem}'; proof abstains.",
                witness=CounterexampleWitness(
                    checker_id="VC2-Z3-UNSUPPORTED-AST", smt_status="UNKNOWN", input_assignments={},
                    base_return_state="", head_return_state="", proof_time_ms=round(elapsed, 3),
                ),
            ),)

        findings: list[VerificationFinding] = []

        def guard_key(record: Any) -> tuple[str, ...]:
            values = []
            for guard in record.path_guards_z3:
                try:
                    values.append(str(_z3_mod.simplify(guard)))
                except Exception:
                    values.append(str(guard))
            return tuple(values)

        # Pair calls only where callee counts and path-guard identities are
        # unambiguous. Positional zip alignment is deliberately prohibited.
        base_by_callee: dict[str, list[Any]] = {}
        head_by_callee: dict[str, list[Any]] = {}
        for call in ext_base.calls:
            base_by_callee.setdefault(call.callee, []).append(call)
        for call in ext_head.calls:
            head_by_callee.setdefault(call.callee, []).append(call)
        aligned_calls: list[tuple[Any, Any]] = []
        for callee in sorted(set(base_by_callee) | set(head_by_callee)):
            base_calls = sorted(base_by_callee.get(callee, []), key=lambda c: c.source_line)
            head_calls = sorted(head_by_callee.get(callee, []), key=lambda c: c.source_line)
            if len(base_calls) != len(head_calls) or not base_calls:
                continue
            if len(base_calls) == 1:
                aligned_calls.append((base_calls[0], head_calls[0]))
                continue
            base_keys = [guard_key(c) for c in base_calls]
            head_keys = [guard_key(c) for c in head_calls]
            if len(set(base_keys)) != len(base_keys) or len(set(head_keys)) != len(head_keys):
                continue
            if set(base_keys) != set(head_keys):
                continue
            hmap = {guard_key(c): c for c in head_calls}
            aligned_calls.extend((b, hmap[guard_key(b)]) for b in base_calls)

        for call_b, call_h in aligned_calls:
            if not (
                len(call_b.norm_args) >= 2
                and len(call_b.norm_args) == len(call_h.norm_args)
                and call_b.norm_args != call_h.norm_args
                and sorted(call_b.norm_args) == sorted(call_h.norm_args)
            ):
                continue
            diff_indices = [i for i, (ab, ah) in enumerate(zip(call_b.norm_args, call_h.norm_args)) if ab != ah]
            if len(diff_indices) < 2:
                continue
            ia, ib = diff_indices[:2]
            if ia >= len(call_b.z3_args) or ib >= len(call_b.z3_args):
                continue
            za, zb = call_b.z3_args[ia], call_b.z3_args[ib]
            # Unsupported arguments or ambiguous call binding are left for the
            # whole-function prover, not replaced with fresh unconstrained symbols.
            if za is None or zb is None:
                continue
            status, assignments = self._solve_distinct_pair_witness(
                za, zb, call_b.norm_args[ia], call_b.norm_args[ib], shared_z3_vars,
                path_guards_z3=(*call_b.path_guards_z3, *call_h.path_guards_z3),
                all_params=func_head.parameters,
            )
            if status != "SAT":
                continue
            elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            witness = CounterexampleWitness(
                checker_id="VC2-CAP004-CALL-SWAP", smt_status="SAT", input_assignments=assignments,
                base_return_state=f"{call_b.callee}({', '.join(call_b.norm_args)})",
                head_return_state=f"{call_h.callee}({', '.join(call_h.norm_args)})",
                proof_time_ms=round(elapsed, 3),
            )
            findings.append(VerificationFinding(
                finding_id=content_digest_hex(f"CALL_SWAP:{file_path}:{call_h.source_line}:{call_h.callee}", domain="verifyci.v2.finding")[:16],
                rule_id="VC2-CAP004-CALL-SWAP", severity="CRITICAL", verdict="FAIL",
                file_path=file_path, start_line=call_h.source_line, end_line=call_h.source_line,
                message=f"Z3 found distinct concrete arguments for reordered call '{call_h.callee}'.", witness=witness,
            ))

        # Return-swap detection is only definitive for terms the legacy structural
        # encoding represents exactly as Int. Typed return semantics are handled
        # by prove_equivalence for all supported scalar constructors.
        if (
            len(ext_base.returns) >= 2 and len(ext_base.returns) == len(ext_head.returns)
            and [r.norm_expr for r in ext_base.returns] != [r.norm_expr for r in ext_head.returns]
            and sorted(r.norm_expr for r in ext_base.returns) == sorted(r.norm_expr for r in ext_head.returns)
        ):
            rb, rh = ext_base.returns[0], ext_head.returns[0]
            try:
                int_sort = _z3_mod.IntSort(ctx=proof_ctx)
                if rb.z3_expr is not None and rh.z3_expr is not None and rb.z3_expr.sort() == int_sort and rh.z3_expr.sort() == int_sort:
                    solver = _z3_mod.Solver(ctx=proof_ctx)
                    solver.set("timeout", self.timeout_ms)
                    for guard in (*rb.path_guards_z3, *rh.path_guards_z3):
                        if guard is not None:
                            solver.add(guard)
                    solver.add(rb.z3_expr != rh.z3_expr)
                    if solver.check() == _z3_mod.sat:
                        assignments = _extract_model_assignments(solver.model(), shared_z3_vars, func_head.parameters)
                        if not func_head.parameters or len(assignments) == len(func_head.parameters):
                            elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                            findings.append(VerificationFinding(
                                finding_id=content_digest_hex(f"RET_SWAP:{file_path}:{rh.source_line}", domain="verifyci.v2.finding")[:16],
                                rule_id="VC2-CAP004-RETURN-SWAP", severity="HIGH", verdict="FAIL",
                                file_path=file_path, start_line=rh.source_line, end_line=func_head.end_line,
                                message="Z3 found a concrete counterexample for reordered return values.",
                                witness=CounterexampleWitness(
                                    checker_id="VC2-CAP004-RETURN-SWAP", smt_status="SAT", input_assignments=assignments,
                                    base_return_state=rb.norm_expr, head_return_state=rh.norm_expr,
                                    proof_time_ms=round(elapsed, 3),
                                ),
                            ))
            except Exception:
                pass

        # Guard-inversion check: pair only a unique branch-shape signature.
        def branch_shape(g: Any) -> tuple[str, str, tuple[str, ...]]:
            return (g.then_summary, g.else_summary, guard_key(g))
        base_guards: dict[tuple[str, str, tuple[str, ...]], list[Any]] = {}
        head_guards: dict[tuple[str, str, tuple[str, ...]], list[Any]] = {}
        for g in ext_base.guards:
            base_guards.setdefault(branch_shape(g), []).append(g)
        for g in ext_head.guards:
            head_guards.setdefault(branch_shape(g), []).append(g)
        for shape in sorted(set(base_guards) & set(head_guards), key=str):
            if len(base_guards[shape]) != 1 or len(head_guards[shape]) != 1:
                continue
            gb, gh = base_guards[shape][0], head_guards[shape][0]
            if gb.norm_cond == gh.norm_cond or gb.then_summary == gb.else_summary:
                continue
            if gb.z3_cond is None or gh.z3_cond is None:
                continue
            try:
                solver = _z3_mod.Solver(ctx=proof_ctx)
                solver.set("timeout", self.timeout_ms)
                for guard in (*gb.path_guards_z3, *gh.path_guards_z3):
                    if guard is not None:
                        solver.add(guard)
                solver.add(gb.z3_cond != gh.z3_cond)
                if solver.check() != _z3_mod.sat:
                    continue
                assignments = _extract_model_assignments(solver.model(), shared_z3_vars, func_head.parameters)
                if func_head.parameters and len(assignments) != len(func_head.parameters):
                    continue
                elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                findings.append(VerificationFinding(
                    finding_id=content_digest_hex(f"GUARD_INV:{file_path}:{gh.source_line}", domain="verifyci.v2.finding")[:16],
                    rule_id="VC2-CAP002-GUARD-INVERSION", severity="CRITICAL", verdict="FAIL",
                    file_path=file_path, start_line=gh.source_line, end_line=gh.source_line,
                    message=f"Z3 found a concrete path where guard '{gb.norm_cond}' differs from '{gh.norm_cond}'.",
                    witness=CounterexampleWitness(
                        checker_id="VC2-CAP002-GUARD-INVERSION", smt_status="SAT", input_assignments=assignments,
                        base_return_state=f"if {gb.norm_cond} -> {gb.then_summary}",
                        head_return_state=f"if {gh.norm_cond} -> {gh.then_summary}", proof_time_ms=round(elapsed, 3),
                    ),
                ))
            except Exception:
                continue

        # A syntactic parameter shadow is not itself a proven defect. Emit the
        # capability-specific rule only when the full supported proof produces
        # a validated divergent witness.
        base_shadow = {item.param_name for item in ext_base.shadowed_params}
        for shadow in ext_head.shadowed_params:
            if shadow.param_name in base_shadow:
                continue
            proof = self.prove_equivalence(
                func_base=func_base, func_cand=func_head,
                base_fn_node=base_fn_node, cand_fn_node=head_fn_node,
            )
            if proof.outcome != "PROVEN_DIVERGENT_SAT" or proof.witness is None:
                continue
            findings.append(VerificationFinding(
                finding_id=content_digest_hex(f"SHADOW:{file_path}:{shadow.source_line}:{shadow.param_name}", domain="verifyci.v2.finding")[:16],
                rule_id="VC2-CAP002-SHADOW-ASSIGN", severity="HIGH", verdict="FAIL",
                file_path=file_path, start_line=shadow.source_line, end_line=shadow.source_line,
                message=f"Parameter '{shadow.param_name}' is shadowed and Z3 validated a concrete semantic divergence.",
                witness=proof.witness,
            ))
            break

        if func_base.h_body != func_head.h_body and not findings:
            found_construct = _detect_unsupported_ast_construct(base_fn_node, head_fn_node, ext_base, ext_head)
            if found_construct or ext_base.unsupported_construct or ext_head.unsupported_construct:
                construct = found_construct or ext_base.unsupported_construct or ext_head.unsupported_construct or "Unsupported"
                elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                findings.append(VerificationFinding(
                    finding_id=content_digest_hex(f"UNSUPPORTED:{file_path}:{func_head.qualified_name}:{construct}", domain="verifyci.v2.finding")[:16],
                    rule_id="VC2-Z3-UNSUPPORTED-AST", severity="MEDIUM", verdict="INCONCLUSIVE",
                    file_path=file_path, start_line=func_head.start_line, end_line=func_head.end_line,
                    message=f"Function '{func_head.qualified_name}' uses unsupported symbolic construct '{construct}'.",
                    witness=CounterexampleWitness(
                        checker_id="VC2-Z3-UNSUPPORTED-AST", smt_status="UNKNOWN", input_assignments={},
                        base_return_state="", head_return_state="", proof_time_ms=round(elapsed, 3),
                    ),
                ))
        return tuple(findings)

    def prove_equivalence(
        self,
        base_source: str | None = None,
        cand_source: str | None = None,
        func_base: FunctionUSSA | None = None,
        func_cand: FunctionUSSA | None = None,
        *,
        base_fn_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None,
        cand_fn_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None,
    ) -> EquivalenceProofResult:
        """Prove equivalence in a per-proof typed PyVal context.

        Pipeline callers supply retained AST nodes. The source-only compatibility
        path uses the canonical compiler once per revision; this method itself
        never calls ast.parse and never aliases None/string values into integers.
        """
        if _z3_mod is None:
            return EquivalenceProofResult(outcome="INCONCLUSIVE_SOLVER_UNAVAILABLE", reason="z3-solver is not available")
        if func_base is None or func_cand is None:
            return EquivalenceProofResult(outcome="INCONCLUSIVE_UNSUPPORTED", reason="FunctionUSSA inputs are required")

        if base_fn_node is None or cand_fn_node is None:
            if base_source is None or cand_source is None:
                return EquivalenceProofResult(outcome="INCONCLUSIVE_UNSUPPORTED", reason="Pre-parsed function nodes or complete source buffers are required")
            try:
                # Compatibility path for historical direct callers. The actual
                # pipeline always passes its already-retained AST nodes.
                from verifyci_v2.pipeline import DiffFileEntry
                from verifyci_v2.ingestion.compile_context import compile_file_pair
                entry = DiffFileEntry.from_sources(func_base.file_path, base_source, cand_source)
                compiled = compile_file_pair(entry, repo_id=func_base.repo_id)
                if compiled.syntax_error is not None or compiled.base_ast is None or compiled.head_ast is None:
                    return EquivalenceProofResult(outcome="INCONCLUSIVE_UNSUPPORTED", reason="Source pair could not be compiled")
                base_fn_node = compiled.base_ast.functions_by_qname.get(func_base.qualified_name)
                cand_fn_node = compiled.head_ast.functions_by_qname.get(func_cand.qualified_name)
            except Exception as exc:
                return EquivalenceProofResult(outcome="INCONCLUSIVE_UNSUPPORTED", reason=f"Compilation failed: {type(exc).__name__}: {exc}")
        if base_fn_node is None or cand_fn_node is None:
            return EquivalenceProofResult(outcome="INCONCLUSIVE_UNSUPPORTED", reason="Function AST node was not found by qualified name")
        if func_base.parameters != func_cand.parameters:
            return EquivalenceProofResult(outcome="INCONCLUSIVE_UNSUPPORTED", reason="Function parameter names/order changed")
        base_ret = ast.dump(base_fn_node.returns, include_attributes=False) if base_fn_node.returns is not None else None
        cand_ret = ast.dump(cand_fn_node.returns, include_attributes=False) if cand_fn_node.returns is not None else None
        base_decs = [ast.dump(d, include_attributes=False) for d in base_fn_node.decorator_list]
        cand_decs = [ast.dump(d, include_attributes=False) for d in cand_fn_node.decorator_list]
        if (
            ast.dump(base_fn_node.args, include_attributes=False) != ast.dump(cand_fn_node.args, include_attributes=False)
            or base_ret != cand_ret
            or base_decs != cand_decs
            or isinstance(base_fn_node, ast.AsyncFunctionDef) != isinstance(cand_fn_node, ast.AsyncFunctionDef)
        ):
            return EquivalenceProofResult(outcome="INCONCLUSIVE_UNSUPPORTED", reason="Function defaults, parameter kinds/annotations, decorators, or async semantics changed")

        # The typed evaluator is intentionally a supported-subset prover, not a
        # general Python interpreter. Unsupported semantics abstain.
        blocked_types = (*_UNSUPPORTED_AST_TYPES, ast.With, ast.AsyncWith, ast.Try, ast.Raise, ast.Global, ast.Nonlocal)
        for fn_node in (base_fn_node, cand_fn_node):
            if any(isinstance(node, blocked_types) for node in ast.walk(fn_node)):
                return EquivalenceProofResult(outcome="INCONCLUSIVE_UNSUPPORTED", reason="Unsupported AST construct")

        start_ns = time.perf_counter_ns()
        try:
            pctx = _Z3ProofContext(self.timeout_ms)
            base_eval = _ASTPyValEvaluator(pctx, base_fn_node, func_base.parameters)
            cand_eval = _ASTPyValEvaluator(pctx, cand_fn_node, func_cand.parameters)
            # Input symbols must describe the same modeled values on both sides.
            for name in func_base.parameters:
                if base_eval.initial_env[name].kind != cand_eval.initial_env[name].kind:
                    return EquivalenceProofResult(outcome="INCONCLUSIVE_UNSUPPORTED", reason=f"Parameter type model changed for {name}")
            base_return = base_eval.execute()
            cand_return = cand_eval.execute()
            solver = pctx.solver()
            for name, raw in base_eval.raw_parameters.items():
                k = base_eval.initial_env[name].kind
                if k == "INT":
                    # The declared int-domain assumption includes bool, which is
                    # a Python int subtype and supports the same scalar arithmetic.
                    solver.add(_z3_mod.Or(pctx.pyval.is_mk_int(raw), pctx.pyval.is_mk_bool(raw)))
                elif k == "BOOL":
                    solver.add(pctx.pyval.is_mk_bool(raw))
                elif k == "STR":
                    solver.add(pctx.pyval.is_mk_str(raw))
            solver.add(base_return.term != cand_return.term)
            check = solver.check()
            elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            if check == _z3_mod.unsat:
                return EquivalenceProofResult(outcome="PROVEN_EQUIVALENT_UNSAT", reason=f"Negated return-equivalence obligation is UNSAT ({elapsed:.3f} ms)")
            if check == _z3_mod.unknown:
                return EquivalenceProofResult(outcome="INCONCLUSIVE_UNKNOWN", reason=f"Z3 returned unknown: {solver.reason_unknown()}")

            model = solver.model()
            assignments: dict[str, str | int | float | bool | None] = {}
            for name, raw in base_eval.raw_parameters.items():
                val = model.eval(raw, model_completion=True)
                pyval = pctx.pyval
                if pctx.is_true(pyval.is_mk_none(val)):
                    assignments[name] = None
                elif pctx.is_true(pyval.is_mk_bool(val)):
                    bool_value = model.eval(pyval.bool_val(val), model_completion=True)
                    assignments[name] = _z3_mod.is_true(bool_value)
                elif pctx.is_true(pyval.is_mk_int(val)):
                    int_value = model.eval(pyval.int_val(val), model_completion=True)
                    if not hasattr(int_value, "as_long"):
                        return EquivalenceProofResult(
                            outcome="INCONCLUSIVE_UNKNOWN",
                            reason=f"SAT model integer for parameter {name!r} could not be materialized",
                        )
                    assignments[name] = int_value.as_long()
                elif pctx.is_true(pyval.is_mk_str(val)):
                    str_value = model.eval(pyval.str_val(val), model_completion=True)
                    try:
                        assignments[name] = str_value.as_string()
                    except Exception:
                        return EquivalenceProofResult(
                            outcome="INCONCLUSIVE_UNKNOWN",
                            reason=f"SAT model string for parameter {name!r} could not be materialized",
                        )
                else:
                    return EquivalenceProofResult(
                        outcome="INCONCLUSIVE_UNKNOWN",
                        reason=f"SAT model for parameter {name!r} used an unsupported PyVal constructor",
                    )
            if set(assignments) != set(base_eval.raw_parameters):
                return EquivalenceProofResult(
                    outcome="INCONCLUSIVE_UNKNOWN",
                    reason="SAT model could not materialize every required parameter binding",
                )
            base_state = str(model.eval(base_return.term, model_completion=True))
            cand_state = str(model.eval(cand_return.term, model_completion=True))
            witness = CounterexampleWitness(
                checker_id="VC2-Z3-SEMANTIC-DIVERGENCE", smt_status="SAT",
                input_assignments=assignments, base_return_state=base_state,
                head_return_state=cand_state, proof_time_ms=round(elapsed, 3),
            )
            return EquivalenceProofResult(outcome="PROVEN_DIVERGENT_SAT", witness=witness, reason="A concrete model distinguishes the return values")
        except _UnsupportedInputDomain as exc:
            # Do not run the integer-only U-SSA fallback for an input-domain
            # mismatch: it could prove a result after silently coercing arbitrary
            # PyVal inputs to integers.
            return EquivalenceProofResult(
                outcome="INCONCLUSIVE_UNSUPPORTED",
                reason=str(exc) or "Unsupported input domain",
            )
        except (_UnsupportedSymbolicExpression, ValueError, TypeError, AttributeError):
            pass
        except Exception as exc:
            return EquivalenceProofResult(outcome="INCONCLUSIVE_UNKNOWN", reason=f"Solver/translation error: {type(exc).__name__}: {exc}")

        # Fallback to U-SSA symbolic equivalence check (for calls, complex control flow, etc.)
        try:
            # Keep the fallback isolated from Z3's process-global default context
            # as well. Every term and solver in this fallback shares this local ctx.
            fallback_ctx = _z3_mod.Context()
            shared_z3_vars = {p: _z3_mod.Int(p, ctx=fallback_ctx) for p in func_base.parameters}
            ext_b = _USSASymbolicExtractor(func_base, shared_z3_vars, ctx=fallback_ctx)
            ext_c = _USSASymbolicExtractor(func_cand, shared_z3_vars, ctx=fallback_ctx)
            if not ext_b.unsupported_construct and not ext_c.unsupported_construct:
                if len(ext_b.calls) == len(ext_c.calls) and len(ext_b.returns) == len(ext_c.returns):
                    s = _z3_mod.Solver(ctx=fallback_ctx)
                    s.set("timeout", self.timeout_ms)
                    calls_ok = True
                    for call_b, call_c in zip(ext_b.calls, ext_c.calls):
                        if call_b.callee != call_c.callee or len(call_b.z3_args) != len(call_c.z3_args):
                            calls_ok = False
                            break
                        for arg_b, arg_c in zip(call_b.z3_args, call_c.z3_args):
                            zb_arg = _to_z3_int(arg_b)
                            zc_arg = _to_z3_int(arg_c)
                            if zb_arg is None or zc_arg is None:
                                if call_b.norm_args != call_c.norm_args:
                                    calls_ok = False
                                    break
                                continue
                            s.reset()
                            s.set("timeout", self.timeout_ms)
                            for g in (*call_b.path_guards_z3, *call_c.path_guards_z3):
                                if g is not None:
                                    s.add(g)
                            s.add(zb_arg != zc_arg)
                            st = s.check()
                            if st == _z3_mod.sat:
                                elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                                assignments = _extract_model_assignments(s.model(), shared_z3_vars, func_cand.parameters)
                                if set(assignments) != set(func_cand.parameters):
                                    return EquivalenceProofResult(
                                        outcome="INCONCLUSIVE_UNKNOWN",
                                        reason="SAT call-divergence model could not materialize every parameter",
                                    )
                                witness = CounterexampleWitness(
                                    checker_id="VC2-Z3-SEMANTIC-DIVERGENCE", smt_status="SAT",
                                    input_assignments=assignments, base_return_state=call_b.callee,
                                    head_return_state=call_c.callee, proof_time_ms=round(elapsed, 3),
                                )
                                return EquivalenceProofResult(outcome="PROVEN_DIVERGENT_SAT", witness=witness, reason="Call argument divergence")
                            if st == _z3_mod.unknown:
                                calls_ok = False
                                break
                    if calls_ok and len(ext_b.guards) == len(ext_c.guards):
                        guards_ok = True
                        for guard_b, guard_c in zip(ext_b.guards, ext_c.guards):
                            if guard_b.z3_cond is None or guard_c.z3_cond is None:
                                guards_ok = False
                                break
                            s.reset()
                            s.set("timeout", self.timeout_ms)
                            for g in (*guard_b.path_guards_z3, *guard_c.path_guards_z3):
                                if g is not None:
                                    s.add(g)
                            s.add(guard_b.z3_cond != guard_c.z3_cond)
                            st = s.check()
                            if st == _z3_mod.sat:
                                elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                                assignments = _extract_model_assignments(s.model(), shared_z3_vars, func_cand.parameters)
                                if set(assignments) != set(func_cand.parameters):
                                    return EquivalenceProofResult(
                                        outcome="INCONCLUSIVE_UNKNOWN",
                                        reason="SAT guard-divergence model could not materialize every parameter",
                                    )
                                witness = CounterexampleWitness(
                                    checker_id="VC2-Z3-SEMANTIC-DIVERGENCE", smt_status="SAT",
                                    input_assignments=assignments, base_return_state=guard_b.norm_cond,
                                    head_return_state=guard_c.norm_cond, proof_time_ms=round(elapsed, 3),
                                )
                                return EquivalenceProofResult(outcome="PROVEN_DIVERGENT_SAT", witness=witness, reason="Branch guard divergence")
                            if st == _z3_mod.unknown:
                                guards_ok = False
                                break
                        if guards_ok:
                            if not ext_b.returns and not ext_c.returns:
                                if ext_b.calls or ext_b.guards:
                                    return EquivalenceProofResult(outcome="PROVEN_EQUIVALENT_UNSAT", reason="Aligned calls and guards with void return")
                            else:
                                ite_b = ext_b.build_return_ite()
                                ite_c = ext_c.build_return_ite()
                                if ite_b is not None and ite_c is not None:
                                    s.reset()
                                    s.set("timeout", self.timeout_ms)
                                    s.add(ite_b != ite_c)
                                    st = s.check()
                                    if st == _z3_mod.unsat:
                                        elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                                        return EquivalenceProofResult(outcome="PROVEN_EQUIVALENT_UNSAT", reason=f"U-SSA ITE equivalence proved ({elapsed:.3f} ms)")
                                    if st == _z3_mod.sat:
                                        elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                                        assignments = _extract_model_assignments(s.model(), shared_z3_vars, func_cand.parameters)
                                        if set(assignments) != set(func_cand.parameters):
                                            return EquivalenceProofResult(
                                                outcome="INCONCLUSIVE_UNKNOWN",
                                                reason="SAT return-divergence model could not materialize every parameter",
                                            )
                                        witness = CounterexampleWitness(
                                            checker_id="VC2-Z3-SEMANTIC-DIVERGENCE", smt_status="SAT",
                                            input_assignments=assignments, base_return_state="",
                                            head_return_state="", proof_time_ms=round(elapsed, 3),
                                        )
                                        return EquivalenceProofResult(outcome="PROVEN_DIVERGENT_SAT", witness=witness, reason="U-SSA ITE divergence")
        except Exception:
            pass
        return EquivalenceProofResult(outcome="INCONCLUSIVE_UNSUPPORTED", reason="Unsupported symbolic construct")


def _evaluate_concrete_divergence(
    base_src: str,
    head_src: str,
    fn_name: str,
    params: tuple[str, ...],
    witness_inputs: dict[str, Any],
) -> bool:
    """Re-check a proposed repair against concrete witness inputs.

    This compatibility helper compiles its supplied candidate pair through the
    canonical compiler. It does not parse or lower source independently, and
    unsupported witness semantics conservatively retain the divergence.
    """
    if _z3_mod is None:
        return True
    try:
        from verifyci_v2.pipeline import DiffFileEntry
        from verifyci_v2.ingestion.compile_context import compile_file_pair

        compiled = compile_file_pair(
            DiffFileEntry.from_sources("repair.py", base_src, head_src),
            repo_id="default-repo",
        )
        if compiled.syntax_error is not None:
            return True
        funcs_b = {f.qualified_name.split(".")[-1]: f for f in compiled.base_ussa.values()}
        funcs_h = {f.qualified_name.split(".")[-1]: f for f in compiled.head_ussa.values()}
        fb, fh = funcs_b.get(fn_name), funcs_h.get(fn_name)
        if fb is None or fh is None:
            return True

        # The helper is used only as an additional rejection check. Unsupported
        # or context-sensitive execution is not treated as evidence of repair.
        ctx = _z3_mod.Context()
        bound_vars: dict[str, Any] = {}
        for p in params:
            raw_v = witness_inputs.get(p)
            if isinstance(raw_v, bool):
                bound_vars[p] = _z3_mod.IntVal(1 if raw_v else 0, ctx=ctx)
            elif isinstance(raw_v, int):
                bound_vars[p] = _z3_mod.IntVal(raw_v, ctx=ctx)
            else:
                return True

        ext_b = _USSASymbolicExtractor(fb, bound_vars, ctx=ctx)
        ext_h = _USSASymbolicExtractor(fh, bound_vars, ctx=ctx)
        if ext_b.unsupported_construct or ext_h.unsupported_construct:
            return True
        solver = _z3_mod.Solver(ctx=ctx)
        solver.set("timeout", 1000)
        ite_b = ext_b.build_return_ite()
        ite_h = ext_h.build_return_ite()
        if ite_b is None or ite_h is None:
            return True
        solver.add(ite_b != ite_h)
        result = solver.check()
        if result == _z3_mod.sat:
            return True
        if result == _z3_mod.unsat:
            return False
        return True
    except Exception:
        return True
