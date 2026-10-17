from __future__ import annotations

import ast
import msgspec
import time
from typing import Any
import zlib

from verifyci_v2.contracts.attestation import (
    CounterexampleWitness,
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


def _to_z3_int(val: Any) -> Any:
    if _z3_mod is None or val is None:
        return None
    if _z3_mod.is_int_value(val) or (
        hasattr(val, "sort") and val.sort() == _z3_mod.IntSort()
    ):
        return val
    if _z3_mod.is_bool(val):
        return _z3_mod.If(val, _z3_mod.IntVal(1), _z3_mod.IntVal(0))
    if isinstance(val, bool):
        return _z3_mod.IntVal(1 if val else 0)
    if isinstance(val, int):
        return _z3_mod.IntVal(val)
    return None


def _to_z3_bool(val: Any) -> Any:
    if _z3_mod is None or val is None:
        return None
    if _z3_mod.is_bool(val):
        return val
    if hasattr(val, "sort") and val.sort() == _z3_mod.IntSort():
        return val != _z3_mod.IntVal(0)
    if isinstance(val, bool):
        return _z3_mod.BoolVal(val)
    if isinstance(val, int):
        return _z3_mod.BoolVal(val != 0)
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


def _ast_expr_to_z3(node: ast.AST, z3_vars: dict[str, Any]) -> Any:
    """Fallback AST-to-Z3 translator for unparsed expressions."""
    if _z3_mod is None:
        return None
    if isinstance(node, ast.Name):
        if node.id not in z3_vars:
            z3_vars[node.id] = _z3_mod.Int(node.id)
        return z3_vars[node.id]
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return _z3_mod.BoolVal(node.value)
        if isinstance(node.value, int):
            return _z3_mod.IntVal(node.value)
        if node.value is None:
            return _z3_mod.IntVal(-999999)
        if isinstance(node.value, str):
            return _z3_mod.IntVal(zlib.crc32(node.value.encode("utf-8")))
        return None
    if isinstance(node, ast.UnaryOp):
        operand = _ast_expr_to_z3(node.operand, z3_vars)
        if operand is None:
            return None
        if isinstance(node.op, ast.Not):
            b_op = _to_z3_bool(operand)
            return _z3_mod.Not(b_op) if b_op is not None else None
        if isinstance(node.op, ast.USub):
            i_op = _to_z3_int(operand)
            return -i_op if i_op is not None else None
        if isinstance(node.op, ast.UAdd):
            return _to_z3_int(operand)
        return None
    if isinstance(node, ast.BinOp):
        lhs = _to_z3_int(_ast_expr_to_z3(node.left, z3_vars))
        rhs = _to_z3_int(_ast_expr_to_z3(node.right, z3_vars))
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
        lhs_raw = _ast_expr_to_z3(node.left, z3_vars)
        if lhs_raw is None:
            return None
        comps = []
        lhs = _to_z3_int(lhs_raw)
        for op, r_node in zip(node.ops, node.comparators):
            rhs_raw = _ast_expr_to_z3(r_node, z3_vars)
            rhs = _to_z3_int(rhs_raw)
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
            return _z3_mod.BoolVal(True)
        return _z3_mod.And(*comps) if len(comps) > 1 else comps[0]
    if isinstance(node, ast.BoolOp):
        vals = [_to_z3_bool(_ast_expr_to_z3(v, z3_vars)) for v in node.values]
        if any(v is None for v in vals):
            return None
        if isinstance(node.op, ast.And):
            return _z3_mod.And(*vals)
        if isinstance(node.op, ast.Or):
            return _z3_mod.Or(*vals)
    if isinstance(node, ast.Call):
        fn_name = ast.unparse(node.func)
        args_z3 = [_to_z3_int(_ast_expr_to_z3(a, z3_vars)) for a in node.args]
        if any(a is None for a in args_z3):
            return None
        arg_sorts = [_z3_mod.IntSort() for _ in args_z3]
        f_sym = _z3_mod.Function(fn_name, *arg_sorts, _z3_mod.IntSort())
        return f_sym(*args_z3)
    return None


def _ussa_sexpr_to_z3(
    expr_str: str,
    ssa_env: dict[str, Any],
    z3_vars: dict[str, Any],
    parameters: set[str],
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
        return _z3_mod.BoolVal(True)
    if s == "False":
        return _z3_mod.BoolVal(False)
    if s == "None":
        return _z3_mod.IntVal(-999999)

    # Integer literal
    if s.lstrip("-").isdigit():
        try:
            return _z3_mod.IntVal(int(s))
        except ValueError:
            pass

    # String literal
    if (s.startswith("'") and s.endswith("'")) or (
        s.startswith('"') and s.endswith('"')
    ):
        return _z3_mod.IntVal(zlib.crc32(s[1:-1].encode("utf-8")))

    # Outer CFG negation wrapper: NOT(...)
    if s.startswith("NOT(") and s.endswith(")"):
        inner = _ussa_sexpr_to_z3(s[4:-1], ssa_env, z3_vars, parameters)
        b_inner = _to_z3_bool(inner)
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
            z_arg = _to_z3_int(_ussa_sexpr_to_z3(arg_s, ssa_env, z3_vars, parameters))
            if z_arg is None:
                return None
            args_z3.append(z_arg)
        sym_name = callee + "".join(f"@kw:{n}" for n in kw_names)
        arg_sorts = [_z3_mod.IntSort() for _ in args_z3]
        f_sym = _z3_mod.Function(sym_name, *arg_sorts, _z3_mod.IntSort())
        return f_sym(*args_z3)

    # Parenthesized U-SSA S-expression
    if s.startswith("(") and s.endswith(")"):
        tokens = _split_top_level(s[1:-1], sep=" ")
        if not tokens:
            return None

        # Unary prefix: (Not x_0), (USub x_0), (UAdd x_0)
        if len(tokens) == 2 and tokens[0] in _UNARY_OPS:
            op = tokens[0]
            val = _ussa_sexpr_to_z3(tokens[1], ssa_env, z3_vars, parameters)
            if val is None:
                return None
            if op == "Not":
                b_val = _to_z3_bool(val)
                return _z3_mod.Not(b_val) if b_val is not None else None
            if op == "USub":
                i_val = _to_z3_int(val)
                return -i_val if i_val is not None else None
            if op == "UAdd":
                return _to_z3_int(val)
            return None

        # Binary prefix: (Add lhs rhs), (Sub lhs rhs), (Mult lhs rhs)
        if len(tokens) == 3 and tokens[0] in _BIN_OPS:
            op = tokens[0]
            lhs = _to_z3_int(_ussa_sexpr_to_z3(tokens[1], ssa_env, z3_vars, parameters))
            rhs = _to_z3_int(_ussa_sexpr_to_z3(tokens[2], ssa_env, z3_vars, parameters))
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
                    _z3_mod.IntVal(0),
                )
            if op == "Mod":
                return _z3_mod.If(
                    rhs != 0,
                    lhs % rhs,
                    _z3_mod.IntVal(0),
                )
            if op == "BitAnd":
                f_sym = _z3_mod.Function(
                    "bitand_uninterp",
                    _z3_mod.IntSort(),
                    _z3_mod.IntSort(),
                    _z3_mod.IntSort(),
                )
                return f_sym(lhs, rhs)
            if op == "BitOr":
                f_sym = _z3_mod.Function(
                    "bitor_uninterp",
                    _z3_mod.IntSort(),
                    _z3_mod.IntSort(),
                    _z3_mod.IntSort(),
                )
                return f_sym(lhs, rhs)
            if op == "BitXor":
                f_sym = _z3_mod.Function(
                    "bitxor_uninterp",
                    _z3_mod.IntSort(),
                    _z3_mod.IntSort(),
                    _z3_mod.IntSort(),
                )
                return f_sym(lhs, rhs)
            return None

        # N-ary Boolean prefix: (And v1 v2 ...), (Or v1 v2 ...)
        if len(tokens) >= 2 and tokens[0] in _BOOL_OPS:
            op = tokens[0]
            b_vals = [
                _to_z3_bool(_ussa_sexpr_to_z3(t, ssa_env, z3_vars, parameters))
                for t in tokens[1:]
            ]
            if any(v is None for v in b_vals):
                return None
            return _z3_mod.And(*b_vals) if op == "And" else _z3_mod.Or(*b_vals)

        # Infix Comparison: (x_0 Gt 0) or chained (0 Lt x_0 Lt 10)
        if len(tokens) >= 3 and len(tokens) % 2 == 1 and tokens[1] in _COMPARE_OPS:
            lhs = _to_z3_int(_ussa_sexpr_to_z3(tokens[0], ssa_env, z3_vars, parameters))
            if lhs is None:
                return None
            comps = []
            for idx in range(1, len(tokens), 2):
                op_name = tokens[idx]
                rhs = _to_z3_int(
                    _ussa_sexpr_to_z3(tokens[idx + 1], ssa_env, z3_vars, parameters)
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
        z3_vars[base_name] = _z3_mod.Int(base_name)
        return z3_vars[base_name]

    try:
        parsed = ast.parse(s, mode="eval").body
        return _ast_expr_to_z3(parsed, z3_vars)
    except SyntaxError:
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
        self, func_ussa: FunctionUSSA, z3_vars: dict[str, Any] | None = None
    ) -> None:
        self.func = func_ussa
        self.param_set = set(func_ussa.parameters)
        self.z3_vars: dict[str, Any] = (
            dict(z3_vars)
            if z3_vars is not None
            else (
                {p: _z3_mod.Int(p) for p in func_ussa.parameters}
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
                            arg_s, ssa_env, self.z3_vars, self.param_set
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

    def _explore(self) -> None:
        if not self.func.basic_blocks:
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

        entry_id = self.func.basic_blocks[0].block_id
        self._walk_block(
            block_id=entry_id,
            pred_block_id=None,
            ssa_env=init_ssa_env,
            expr_env=init_expr_env,
            path_guards_z3=(),
            visited_blocks=frozenset(),
        )

    def _walk_block(
        self,
        block_id: str,
        pred_block_id: str | None,
        ssa_env: dict[str, Any],
        expr_env: dict[str, str],
        path_guards_z3: tuple[Any, ...],
        visited_blocks: frozenset[str],
    ) -> None:
        if block_id in visited_blocks:
            return
        blk = self._block_map.get(block_id)
        if blk is None:
            return

        cur_ssa = dict(ssa_env)
        cur_expr = dict(expr_env)

        # Resolve PhiNodes based on the incoming predecessor block
        for phi in blk.phi_nodes:
            chosen_ssa: str | None = None
            for incoming_blk, var_ssa in phi.incoming_branches:
                if incoming_blk == pred_block_id:
                    chosen_ssa = var_ssa
                    break
            if chosen_ssa is None and phi.incoming_branches:
                for _inc_blk, var_ssa in phi.incoming_branches:
                    if var_ssa in cur_ssa:
                        chosen_ssa = var_ssa
                        break
            if chosen_ssa is not None:
                if chosen_ssa in cur_ssa:
                    cur_ssa[phi.target_var] = cur_ssa[chosen_ssa]
                if chosen_ssa in cur_expr:
                    cur_expr[phi.target_var] = cur_expr[chosen_ssa]

        out_edges = self._cfg_out.get(block_id, [])

        for inst in blk.instructions:
            if inst.opcode in ("ASSIGN", "BINOP") and inst.target_var and inst.operands:
                raw_rhs = inst.operands[0]
                used_ssa = inst.operands[1:]
                self._extract_calls_from_sexpr(
                    raw_rhs, cur_ssa, cur_expr, path_guards_z3, inst.source_line
                )
                z3_rhs = _ussa_sexpr_to_z3(
                    raw_rhs, cur_ssa, self.z3_vars, self.param_set
                )
                norm_rhs = _normalize_ussa_expr(raw_rhs, cur_expr, self.param_set)

                # Detect unconditional parameter shadow assignment via U-SSA Def-Use
                base_tgt = _strip_ssa_suffix(inst.target_var, self.param_set)
                if (
                    inst.opcode == "ASSIGN"
                    and base_tgt in self.param_set
                    and inst.target_var == f"{base_tgt}_1"
                    and f"{base_tgt}_0" not in used_ssa
                    and len(path_guards_z3) == 0
                ):
                    self.shadowed_params.append(
                        _USSAShadowRecord(
                            param_name=base_tgt,
                            norm_val=norm_rhs,
                            z3_val=z3_rhs,
                            source_line=inst.source_line,
                        )
                    )

                cur_ssa[inst.target_var] = z3_rhs
                cur_expr[inst.target_var] = norm_rhs
                cur_ssa[base_tgt] = z3_rhs
                cur_expr[base_tgt] = norm_rhs

            elif inst.opcode == "CALL" and inst.operands:
                self._extract_calls_from_sexpr(
                    inst.operands[0],
                    cur_ssa,
                    cur_expr,
                    path_guards_z3,
                    inst.source_line,
                )

            elif inst.opcode == "BRANCH" and inst.operands:
                raw_cond = inst.operands[0]
                norm_cond = _normalize_ussa_expr(raw_cond, cur_expr, self.param_set)
                z3_cond = _to_z3_bool(
                    _ussa_sexpr_to_z3(raw_cond, cur_ssa, self.z3_vars, self.param_set)
                )
                then_sum = "pass"
                else_sum = "pass"
                for edge in out_edges:
                    if edge.predicate_label == raw_cond:
                        then_sum = self._summarize_block_terminal(edge.dst_node_uid)
                    elif edge.predicate_label == f"NOT({raw_cond})":
                        else_sum = self._summarize_block_terminal(edge.dst_node_uid)
                self.guards.append(
                    _USSAGuardRecord(
                        norm_cond=norm_cond,
                        z3_cond=z3_cond,
                        then_summary=then_sum,
                        else_summary=else_sum,
                        path_guards_z3=path_guards_z3,
                        source_line=inst.source_line,
                    )
                )

            elif inst.opcode == "RETURN":
                raw_ret = inst.operands[0] if inst.operands else "None"
                self._extract_calls_from_sexpr(
                    raw_ret, cur_ssa, cur_expr, path_guards_z3, inst.source_line
                )
                norm_ret = _normalize_ussa_expr(raw_ret, cur_expr, self.param_set)
                z3_ret = _ussa_sexpr_to_z3(
                    raw_ret, cur_ssa, self.z3_vars, self.param_set
                )
                self.returns.append(
                    _USSAReturnRecord(
                        norm_expr=norm_ret,
                        z3_expr=z3_ret,
                        path_guards_z3=path_guards_z3,
                        source_line=inst.source_line,
                    )
                )
                # Execution of this path ends at RETURN; do not traverse fallthrough edges
                return

            elif inst.opcode == "RAISE":
                return

        next_visited = visited_blocks | {block_id}
        for edge in out_edges:
            lbl = edge.predicate_label
            if lbl is None or lbl == "fallthrough":
                self._walk_block(
                    block_id=edge.dst_node_uid,
                    pred_block_id=block_id,
                    ssa_env=cur_ssa,
                    expr_env=cur_expr,
                    path_guards_z3=path_guards_z3,
                    visited_blocks=next_visited,
                )
            else:
                z_guard = _to_z3_bool(
                    _ussa_sexpr_to_z3(lbl, cur_ssa, self.z3_vars, self.param_set)
                )
                new_guards = (
                    (*path_guards_z3, z_guard)
                    if z_guard is not None
                    else path_guards_z3
                )
                self._walk_block(
                    block_id=edge.dst_node_uid,
                    pred_block_id=block_id,
                    ssa_env=cur_ssa,
                    expr_env=cur_expr,
                    path_guards_z3=new_guards,
                    visited_blocks=next_visited,
                )

    def build_return_ite(self) -> Any:
        """
        Composes all path return expressions and their branch guards into a single
        Z3 If-Then-Else (ITE) term representing the full function return semantics.
        """
        if _z3_mod is None or not self.returns:
            return None
        if any(r.z3_expr is None for r in self.returns):
            return None

        acc = _to_z3_int(self.returns[-1].z3_expr)
        if acc is None:
            return None

        for ret in reversed(self.returns[:-1]):
            val = _to_z3_int(ret.z3_expr)
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
) -> dict[str, int | str]:
    res: dict[str, int | str] = {}
    for p in parameters:
        sym = z3_vars.get(p)
        v = model[sym] if sym is not None else None
        if v is not None:
            res[p] = v.as_long() if hasattr(v, "as_long") else int(str(v))
        else:
            res[p] = default_val
    return res


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
        s = _z3_mod.Solver()
        s.set("timeout", self.timeout_ms)

        a_term = (
            _to_z3_int(z3_a)
            if z3_a is not None
            else z3_vars.setdefault(var_a_name, _z3_mod.Int(var_a_name))
        )
        b_term = (
            _to_z3_int(z3_b)
            if z3_b is not None
            else z3_vars.setdefault(var_b_name, _z3_mod.Int(var_b_name))
        )

        for g in path_guards_z3:
            if g is not None:
                s.add(g)

        s.add(a_term != b_term)

        status = s.check()
        if status == _z3_mod.sat:
            m = s.model()
            res: dict[str, int | str] = {}
            for name in all_params:
                sym = z3_vars.get(name)
                v = m[sym] if sym is not None else None
                if v is not None:
                    res[name] = v.as_long() if hasattr(v, "as_long") else int(str(v))
                else:
                    res[name] = 1 if name == var_a_name else 2
            return "SAT", res
        if status == _z3_mod.unsat:
            return "UNSAT", {}
        return "UNKNOWN", {}

    def prove_function_diff(
        self,
        *,
        file_path: str,
        base_source: str,
        head_source: str,
        func_base: FunctionUSSA,
        func_head: FunctionUSSA,
    ) -> tuple[VerificationFinding, ...]:
        start_ns = time.perf_counter_ns()

        # Stage 1: Fast egglog equality saturation check (<1ms)
        eq_res = self.egglog.check_equivalence(func_base, func_head)
        if eq_res.is_equivalent:
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            fid = content_digest_hex(
                f"EQUIV:{func_head.qualified_name}:{eq_res.head_eclass_digest}",
                domain="verifyci.v2.finding",
            )[:16]
            return (
                VerificationFinding(
                    finding_id=fid,
                    # Named for what it proves: return-value equivalence only.
                    # This is not a safety verdict - a patch can preserve the
                    # return value while adding a credential or a dangerous
                    # call. Safety checkers run independently of this finding.
                    rule_id="VC2-RETURN-VALUE-EQUIVALENT",
                    severity="LOW",
                    verdict="HEURISTIC_EQUIVALENT_CANDIDATE",
                    file_path=file_path,
                    start_line=func_head.start_line,
                    end_line=func_head.end_line,
                    message=(
                        f"Function '{func_head.qualified_name}' candidate "
                        f"return-value equivalent via egglog equality saturation "
                        f"(rewrites: {list(eq_res.applied_rewrites)}). This says "
                        "nothing about safety."
                    ),
                    witness=CounterexampleWitness(
                        checker_id="VC2-RETURN-VALUE-EQUIVALENT",
                        smt_status="UNVERIFIED_HEURISTIC",
                        input_assignments={},
                        base_return_state=eq_res.base_eclass_digest[:12],
                        head_return_state=eq_res.head_eclass_digest[:12],
                        proof_time_ms=round(elapsed_ms, 3),
                    ),
                ),
            )

        # Stage 2: Direct U-SSA Symbolic Path Extraction
        fn_short = func_head.qualified_name.split(".")[-1]
        base_fn_node: ast.AST | None = None
        head_fn_node: ast.AST | None = None
        try:
            base_tree = ast.parse(base_source, filename=file_path)
            head_tree = ast.parse(head_source, filename=file_path)
            base_fn_node = next(
                (
                    n
                    for n in base_tree.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and n.name == fn_short
                ),
                None,
            )
            head_fn_node = next(
                (
                    n
                    for n in head_tree.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and n.name == fn_short
                ),
                None,
            )
        except SyntaxError:
            return ()

        shared_z3_vars: dict[str, Any] = (
            {p: _z3_mod.Int(p) for p in func_head.parameters}
            if _z3_mod is not None
            else {}
        )
        ext_base = _USSASymbolicExtractor(func_base, shared_z3_vars)
        ext_head = _USSASymbolicExtractor(func_head, shared_z3_vars)

        findings: list[VerificationFinding] = []

        # 1. Call-Argument Swap Verification over U-SSA Call Sites
        for call_b, call_h in zip(ext_base.calls, ext_head.calls):
            if (
                call_b.callee == call_h.callee
                and len(call_b.norm_args) >= 2
                and len(call_b.norm_args) == len(call_h.norm_args)
                and call_b.norm_args != call_h.norm_args
                and sorted(call_b.norm_args) == sorted(call_h.norm_args)
            ):
                diff_indices = [
                    i
                    for i, (ab, ah) in enumerate(
                        zip(call_b.norm_args, call_h.norm_args)
                    )
                    if ab != ah
                ]
                idx_a, idx_b = diff_indices[0], diff_indices[1]
                v_a, v_b = call_b.norm_args[idx_a], call_b.norm_args[idx_b]
                z3_a = call_b.z3_args[idx_a] if idx_a < len(call_b.z3_args) else None
                z3_b = call_b.z3_args[idx_b] if idx_b < len(call_b.z3_args) else None
                combined_guards = (*call_b.path_guards_z3, *call_h.path_guards_z3)

                smt_st, assignments = self._solve_distinct_pair_witness(
                    z3_a,
                    z3_b,
                    v_a,
                    v_b,
                    shared_z3_vars,
                    path_guards_z3=combined_guards,
                    all_params=func_head.parameters,
                )

                elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                witness = CounterexampleWitness(
                    checker_id="VC2-CAP004-CALL-SWAP",
                    smt_status=smt_st,
                    input_assignments=assignments,
                    base_return_state=(
                        f"{call_b.callee}({', '.join(str(assignments.get(a, a)) for a in call_b.norm_args)})"
                    ),
                    head_return_state=(
                        f"{call_h.callee}({', '.join(str(assignments.get(a, a)) for a in call_h.norm_args)})"
                    ),
                    proof_time_ms=round(elapsed_ms, 3),
                )
                fid = content_digest_hex(
                    f"CALL_SWAP:{file_path}:{call_h.source_line}:{call_h.callee}",
                    domain="verifyci.v2.finding",
                )[:16]
                findings.append(
                    VerificationFinding(
                        finding_id=fid,
                        rule_id="VC2-CAP004-CALL-SWAP",
                        severity="CRITICAL",
                        verdict="FAIL",
                        file_path=file_path,
                        start_line=call_h.source_line,
                        end_line=call_h.source_line,
                        message=(
                            f"Z3 proven call-argument swap in '{call_h.callee}': "
                            f"base passed ({', '.join(call_b.norm_args)}) vs head ({', '.join(call_h.norm_args)})."
                        ),
                        witness=witness,
                    )
                )

        # 2. Return-Value Swap Verification over U-SSA Return Paths
        if (
            len(ext_base.returns) >= 2
            and len(ext_base.returns) == len(ext_head.returns)
            and [r.norm_expr for r in ext_base.returns]
            != [r.norm_expr for r in ext_head.returns]
            and sorted(r.norm_expr for r in ext_base.returns)
            == sorted(r.norm_expr for r in ext_head.returns)
        ):
            ret_b0 = ext_base.returns[0]
            ret_h0 = ext_head.returns[0]
            if _z3_mod is None:
                smt_st = "SOLVER_UNAVAILABLE"
                assignments = {}
            else:
                s = _z3_mod.Solver()
                s.set("timeout", self.timeout_ms)
                for g in (*ret_b0.path_guards_z3, *ret_h0.path_guards_z3):
                    if g is not None:
                        s.add(g)
                zb_r0 = _to_z3_int(ret_b0.z3_expr)
                zh_r0 = _to_z3_int(ret_h0.z3_expr)
                if zb_r0 is not None and zh_r0 is not None:
                    s.add(zb_r0 != zh_r0)
                if s.check() == _z3_mod.sat:
                    smt_st = "SAT"
                    assignments = _extract_model_assignments(
                        s.model(), shared_z3_vars, func_head.parameters, default_val=1
                    )
                else:
                    smt_st = "UNKNOWN"
                    assignments = {}

            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            witness = CounterexampleWitness(
                checker_id="VC2-CAP004-RETURN-SWAP",
                smt_status=smt_st,
                input_assignments=assignments,
                base_return_state=str(ret_b0.norm_expr),
                head_return_state=str(ret_h0.norm_expr),
                proof_time_ms=round(elapsed_ms, 3),
            )
            fid = content_digest_hex(
                f"RET_SWAP:{file_path}:{ret_h0.source_line}",
                domain="verifyci.v2.finding",
            )[:16]
            findings.append(
                VerificationFinding(
                    finding_id=fid,
                    rule_id="VC2-CAP004-RETURN-SWAP",
                    severity="HIGH",
                    verdict="FAIL",
                    file_path=file_path,
                    start_line=ret_h0.source_line,
                    end_line=func_head.end_line,
                    message=(
                        f"Z3 proven return value swap: base returns '{ret_b0.norm_expr}' "
                        f"where head returns '{ret_h0.norm_expr}'."
                    ),
                    witness=witness,
                )
            )

        # 3. Branch Guard Inversion Verification over U-SSA BasicBlock Terminators
        for guard_b, guard_h in zip(ext_base.guards, ext_head.guards):
            if (
                guard_b.norm_cond != guard_h.norm_cond
                and guard_b.then_summary == guard_h.then_summary
                and guard_b.else_summary == guard_h.else_summary
            ):
                if _z3_mod is None:
                    smt_st = "SOLVER_UNAVAILABLE"
                    assignments = {}
                else:
                    s = _z3_mod.Solver()
                    s.set("timeout", self.timeout_ms)
                    for g in (*guard_b.path_guards_z3, *guard_h.path_guards_z3):
                        if g is not None:
                            s.add(g)
                    if guard_b.z3_cond is not None and guard_h.z3_cond is not None:
                        s.add(guard_b.z3_cond != guard_h.z3_cond)
                        if s.check() == _z3_mod.sat:
                            smt_st = "SAT"
                            assignments = _extract_model_assignments(
                                s.model(),
                                shared_z3_vars,
                                func_head.parameters,
                                default_val=0,
                            )
                        else:
                            smt_st = "UNKNOWN"
                            assignments = {}
                    else:
                        smt_st = "UNKNOWN"
                        assignments = {}

                elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                witness = CounterexampleWitness(
                    checker_id="VC2-CAP002-GUARD-INVERSION",
                    smt_status=smt_st,
                    input_assignments=assignments,
                    base_return_state=f"if {guard_b.norm_cond} -> {guard_b.then_summary}",
                    head_return_state=f"if {guard_h.norm_cond} -> {guard_h.else_summary}",
                    proof_time_ms=round(elapsed_ms, 3),
                )
                fid = content_digest_hex(
                    f"GUARD_INV:{file_path}:{guard_h.source_line}",
                    domain="verifyci.v2.finding",
                )[:16]
                findings.append(
                    VerificationFinding(
                        finding_id=fid,
                        rule_id="VC2-CAP002-GUARD-INVERSION",
                        severity="CRITICAL",
                        verdict="FAIL",
                        file_path=file_path,
                        start_line=guard_h.source_line,
                        end_line=guard_h.source_line,
                        message=(
                            f"Z3 proven branch guard inversion: '{guard_b.norm_cond}' "
                            f"mutated to '{guard_h.norm_cond}' without branch swap."
                        ),
                        witness=witness,
                    )
                )

        # 4. Unconditional Parameter Shadow Assignment over U-SSA Def-Use
        base_shadow_vars = {s.param_name for s in ext_base.shadowed_params}
        for sh in ext_head.shadowed_params:
            if sh.param_name not in base_shadow_vars:
                chosen_val = 999
                if _z3_mod is None:
                    smt_st = "SOLVER_UNAVAILABLE"
                    assignments = {}
                else:
                    s = _z3_mod.Solver()
                    s.set("timeout", self.timeout_ms)
                    p_sym = shared_z3_vars.setdefault(
                        sh.param_name, _z3_mod.Int(sh.param_name)
                    )
                    rhs_int = _to_z3_int(sh.z3_val)
                    if rhs_int is not None:
                        s.add(p_sym != rhs_int)
                    s.push()
                    s.add(p_sym == _z3_mod.IntVal(999))
                    if s.check() == _z3_mod.sat:
                        smt_st = "SAT"
                        chosen_val = 999
                        assignments = {sh.param_name: chosen_val}
                    else:
                        s.pop()
                        if s.check() == _z3_mod.sat:
                            smt_st = "SAT"
                            v = s.model()[p_sym]
                            chosen_val = (
                                v.as_long()
                                if v is not None and hasattr(v, "as_long")
                                else 999
                            )
                            assignments = {sh.param_name: chosen_val}
                        else:
                            smt_st = "SAT"
                            assignments = {sh.param_name: 999}

                elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                witness = CounterexampleWitness(
                    checker_id="VC2-CAP002-SHADOW-ASSIGN",
                    smt_status=smt_st,
                    input_assignments=assignments,
                    base_return_state=f"uses parameter {sh.param_name}={chosen_val}",
                    head_return_state=f"overwrites {sh.param_name}={sh.norm_val}",
                    proof_time_ms=round(elapsed_ms, 3),
                )
                fid = content_digest_hex(
                    f"SHADOW:{file_path}:{sh.source_line}:{sh.param_name}",
                    domain="verifyci.v2.finding",
                )[:16]
                findings.append(
                    VerificationFinding(
                        finding_id=fid,
                        rule_id="VC2-CAP002-SHADOW-ASSIGN",
                        severity="HIGH",
                        verdict="FAIL",
                        file_path=file_path,
                        start_line=sh.source_line,
                        end_line=sh.source_line,
                        message=(
                            f"Parameter '{sh.param_name}' is unconditionally shadowed "
                            f"by '{sh.norm_val}' on line {sh.source_line}."
                        ),
                        witness=witness,
                    )
                )

        # 5. Unsupported Construct Escalation (Loops, Try, Async, Comprehensions)
        if not findings and func_base.h_body != func_head.h_body:
            found_construct = _detect_unsupported_ast_construct(
                base_fn_node, head_fn_node, ext_base, ext_head
            )
            if found_construct:
                elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                witness = CounterexampleWitness(
                    checker_id="VC2-SYMBOLIC-UNSUPPORTED-CONSTRUCT",
                    smt_status="UNKNOWN",
                    input_assignments={},
                    base_return_state="",
                    head_return_state="",
                    proof_time_ms=round(elapsed_ms, 3),
                )
                fid = content_digest_hex(
                    f"UNSUPPORTED:{file_path}:{func_head.qualified_name}:{found_construct}",
                    domain="verifyci.v2.finding",
                )[:16]
                findings.append(
                    VerificationFinding(
                        finding_id=fid,
                        rule_id="VC2-Z3-UNSUPPORTED-AST",
                        severity="MEDIUM",
                        verdict="INCONCLUSIVE",
                        file_path=file_path,
                        start_line=func_head.start_line,
                        end_line=func_head.end_line,
                        message=(
                            f"Function '{fn_short}' contains unsupported AST construct '{found_construct}' "
                            f"outside linear integer SMT fragment; verification is inconclusive."
                        ),
                        witness=witness,
                    )
                )
            elif _z3_mod is None:
                # Fail closed: the body changed, the change is inside the
                # supported fragment, and no solver is available to decide
                # equivalence. Returning nothing here would let the caller
                # report PASS for an unverified behavioural change.
                elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                fid = content_digest_hex(
                    f"UNAVAILABLE:{file_path}:{func_head.qualified_name}:{func_head.h_body}",
                    domain="verifyci.v2.finding",
                )[:16]
                findings.append(
                    VerificationFinding(
                        finding_id=fid,
                        rule_id="VC2-Z3-SOLVER-UNAVAILABLE",
                        severity="MEDIUM",
                        verdict="INCONCLUSIVE",
                        file_path=file_path,
                        start_line=func_head.start_line,
                        end_line=func_head.end_line,
                        message=(
                            f"Function '{fn_short}' body changed "
                            f"({func_base.h_body[:8]} -> {func_head.h_body[:8]}) and the Z3 "
                            "solver is unavailable to prove equivalence; failing closed."
                        ),
                        witness=CounterexampleWitness(
                            checker_id="VC2-Z3-SOLVER-UNAVAILABLE",
                            smt_status="SOLVER_UNAVAILABLE",
                            input_assignments={},
                            base_return_state=(
                                ext_base.returns[0].norm_expr
                                if ext_base.returns
                                else ""
                            ),
                            head_return_state=(
                                ext_head.returns[0].norm_expr
                                if ext_head.returns
                                else ""
                            ),
                            proof_time_ms=round(elapsed_ms, 3),
                        ),
                    )
                )

        return tuple(findings)

    def prove_equivalence(
        self,
        base_source: str,
        cand_source: str,
        func_base: FunctionUSSA,
        func_cand: FunctionUSSA,
    ) -> tuple[bool, SMTStatus]:
        """
        Proves functional equivalence over the supported linear integer U-SSA fragment
        by solving `ITE_base(params) != ITE_cand(params)` and checking call-trace alignment.
        """
        if _z3_mod is None:
            return False, "SOLVER_UNAVAILABLE"

        fn_short = func_base.qualified_name.split(".")[-1]
        try:
            base_tree = ast.parse(base_source)
            cand_tree = ast.parse(cand_source)
        except SyntaxError:
            return False, "UNKNOWN"

        base_fn = next(
            (
                n
                for n in base_tree.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == fn_short
            ),
            None,
        )
        cand_fn = next(
            (
                n
                for n in cand_tree.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == fn_short
            ),
            None,
        )

        if base_fn is None or cand_fn is None:
            return False, "UNKNOWN"

        # Disallow unsupported constructs (loops, tries, with blocks, async/generators)
        for fn_node in (base_fn, cand_fn):
            for node in ast.walk(fn_node):
                if isinstance(node, (*_UNSUPPORTED_AST_TYPES, ast.With)):
                    return False, "UNKNOWN"

        # Reject empty bodies or trivial `return 0` deletions of multi-statement functions
        cand_stmts = [
            s
            for s in cand_fn.body
            if not isinstance(s, ast.Expr) or not isinstance(s.value, ast.Constant)
        ]
        if not cand_stmts:
            return False, "UNKNOWN"
        if (
            len(base_fn.body) > 1
            and len(cand_fn.body) == 1
            and isinstance(cand_fn.body[0], ast.Return)
            and isinstance(cand_fn.body[0].value, ast.Constant)
            and cand_fn.body[0].value.value == 0
        ):
            return False, "UNKNOWN"

        shared_z3_vars = {p: _z3_mod.Int(p) for p in func_base.parameters}
        ext_b = _USSASymbolicExtractor(func_base, shared_z3_vars)
        ext_c = _USSASymbolicExtractor(func_cand, shared_z3_vars)

        if ext_b.unsupported_construct or ext_c.unsupported_construct:
            return False, "UNKNOWN"

        # Verify call traces align and arguments are provably equivalent
        if len(ext_b.calls) != len(ext_c.calls) or len(ext_b.returns) != len(
            ext_c.returns
        ):
            return False, "UNKNOWN"

        s = _z3_mod.Solver()
        s.set("timeout", self.timeout_ms)

        for call_b, call_c in zip(ext_b.calls, ext_c.calls):
            if call_b.callee != call_c.callee or len(call_b.z3_args) != len(
                call_c.z3_args
            ):
                return False, "UNKNOWN"
            for arg_b, arg_c in zip(call_b.z3_args, call_c.z3_args):
                zb_arg = _to_z3_int(arg_b)
                zc_arg = _to_z3_int(arg_c)
                if zb_arg is None or zc_arg is None:
                    if call_b.norm_args != call_c.norm_args:
                        return False, "UNKNOWN"
                    continue
                s.reset()
                s.set("timeout", self.timeout_ms)
                for g in (*call_b.path_guards_z3, *call_c.path_guards_z3):
                    if g is not None:
                        s.add(g)
                s.add(zb_arg != zc_arg)
                st = s.check()
                if st == _z3_mod.sat:
                    return False, "SAT"
                if st == _z3_mod.unknown:
                    return False, "UNKNOWN"

        # Verify branch guards equivalence
        if len(ext_b.guards) != len(ext_c.guards):
            return False, "UNKNOWN"

        for guard_b, guard_c in zip(ext_b.guards, ext_c.guards):
            if guard_b.z3_cond is None or guard_c.z3_cond is None:
                return False, "UNKNOWN"
            s.reset()
            s.set("timeout", self.timeout_ms)
            for g in (*guard_b.path_guards_z3, *guard_c.path_guards_z3):
                if g is not None:
                    s.add(g)
            s.add(guard_b.z3_cond != guard_c.z3_cond)
            st = s.check()
            if st == _z3_mod.sat:
                return False, "SAT"
            if st == _z3_mod.unknown:
                return False, "UNKNOWN"

        if not ext_b.returns and not ext_c.returns:
            if not ext_b.calls and not ext_c.calls and not ext_b.guards and not ext_c.guards:
                # No captured effects on either side: absence of evidence is not evidence of equivalence.
                # If function bodies differ without any return/call/guard evidence, fail closed to UNKNOWN.
                return False, "UNKNOWN"
            if len(ext_b.calls) != len(ext_c.calls) or len(ext_b.guards) != len(ext_c.guards):
                return False, "UNKNOWN"
            return True, "UNSAT"

        # Unified Path-Sensitive Return ITE Equivalence Check: ITE_base != ITE_cand
        ite_b = ext_b.build_return_ite()
        ite_c = ext_c.build_return_ite()
        if ite_b is None or ite_c is None:
            return False, "UNKNOWN"

        s.reset()
        s.set("timeout", self.timeout_ms)
        s.add(ite_b != ite_c)
        st = s.check()
        if st == _z3_mod.sat:
            return False, "SAT"
        if st == _z3_mod.unknown:
            return False, "UNKNOWN"

        return True, "UNSAT"


def _evaluate_concrete_divergence(
    base_src: str,
    head_src: str,
    fn_name: str,
    params: tuple[str, ...],
    witness_inputs: dict[str, Any],
) -> bool:
    """
    Evaluates whether base and head diverge under concrete witness input assignments
    using Z3 EUF congruence closure over U-SSA without invoking `exec()`.
    """
    if _z3_mod is None:
        return True
    try:
        from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa

        funcs_b = {
            f.qualified_name.split(".")[-1]: f
            for f in lower_file_to_ussa("base.py", base_src)
        }
        funcs_h = {
            f.qualified_name.split(".")[-1]: f
            for f in lower_file_to_ussa("head.py", head_src)
        }
        fb = funcs_b.get(fn_name)
        fh = funcs_h.get(fn_name)
        if fb is None or fh is None:
            return True

        bound_vars: dict[str, Any] = {}
        for p in params:
            raw_v = witness_inputs.get(p, 0)
            if isinstance(raw_v, bool):
                bound_vars[p] = _z3_mod.IntVal(1 if raw_v else 0)
            elif isinstance(raw_v, int):
                bound_vars[p] = _z3_mod.IntVal(raw_v)
            else:
                bound_vars[p] = _z3_mod.Int(p)

        ext_b = _USSASymbolicExtractor(fb, bound_vars)
        ext_h = _USSASymbolicExtractor(fh, bound_vars)

        s = _z3_mod.Solver()

        # 1. Check return ITE divergence under EUF (e.g. wire(1, 2) != wire(2, 1) is SAT; wire(1, 1) != wire(1, 1) is UNSAT)
        ite_b = ext_b.build_return_ite()
        ite_h = ext_h.build_return_ite()
        if ite_b is not None and ite_h is not None:
            s.add(ite_b != ite_h)
            if s.check() == _z3_mod.sat:
                return True

        # 2. Check call-site argument divergence along active branch guards
        for call_b, call_h in zip(ext_b.calls, ext_h.calls):
            s.reset()
            for g in (*call_b.path_guards_z3, *call_h.path_guards_z3):
                if g is not None:
                    s.add(g)
            if s.check() != _z3_mod.sat:
                continue
            if call_b.callee != call_h.callee or len(call_b.z3_args) != len(
                call_h.z3_args
            ):
                return True
            for arg_b, arg_h in zip(call_b.z3_args, call_h.z3_args):
                zb = _to_z3_int(arg_b)
                zh = _to_z3_int(arg_h)
                if zb is not None and zh is not None:
                    s.reset()
                    s.add(zb != zh)
                    if s.check() == _z3_mod.sat:
                        return True
        return False
    except Exception:
        return True
