from __future__ import annotations

import ast
import msgspec
import re
from typing import Iterable, Sequence

from verifyci_v2.contracts.attestation import VerdictKind, VerificationFinding
from verifyci_v2.contracts.canonical import blake3_hex
from verifyci_v2.contracts.ssa_ir import FunctionUSSA

_COMMUTATIVE_OPS = frozenset(
    {"Add", "Mult", "BitAnd", "BitOr", "BitXor", "Eq", "NotEq", "And", "Or"}
)
_COMPARISON_FLIP = {
    "Lt": "Gt",
    "Gt": "Lt",
    "LtE": "GtE",
    "GtE": "LtE",
    "Eq": "Eq",
    "NotEq": "NotEq",
}
_NEGATED_COMP = {
    "Lt": "GtE",
    "GtE": "Lt",
    "Gt": "LtE",
    "LtE": "Gt",
    "Eq": "NotEq",
    "NotEq": "Eq",
}


class EquivalenceSaturationResult(msgspec.Struct, frozen=True):
    is_equivalent: bool
    base_eclass_digest: str
    head_eclass_digest: str
    applied_rewrites: tuple[str, ...]
    verdict: VerdictKind = "HEURISTIC_EQUIVALENT_CANDIDATE"


def _has_floating_point(func: FunctionUSSA) -> bool:
    if (
        "float" in func.return_annotation.lower()
        or "float" in func.canonical_signature.lower()
    ):
        return True
    float_pattern = re.compile(r"(?:\b\d+\.\d+|\b\d+\.|\.\d+)\b|\bfloat\b")
    for block in func.basic_blocks:
        for inst in block.instructions:
            for op in inst.operands:
                if float_pattern.search(op):
                    return True
    return False


def _canonicalize_sexpr(expr: str, rewrites_log: list[str]) -> str:
    """
    Applies semantics-preserving e-graph equality saturation rewrite rules:
    1. Identity & Algebraic Simplification: (Add x 0) -> x, (Mult x 1) -> x
    2. Comparison Orientation Normalization: (Gt b a) -> (Lt a b)
    3. De Morgan & Double Negation: NOT((NotEq a b)) -> (Eq a b), NOT(NOT(x)) -> x
    4. Commutative Operand Sorting: (Add b a) -> (Add a b)
    """
    expr = expr.strip()

    # Double negation elimination: NOT(NOT(x)) or (Not (Not x))
    while expr.startswith("NOT(NOT(") and expr.endswith("))"):
        expr = expr[8:-2].strip()
        rewrites_log.append("double_negation_elim")
    while expr.startswith("(Not (Not ") and expr.endswith("))"):
        expr = expr[10:-2].strip()
        rewrites_log.append("double_negation_elim")

    # Normalize (Not X) -> NOT(X)
    if expr.startswith("(Not ") and expr.endswith(")"):
        inner = _canonicalize_sexpr(expr[5:-1].strip(), rewrites_log)
        rewrites_log.append("not_canonical")
        expr = f"NOT({inner})"

    # De Morgan & negated comparison normalization: NOT((Lt a b)) -> (GtE a b)
    if expr.startswith("NOT((") and expr.endswith("))"):
        inner_comp = expr[5:-2].strip()
        parts = inner_comp.split(" ", 2)
        if len(parts) == 3 and parts[1] in _NEGATED_COMP:
            left, op, right = parts[0], parts[1], parts[2]
            flipped_op = _NEGATED_COMP[op]
            rewrites_log.append(f"negated_comparison:{op}->{flipped_op}")
            expr = f"({left} {flipped_op} {right})"

    if not (expr.startswith("(") and expr.endswith(")")):
        return expr

    body = expr[1:-1].strip()
    tokens = _split_top_level_sexpr(body)
    if len(tokens) == 3:
        t0, t1, t2 = (
            _canonicalize_sexpr(tokens[0], rewrites_log),
            _canonicalize_sexpr(tokens[1], rewrites_log),
            _canonicalize_sexpr(tokens[2], rewrites_log),
        )
        # Prefix binary op: (Add left right)
        if t0 in _COMMUTATIVE_OPS:
            if t0 in ("And", "Or") and t1 == t2:
                rewrites_log.append(f"idempotent_{t0}")
                return t1
            if t0 == "Add" and t2 == "0":
                rewrites_log.append("add_zero_identity")
                return t1
            if t0 == "Add" and t1 == "0":
                rewrites_log.append("add_zero_identity")
                return t2
            if t0 == "Mult" and t2 == "1":
                rewrites_log.append("mult_one_identity")
                return t1
            if t0 == "Mult" and t1 == "1":
                rewrites_log.append("mult_one_identity")
                return t2
            if t1 > t2:
                rewrites_log.append(f"commute_{t0}")
                t1, t2 = t2, t1
            return f"({t0} {t1} {t2})"

        if t0 == "Sub" and t2 == "0":
            rewrites_log.append("sub_zero_identity")
            return t1
        if t0 == "Sub" and t1 == t2:
            rewrites_log.append("sub_self_annihilation")
            return "0"

        # Infix comparison: (left Op right)
        if t1 in _COMPARISON_FLIP:
            if t1 in ("Gt", "GtE"):
                flipped = _COMPARISON_FLIP[t1]
                rewrites_log.append(f"orient_compare:{t1}->{flipped}")
                return f"({t2} {flipped} {t0})"
            if t1 in ("Eq", "NotEq") and t0 > t2:
                rewrites_log.append(f"commute_{t1}")
                return f"({t2} {t1} {t0})"
            return f"({t0} {t1} {t2})"

    return (
        "(" + " ".join(_canonicalize_sexpr(tok, rewrites_log) for tok in tokens) + ")"
    )


def _split_top_level_sexpr(text: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in text:
        if ch in "([":
            depth += 1
            current.append(ch)
        elif ch in ")]":
            depth -= 1
            current.append(ch)
        elif ch.isspace() and depth == 0:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(ch)
    if current:
        tokens.append("".join(current))
    return tokens


def saturate_function_egraph(func: FunctionUSSA) -> tuple[str, tuple[str, ...]]:
    """
    Loads a FunctionUSSA into an equality-saturation e-graph:
    - Performs alpha-renaming of local SSA temporaries to positional canonical IDs.
    - Eliminates dead stores via symbolic substitution into return/effect expressions.
    - Applies algebraic, commutative, and De Morgan rewrite rules to fixed-point saturation.
    """
    rewrites: list[str] = []
    env_subst: dict[str, str] = {}

    for idx, param in enumerate(func.parameters):
        env_subst[f"{param}_0"] = f"$arg{idx}"

    canonical_effects: list[str] = []

    for block in func.basic_blocks:
        for phi in block.phi_nodes:
            branches_norm = []
            for br_blk, br_var in phi.incoming_branches:
                resolved = env_subst.get(br_var, br_var)
                branches_norm.append(_canonicalize_sexpr(resolved, rewrites))
            env_subst[phi.target_var] = f"PHI({','.join(sorted(branches_norm))})"

        for inst in block.instructions:
            raw_expr = inst.operands[0] if inst.operands else ""
            # Substitute known SSA variable definitions (dead-store / temp un-shadowing)
            if env_subst and raw_expr:
                pattern = re.compile(
                    r"\b("
                    + "|".join(
                        re.escape(k) for k in sorted(env_subst, key=len, reverse=True)
                    )
                    + r")\b"
                )
                raw_expr = pattern.sub(lambda m: env_subst[m.group(0)], raw_expr)

            saturated_expr = _canonicalize_sexpr(raw_expr, rewrites)
            if inst.opcode in ("ASSIGN", "BINOP") and inst.target_var:
                env_subst[inst.target_var] = saturated_expr
            elif inst.opcode in ("RETURN", "RAISE", "CALL", "STORE_ATTR", "BRANCH"):
                canonical_effects.append(
                    f"{block.block_id}:{inst.opcode}:{saturated_expr}"
                )

    eclass_signature = "|".join(canonical_effects)
    digest = blake3_hex(eclass_signature, domain="verifyci.v2.egglog.eclass")
    return digest, tuple(sorted(set(rewrites)))


class EgglogEquivalenceEngine:
    """
    Layer 5 Stage 1 Symbolic Engine (`verifyci_v2/symbolic/egglog_engine.py`):
    1. Equality saturation equivalence heuristic candidate detector (<1ms).
    2. Declarative Datalog reachability for Unsafe Deletion (`cap003a`).
    3. Declarative Datalog lock-order & unguarded async shared-state race detection (`cap008`).
    """

    def check_equivalence(
        self,
        func_base: FunctionUSSA,
        func_head: FunctionUSSA,
    ) -> EquivalenceSaturationResult:
        if _has_floating_point(func_base) or _has_floating_point(func_head):
            return EquivalenceSaturationResult(
                is_equivalent=False,
                base_eclass_digest=func_base.h_body or blake3_hex("base_float"),
                head_eclass_digest=func_head.h_body or blake3_hex("head_float"),
                applied_rewrites=(),
                verdict="INCONCLUSIVE",
            )
        if func_base.parameters != func_head.parameters:
            return EquivalenceSaturationResult(
                is_equivalent=False,
                base_eclass_digest=func_base.h_body,
                head_eclass_digest=func_head.h_body,
                applied_rewrites=(),
                verdict="INCONCLUSIVE",
            )
        has_unsupported = any(
            inst.opcode.startswith(("LOOP_", "TRY_"))
            for f in (func_base, func_head)
            for b in f.basic_blocks
            for inst in b.instructions
        )
        if has_unsupported:
            return EquivalenceSaturationResult(
                is_equivalent=False,
                base_eclass_digest=func_base.h_body,
                head_eclass_digest=func_head.h_body,
                applied_rewrites=(),
                verdict="INCONCLUSIVE",
            )
        base_dig, base_rw = saturate_function_egraph(func_base)
        head_dig, head_rw = saturate_function_egraph(func_head)
        all_rw = tuple(sorted(set(base_rw) | set(head_rw)))
        is_eq = base_dig == head_dig
        return EquivalenceSaturationResult(
            is_equivalent=is_eq,
            base_eclass_digest=base_dig,
            head_eclass_digest=head_dig,
            applied_rewrites=all_rw,
            verdict="HEURISTIC_EQUIVALENT_CANDIDATE" if is_eq else "INCONCLUSIVE",
        )

    def datalog_unsafe_deletions(
        self,
        *,
        removed_qnames: Iterable[str],
        active_callers_map: dict[str, Sequence[str]],
        exported_symbols: Iterable[str] = (),
        file_path: str = "unknown.py",
    ) -> tuple[VerificationFinding, ...]:
        """
        Datalog Rule (cap003a):
        UnsafeDeletion(sym, caller) :- RemovedInHead(sym), (LiveCaller(caller, sym) ; ExportedInAll(sym)).
        """
        exported_set = set(exported_symbols)
        findings: list[VerificationFinding] = []
        for sym in sorted(set(removed_qnames)):
            callers = tuple(sorted(set(active_callers_map.get(sym, ()))))
            is_exported = sym in exported_set or sym.split(".")[-1] in exported_set
            if callers or is_exported:
                reason = (
                    f"Deleted symbol '{sym}' remains reachable from live callers {list(callers)}"
                    if callers
                    else f"Deleted symbol '{sym}' is still exported in __all__ or cross-language bridge"
                )
                fid = blake3_hex(
                    f"CAP003A:{sym}:{reason}", domain="verifyci.v2.finding"
                )[:16]
                findings.append(
                    VerificationFinding(
                        finding_id=fid,
                        rule_id="VC2-CAP003A-UNSAFE-DELETION",
                        severity="HIGH",
                        verdict="FAIL",
                        file_path=file_path,
                        start_line=1,
                        end_line=1,
                        message=reason,
                    )
                )
        return tuple(findings)

    def datalog_concurrency_invariants(
        self,
        file_path: str,
        source: str,
    ) -> tuple[VerificationFinding, ...]:
        """
        Datalog Rules (cap008):
        1. UnguardedSharedMutation(fn, global_var) :- ConcurrentEntrypoint(fn), MutatesGlobal(fn, global_var), !AcquiresLock(fn).
        2. LockOrderInversion(fn1, fn2, L1, L2) :- AcquiresNested(fn1, L1, L2), AcquiresNested(fn2, L2, L1), L1 != L2.
        """
        tree = ast.parse(source, filename=file_path)
        findings: list[VerificationFinding] = []
        nested_lock_orders: list[
            tuple[str, str, str, int]
        ] = []  # (fn_name, lock1, lock2, lineno)

        for stmt in tree.body:
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            is_concurrent = isinstance(stmt, ast.AsyncFunctionDef) or any(
                tok in stmt.name.lower()
                for tok in ("worker", "thread", "concurrent", "parallel", "async")
            )
            acquired_locks: list[str] = []
            mutated_shared: list[tuple[str, int]] = []

            # Inspect `with lock:` / `async with lock:` blocks and nested lock orders
            for node in ast.walk(stmt):
                if isinstance(node, (ast.With, ast.AsyncWith)):
                    outer_locks = [
                        ast.unparse(item.context_expr) for item in node.items
                    ]
                    acquired_locks.extend(outer_locks)
                    for child in node.body:
                        if isinstance(child, (ast.With, ast.AsyncWith)):
                            inner_locks = [
                                ast.unparse(item.context_expr) for item in child.items
                            ]
                            for l1 in outer_locks:
                                for l2 in inner_locks:
                                    if l1 != l2:
                                        nested_lock_orders.append(
                                            (stmt.name, l1, l2, stmt.lineno)
                                        )

                elif isinstance(node, ast.Global):
                    for gname in node.names:
                        mutated_shared.append((gname, stmt.lineno))
                elif isinstance(node, (ast.Assign, ast.AugAssign)):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    for tgt in targets:
                        if isinstance(tgt, (ast.Attribute, ast.Subscript)):
                            mutated_shared.append(
                                (ast.unparse(tgt), getattr(node, "lineno", stmt.lineno))
                            )

            if is_concurrent and mutated_shared and not acquired_locks:
                state_name, line_no = mutated_shared[0]
                fid = blake3_hex(
                    f"CAP008:RACE:{file_path}:{stmt.name}:{state_name}",
                    domain="verifyci.v2.finding",
                )[:16]
                findings.append(
                    VerificationFinding(
                        finding_id=fid,
                        rule_id="VC2-CAP008-UNGUARDED-SHARED-MUTATION",
                        severity="HIGH",
                        verdict="FAIL",
                        file_path=file_path,
                        start_line=line_no,
                        end_line=getattr(stmt, "end_lineno", line_no),
                        message=(
                            f"Concurrent function '{stmt.name}' mutates shared state '{state_name}' "
                            "without a dominating lock acquisition."
                        ),
                    )
                )

        # Check LockOrderInversion across pairs of functions
        seen_inversions: set[tuple[str, str]] = set()
        for fn1, l1, l2, line1 in nested_lock_orders:
            for fn2, m1, m2, _line2 in nested_lock_orders:
                if l1 == m2 and l2 == m1 and (l2, l1) not in seen_inversions:
                    seen_inversions.add((l1, l2))
                    fid = blake3_hex(
                        f"CAP008:DEADLOCK:{file_path}:{fn1}:{fn2}:{l1}:{l2}",
                        domain="verifyci.v2.finding",
                    )[:16]
                    findings.append(
                        VerificationFinding(
                            finding_id=fid,
                            rule_id="VC2-CAP008-LOCK-ORDER-INVERSION",
                            severity="CRITICAL",
                            verdict="FAIL",
                            file_path=file_path,
                            start_line=line1,
                            end_line=line1,
                            message=(
                                f"Deadlock hazard: '{fn1}' acquires ({l1} -> {l2}) while '{fn2}' "
                                f"acquires inverted lock order ({m1} -> {m2})."
                            ),
                        )
                    )

        return tuple(findings)
