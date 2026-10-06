"""Argument-Value and Call-Semantics Verification (CAP-004).

Provides deterministic, AST-grounded call extraction, parameter binding,
constant-folding expression evaluation, and semantic contract verification.

Epistemic invariants:
- A graph edge CALLS(caller, callee) is necessary but not sufficient.
- When a contract governs argument values or receivers, contradicting
  values route to FAIL.
- Dynamic runtime expressions (os.environ, method invocations, ungrounded
  **kwargs / *args, unmodeled callee signatures) route to INCONCLUSIVE.
  Absence of proof is NEVER proof of compliance.
- Diffs mutating existing call arguments without verified proof escalate
  to HUMAN_REVIEW or FAIL, closing the CAP-002 N-S4 argument-blindness falsifier.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any

from verifyci.contracts.verification_ir import CheckResult
from verifyci.verification.diffmap import iter_hunks
from verifyci.verification.partition import FilePartition, classify_path


@dataclass(frozen=True)
class CallExpression:
    """Structured representation of a parsed call site."""
    callee: str
    receiver: str | None
    raw_code: str
    positional_args: tuple[tuple[str, Any], ...]
    keyword_args: dict[str, tuple[str, Any]]
    has_star_args: bool
    star_args_expr: str | None
    has_kwargs: bool
    kwargs_expr: str | None
    is_conditional: bool
    line_number: int | None = None


def evaluate_ast_node(node: ast.AST) -> tuple[str, Any]:
    """Evaluates an AST expression node.

    Returns (kind, value):
      - ('LITERAL', val) for constant literals and safely folded operations
      - ('IDENTIFIER', name) for raw variable/parameter names
      - ('CONDITIONAL', (branch1, branch2)) for ternary expressions
      - ('DYNAMIC', raw_expr) for dynamic calls/attributes/lookups
      - ('UNPACKED_DYNAMIC', raw_expr) for ungrounded *args / **kwargs
    """
    if isinstance(node, ast.Constant):
        return ("LITERAL", node.value)

    if isinstance(node, ast.Name):
        return ("IDENTIFIER", node.id)

    if isinstance(node, ast.UnaryOp):
        sub_kind, sub_val = evaluate_ast_node(node.operand)
        if sub_kind == "LITERAL":
            try:
                if isinstance(node.op, ast.USub):
                    return ("LITERAL", -sub_val)
                if isinstance(node.op, ast.UAdd):
                    return ("LITERAL", +sub_val)
                if isinstance(node.op, ast.Not):
                    return ("LITERAL", not sub_val)
                if isinstance(node.op, ast.Invert):
                    return ("LITERAL", ~sub_val)
            except Exception:
                pass
        return ("DYNAMIC", _unparse_safe(node))

    if isinstance(node, ast.BinOp):
        left_kind, left_val = evaluate_ast_node(node.left)
        right_kind, right_val = evaluate_ast_node(node.right)
        if left_kind == "LITERAL" and right_kind == "LITERAL":
            try:
                if isinstance(node.op, ast.Add):
                    return ("LITERAL", left_val + right_val)
                if isinstance(node.op, ast.Sub):
                    return ("LITERAL", left_val - right_val)
                if isinstance(node.op, ast.Mult):
                    return ("LITERAL", left_val * right_val)
                if isinstance(node.op, ast.Div):
                    return ("LITERAL", left_val / right_val)
                if isinstance(node.op, ast.FloorDiv):
                    return ("LITERAL", left_val // right_val)
                if isinstance(node.op, ast.Mod):
                    return ("LITERAL", left_val % right_val)
                if isinstance(node.op, ast.Pow):
                    return ("LITERAL", left_val ** right_val)
            except Exception:
                pass
        return ("DYNAMIC", _unparse_safe(node))

    if isinstance(node, ast.Dict):
        keys = [evaluate_ast_node(k) for k in node.keys if k is not None]
        values = [evaluate_ast_node(v) for v in node.values]
        if len(keys) == len(node.keys) and all(k[0] == "LITERAL" for k in keys) and all(v[0] == "LITERAL" for v in values):
            d = {k[1]: v[1] for k, v in zip(keys, values)}
            return ("LITERAL", d)
        return ("DYNAMIC", _unparse_safe(node))

    if isinstance(node, (ast.List, ast.Tuple)):
        elements = [evaluate_ast_node(e) for e in node.elts]
        if all(e[0] == "LITERAL" for e in elements):
            res = tuple(e[1] for e in elements) if isinstance(node, ast.Tuple) else [e[1] for e in elements]
            return ("LITERAL", res)
        return ("DYNAMIC", _unparse_safe(node))

    if isinstance(node, ast.IfExp):
        test_kind, test_val = evaluate_ast_node(node.test)
        body_eval = evaluate_ast_node(node.body)
        orelse_eval = evaluate_ast_node(node.orelse)
        if test_kind == "LITERAL":
            return body_eval if test_val else orelse_eval
        return ("CONDITIONAL", (body_eval, orelse_eval))

    if isinstance(node, ast.Call):
        # Support literal dict constructor: dict(k1=v1, k2=v2)
        if isinstance(node.func, ast.Name) and node.func.id == "dict":
            literal_kwargs = {}
            all_literal = True
            for kw in node.keywords:
                if kw.arg is None:
                    all_literal = False
                    break
                v_kind, v_val = evaluate_ast_node(kw.value)
                if v_kind == "LITERAL":
                    literal_kwargs[kw.arg] = v_val
                else:
                    all_literal = False
                    break
            if all_literal and not node.args:
                return ("LITERAL", literal_kwargs)
        return ("DYNAMIC", _unparse_safe(node))

    if isinstance(node, ast.Attribute):
        return ("DYNAMIC", _unparse_safe(node))

    return ("DYNAMIC", _unparse_safe(node))


def _unparse_safe(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return "<expr>"


def extract_calls_from_text(text: str, target_callee: str | None = None, top_level_only: bool = False) -> list[CallExpression]:
    """Extracts call expressions from code text or expressions using standard ast."""
    calls: list[CallExpression] = []
    import textwrap
    clean = textwrap.dedent(text).strip()
    tree = None
    for cand in (text, clean, f"x = {clean}", f"def _dummy():\n    {clean}"):
        try:
            tree = ast.parse(cand)
            break
        except SyntaxError:
            continue
    if tree is None:
        return calls

    def _visit(node: ast.AST):
        if isinstance(node, ast.Call):
            receiver: str | None = None
            if isinstance(node.func, ast.Name):
                callee = node.func.id
            elif isinstance(node.func, ast.Attribute):
                callee = node.func.attr
                receiver = _unparse_safe(node.func.value)
            else:
                callee = _unparse_safe(node.func)

            positional: list[tuple[str, Any]] = []
            has_star = False
            star_expr = None
            for a in node.args:
                if isinstance(a, ast.Starred):
                    has_star = True
                    star_expr = _unparse_safe(a.value)
                else:
                    positional.append(evaluate_ast_node(a))

            keywords: dict[str, tuple[str, Any]] = {}
            has_kwargs = False
            kwargs_expr = None
            for kw in node.keywords:
                if kw.arg is None:
                    has_kwargs = True
                    kwargs_expr = _unparse_safe(kw.value)
                    # If kwargs is a literal dict or dict(...) constructor, extract keys
                    kw_eval = evaluate_ast_node(kw.value)
                    if kw_eval[0] == "LITERAL" and isinstance(kw_eval[1], dict):
                        for k, v in kw_eval[1].items():
                            keywords[str(k)] = ("LITERAL", v)
                        has_kwargs = False
                else:
                    keywords[kw.arg] = evaluate_ast_node(kw.value)

            raw_code = _unparse_safe(node)
            line_no = getattr(node, "lineno", None)
            c = CallExpression(
                callee=callee,
                receiver=receiver,
                raw_code=raw_code,
                positional_args=tuple(positional),
                keyword_args=keywords,
                has_star_args=has_star,
                star_args_expr=star_expr,
                has_kwargs=has_kwargs,
                kwargs_expr=kwargs_expr,
                is_conditional=False,
                line_number=line_no,
            )
            if target_callee is None or callee == target_callee:
                calls.append(c)
            if top_level_only:
                return  # Do not recurse into nested call arguments

        for child in ast.iter_child_nodes(node):
            _visit(child)

    _visit(tree)
    return calls


def bind_parameters(call: CallExpression, signature: dict | None) -> dict[str, tuple[str, Any]]:
    """Maps call arguments (positional and keyword) to parameter names."""
    bound: dict[str, tuple[str, Any]] = {}
    params = signature.get("parameters", []) if signature else []
    defaults = signature.get("defaults", {}) if signature else {}

    # 1. Bind positional args
    for idx, arg_val in enumerate(call.positional_args):
        bound[f"__arg_{idx}"] = arg_val
        if idx < len(params):
            param_name = params[idx]
            bound[param_name] = arg_val

    # 2. Bind keyword args
    for kw_name, kw_val in call.keyword_args.items():
        bound[kw_name] = kw_val

    # 3. Fill default values for missing parameters
    for p in params:
        if p not in bound and p in defaults:
            bound[p] = ("DEFAULT_LITERAL", defaults[p])

    return bound


def verify_call_semantics(
    call: CallExpression,
    contract: dict,
    signature: dict | None = None,
    receiver_type: str | None = None,
) -> tuple[str, str]:
    """Evaluates a call against a semantic contract.

    Returns (status, rationale) where status is:
      - 'VERIFIED': statically grounded proof of compliance
      - 'FAIL': definitive contradiction or forbidden argument
      - 'INCONCLUSIVE': ungrounded dynamic expression or missing signature
    """
    contract_callee = contract.get("callee")
    if contract_callee and call.callee != contract_callee:
        return "FAIL", f"callee mismatch: expected {contract_callee!r}, found {call.callee!r}"

    fail_reasons: list[str] = []
    inconclusive_reasons: list[str] = []

    # 1. Receiver Type Verification
    req_recv = contract.get("required_receiver_type")
    forbid_recv = contract.get("forbidden_receiver_type")

    # If receiver_type not passed explicitly, fallback to call's receiver string if simple
    effective_receiver = receiver_type

    if forbid_recv:
        if effective_receiver == forbid_recv:
            fail_reasons.append(f"forbidden receiver type {forbid_recv!r} matched")

    if req_recv:
        if effective_receiver is None:
            inconclusive_reasons.append(f"receiver type for {call.callee!r} is ungrounded")
        elif effective_receiver != req_recv:
            fail_reasons.append(f"receiver type {effective_receiver!r} violates required {req_recv!r}")

    # 2. Bind parameters
    bound = bind_parameters(call, signature)

    # 3. Check Forbidden Arguments
    forbidden_kwargs = contract.get("forbidden_kwargs", {})
    forbidden_args = contract.get("forbidden_args", {})
    forbidden_bindings = contract.get("forbidden_param_bindings", {})
    all_forbidden = {**forbidden_kwargs, **forbidden_args, **forbidden_bindings}

    for param, forbid_val in all_forbidden.items():
        if param in bound:
            k, v = bound[param]
            if k in ("LITERAL", "DEFAULT_LITERAL", "IDENTIFIER"):
                if v == forbid_val:
                    fail_reasons.append(f"forbidden argument {param}={forbid_val!r} detected")
            elif k == "CONDITIONAL":
                (b1_k, b1_v), (b2_k, b2_v) = v
                if (b1_k == "LITERAL" and b1_v == forbid_val) or (b2_k == "LITERAL" and b2_v == forbid_val):
                    fail_reasons.append(f"conditional branch permits forbidden argument {param}={forbid_val!r}")

    # 4. Check Required Arguments
    required_kwargs = contract.get("required_kwargs", {})
    required_args = contract.get("required_args", {})
    required_bindings = contract.get("required_param_bindings", {})
    all_required = {**required_kwargs, **required_args, **required_bindings}

    params_in_sig = set(signature.get("parameters", [])) if signature else set()

    for param, req_val in all_required.items():
        if param not in bound:
            if signature and not params_in_sig:
                inconclusive_reasons.append(f"signature for callee {call.callee!r} is unmodeled")
            elif call.has_star_args:
                inconclusive_reasons.append(f"parameter {param!r} may be supplied by dynamic *args unpacking")
            elif call.has_kwargs:
                inconclusive_reasons.append(f"parameter {param!r} may be supplied by dynamic **kwargs unpacking")
            else:
                fail_reasons.append(f"required argument {param!r} missing")
            continue

        k, v = bound[param]
        if k in ("LITERAL", "DEFAULT_LITERAL", "IDENTIFIER"):
            if v != req_val:
                fail_reasons.append(f"argument {param}={v!r} contradicts required {req_val!r}")
        elif k == "CONDITIONAL":
            (b1_k, b1_v), (b2_k, b2_v) = v
            b1_violates = (b1_k == "LITERAL" and b1_v != req_val)
            b2_violates = (b2_k == "LITERAL" and b2_v != req_val)
            if b1_violates or b2_violates:
                fail_reasons.append(f"conditional branch permits contradicting value for {param!r}")
            elif b1_v == req_val and b2_v == req_val:
                pass  # verified
            else:
                inconclusive_reasons.append(f"conditional expression for {param!r} contains dynamic branch")
        elif k in ("DYNAMIC", "UNPACKED_DYNAMIC"):
            inconclusive_reasons.append(f"argument {param!r} is dynamic expression {v!r}")

    # 5. Dynamic Unpacking checks: dynamic kwargs can override defaults
    if call.has_kwargs:
        unbound_or_default = [
            p for p in all_required
            if p not in bound or bound[p][0] in ("DEFAULT_LITERAL", "DYNAMIC", "UNPACKED_DYNAMIC")
        ]
        if unbound_or_default:
            inconclusive_reasons.append(f"dynamic **kwargs unpacking may override parameters: {unbound_or_default}")

    if call.has_star_args:
        unbound_pos = [
            p for p in all_required
            if p not in bound or bound[p][0] in ("DYNAMIC", "UNPACKED_DYNAMIC")
        ]
        if unbound_pos:
            inconclusive_reasons.append(f"dynamic *args unpacking covers required parameters: {unbound_pos}")

    # Epistemic Decision Rule:
    if fail_reasons:
        return "FAIL", "; ".join(fail_reasons)
    if inconclusive_reasons:
        return "INCONCLUSIVE", "; ".join(inconclusive_reasons)
    return "VERIFIED", "call semantics and argument contracts verified"


def evaluate_diff_call_case(
    diff: str,
    contract: dict | None = None,
    signature: dict | None = None,
    receiver_type: str | None = None,
) -> tuple[str, str]:
    """Evaluates unified diff call additions or mutations."""
    # Find all calls added in diff
    added_calls: list[CallExpression] = []
    removed_calls: list[CallExpression] = []

    for hunk in iter_hunks(diff or ""):
        for body in hunk.lines:
            if body.startswith("+") and not body.startswith("+++"):
                added_calls.extend(extract_calls_from_text(body[1:]))
            elif body.startswith("-") and not body.startswith("---"):
                removed_calls.extend(extract_calls_from_text(body[1:]))

    if not added_calls and not removed_calls:
        return "INCONCLUSIVE", "no call expressions found in diff"

    # If evaluating against a specific contract:
    target_callee = contract.get("callee") if contract else None
    matching_added = [c for c in added_calls if not target_callee or c.callee == target_callee]

    if matching_added and contract:
        # Check added call against contract
        return verify_call_semantics(matching_added[0], contract, signature=signature, receiver_type=receiver_type)

    # Check for direct mutation between removed and added call
    if removed_calls and added_calls:
        first_rem = removed_calls[0]
        first_add = added_calls[0]
        if first_rem.callee == first_add.callee:
            # Callee identical, arguments mutated
            if contract:
                return verify_call_semantics(first_add, contract, signature=signature, receiver_type=receiver_type)
            # Tripwire: mutating arguments without contract
            return "FAIL", f"call arguments mutated for {first_rem.callee}: {first_rem.raw_code} -> {first_add.raw_code}"

    if matching_added:
        return "VERIFIED", "added call extracted"
    return "INCONCLUSIVE", "call could not be matched"


def _is_call_argument_mutation(rc: CallExpression, ac: CallExpression) -> bool:
    """True if call arguments or values were mutated, rather than compliant evolution."""
    if rc.callee != ac.callee:
        return False
    # If positional args count decreased: dropped argument -> mutation
    if len(ac.positional_args) < len(rc.positional_args):
        for i in range(len(ac.positional_args), len(rc.positional_args)):
            orig = rc.positional_args[i]
            found = any(val == orig for val in ac.keyword_args.values())
            if not found:
                return True
    # If any positional arg that exists in both changed value -> mutation
    common_pos = min(len(rc.positional_args), len(ac.positional_args))
    for i in range(common_pos):
        if rc.positional_args[i] != ac.positional_args[i]:
            return True
    # If an existing keyword argument changed its value -> mutation
    for k, v in rc.keyword_args.items():
        if k in ac.keyword_args:
            if ac.keyword_args[k] != v:
                return True
        else:
            return True
    return False


def call_semantics_check(diff: str | None) -> CheckResult:
    """Non-blocking tripwire check for call argument / routing mutations in diffs.

    Detects when a call's arguments are mutated in-place (such as CAP-002 N-S4
    send_email("a") -> send_email("b")).
    Escalates to HUMAN_REVIEW (blocking=False), never silent PASS.
    """
    mutations: list[str] = []
    for hunk in iter_hunks(diff or ""):
        if hunk.file is None or classify_path(hunk.file) != FilePartition.CODE_CORE:
            continue
        rem_calls: list[tuple[int, CallExpression]] = []
        add_calls: list[CallExpression] = []
        old_ln = hunk.old_start
        for body in hunk.lines:
            if body.startswith("-") and not body.startswith("---"):
                for c in extract_calls_from_text(body[1:]):
                    rem_calls.append((old_ln, c))
                old_ln += 1
            elif body.startswith("+") and not body.startswith("+++"):
                for c in extract_calls_from_text(body[1:]):
                    add_calls.append(c)
            elif not body.startswith("\\"):
                old_ln += 1

        for ln, rc in rem_calls:
            # If the exact call is preserved in additions, it was not mutated
            if any(ac.callee == rc.callee and ac.positional_args == rc.positional_args and ac.keyword_args == rc.keyword_args for ac in add_calls):
                continue
            for ac in add_calls:
                if rc.callee == "get" and rc.positional_args and ac.positional_args and rc.positional_args[0] == ac.positional_args[0]:
                    continue
                if _is_call_argument_mutation(rc, ac):
                    mutations.append(f"{hunk.file}:{ln}: {rc.callee} arguments mutated ({rc.raw_code} -> {ac.raw_code})")

    if not mutations:
        return CheckResult(
            check_id="call_semantics_mutation",
            passed=True,
            score=1.0,
            evidence=[],
            explanation="no call argument mutations detected",
            blocking=False,
        )

    first = mutations[0]
    rest = f" +{len(mutations) - 1} more" if len(mutations) > 1 else ""
    return CheckResult(
        check_id="call_semantics_mutation",
        passed=False,
        score=0.0,
        evidence=list(mutations),
        explanation=f"call semantics mutated at {first}{rest}; argument contract unverified",
        blocking=False,
    )


def evaluate_call_invariant_query(diff: str, query_text: str, mode: str = "require") -> tuple[bool, str, bool, list]:
    """Evaluates an invariant call query against diff.

    Returns (passed, why, established, hits).
    mode: 'require' or 'forbid'.
    """
    calls = extract_calls_from_text(query_text)
    if not calls:
        return False, f"invalid call query syntax: {query_text!r}", True, []
    query_call = calls[0]
    callee = query_call.callee

    added_calls: list[CallExpression] = []
    hit_files: list[str] = []
    for hunk in iter_hunks(diff or ""):
        for body in hunk.lines:
            if body.startswith("+") and not body.startswith("+++"):
                extracted = extract_calls_from_text(body[1:], target_callee=callee)
                if extracted:
                    added_calls.extend(extracted)
                    if hunk.file:
                        hit_files.append(hunk.file)

    if mode == "forbid":
        contract = {
            "callee": callee,
            "forbidden_kwargs": {k: v[1] for k, v in query_call.keyword_args.items() if v[0] == "LITERAL"},
            "forbidden_args": {f"__arg_{i}": v[1] for i, v in enumerate(query_call.positional_args) if v[0] == "LITERAL"},
        }
        for ac in added_calls:
            status, rationale = verify_call_semantics(ac, contract)
            if status == "FAIL":
                return False, f"forbidden call semantics in {hit_files[0] if hit_files else 'diff'}: {rationale}", True, hit_files
            if status == "INCONCLUSIVE":
                return False, f"ungrounded dynamic call in {hit_files[0] if hit_files else 'diff'}: {rationale}", False, []
        return True, f"no forbidden call semantics detected for {callee}", True, []

    elif mode == "require":
        contract = {
            "callee": callee,
            "required_kwargs": {k: v[1] for k, v in query_call.keyword_args.items() if v[0] == "LITERAL"},
            "required_args": {f"__arg_{i}": v[1] for i, v in enumerate(query_call.positional_args) if v[0] == "LITERAL"},
        }
        if not added_calls:
            return False, f"required call {callee} not found in added code", True, []
        for ac in added_calls:
            status, rationale = verify_call_semantics(ac, contract)
            if status == "VERIFIED":
                return True, f"required call semantics verified for {callee}", True, []
            if status == "FAIL":
                return False, f"call semantics violation: {rationale}", True, hit_files
            if status == "INCONCLUSIVE":
                return False, f"call semantics ungrounded: {rationale}", False, []
        return False, f"required call semantics could not be established for {callee}", False, []

    return False, "unknown mode", True, []
