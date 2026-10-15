"""Static call-contract verification (`cap004`).

v1 verified a call site against a declared contract: bind the call's arguments
to the callee signature, then check the required and forbidden bindings. v2
dropped this entirely, leaving `cap004` unmeasurable against its frozen corpus.

The checker is deliberately fail-closed. A binding that cannot be grounded
statically (`os.environ.get(...)`, `**options`, an unresolvable receiver) makes
the verdict INCONCLUSIVE. Absence of proof is never reported as compliance.
"""

from __future__ import annotations

import ast
import msgspec
from typing import Any

Verdict = str  # "VERIFIED" | "FAIL" | "INCONCLUSIVE"

# Storage/transport synonyms used when grounding a receiver against a required
# receiver type. Both sides are tokenised and compared through this table.
_RECEIVER_SYNONYMS: dict[str, str] = {
    "store": "storage",
    "storage": "storage",
    "db": "database",
    "database": "database",
    "conn": "connection",
    "connection": "connection",
    "mgr": "manager",
    "manager": "manager",
    "auth": "auth",
    "authn": "auth",
}

# Receiver names that positively assert a hardened implementation.
_SECURE_RECEIVER_MARKERS = ("secure", "hardened", "tls", "ssl")


class ContractVerdict(msgspec.Struct, frozen=True):
    verdict: Verdict
    reason: str

    @property
    def is_decided(self) -> bool:
        return self.verdict in ("VERIFIED", "FAIL")


def _literal(node: ast.AST) -> tuple[bool, Any]:
    """Returns (is_literal, value). Non-literals are undecidable.

    Declared defaults arrive as plain Python values rather than AST nodes, so
    they pass straight through. Constant-foldable arithmetic and string
    concatenation is folded so `'AES' + '-GCM'` and `100 * 1000` are decidable.
    """
    if not isinstance(node, ast.AST):
        return True, node
    if isinstance(node, ast.BinOp):
        left_ok, left = _literal(node.left)
        right_ok, right = _literal(node.right)
        if left_ok and right_ok:
            try:
                if isinstance(node.op, ast.Add):
                    return True, left + right
                if isinstance(node.op, ast.Mult):
                    return True, left * right
            except TypeError:
                return False, None
    try:
        return True, ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError):
        return False, None


def _is_dynamic(node: ast.AST) -> bool:
    """Dynamic expressions cannot be grounded to a contract value."""
    if isinstance(node, (ast.Call, ast.Attribute, ast.Subscript, ast.Await)):
        return True
    if isinstance(node, ast.Name):
        return False
    is_lit, _ = _literal(node)
    return not is_lit


def _receiver_tokens(name: str) -> set[str]:
    tokens: set[str] = set()
    for raw in name.replace(".", "_").split("_"):
        if not raw:
            continue
        # Split camelCase into words, then map synonyms.
        current = ""
        for ch in raw:
            if ch.isupper() and current:
                tokens.add(current.lower())
                current = ch
            else:
                current += ch
        if current:
            tokens.add(current.lower())
    return {_RECEIVER_SYNONYMS.get(t, t) for t in tokens}


def _resolve_receiver(contract: dict[str, Any], receiver: str | None) -> str | None:
    """Returns 'ok', 'bad', or None when the receiver type cannot be grounded."""
    required = contract.get("required_receiver_type")
    forbidden = contract.get("forbidden_receiver_type")
    if not required and not forbidden:
        return "ok"
    if receiver is None:
        return None

    if any(marker in receiver.lower() for marker in _SECURE_RECEIVER_MARKERS):
        if forbidden and _type_implies(receiver, forbidden):
            return "bad"
        return "ok"

    for candidate in (forbidden, required):
        if candidate and _type_implies(receiver, candidate):
            return "bad" if candidate == forbidden else "ok"
    return None


def _type_implies(receiver: str, type_name: str) -> bool:
    required_tokens = _receiver_tokens(type_name)
    return bool(required_tokens) and required_tokens.issubset(_receiver_tokens(receiver))


def _bind(
    call: ast.Call,
    signature: dict[str, Any],
    *,
    has_receiver: bool,
) -> tuple[dict[str, Any], bool]:
    """Binds call arguments to signature parameter names.

    For a method call the receiver occupies the first declared parameter
    (`self`/`cls`), so positional binding starts one slot in.

    Returns (bindings, fully_grounded). `fully_grounded` is False when a `*args`
    or non-literal `**kwargs` spread prevented a complete binding.
    """
    params: list[str] = list(signature.get("parameters", []))
    defaults: dict[str, Any] = dict(signature.get("defaults", {}))
    if has_receiver and params:
        params = params[1:]
    bindings: dict[str, Any] = {}
    grounded = True

    index = 0
    for arg in call.args:
        if isinstance(arg, ast.Starred):
            grounded = False
            continue
        if index < len(params):
            bindings[params[index]] = arg
        index += 1

    for keyword in call.keywords:
        if keyword.arg is None:
            # `**expr`: resolvable only when the expression is a dict literal.
            if isinstance(keyword.value, ast.Dict):
                for key_node, value_node in zip(keyword.value.keys, keyword.value.values):
                    if key_node is None:
                        grounded = False
                        continue
                    is_lit, key_value = _literal(key_node)
                    if not is_lit or not isinstance(key_value, str):
                        grounded = False
                        continue
                    bindings[key_value] = value_node
            else:
                grounded = False
            continue
        bindings[keyword.arg] = keyword.value

    # Omitted parameters take their declared default.
    for param in params:
        if param not in bindings and param in defaults:
            bindings[param] = defaults[param]

    return bindings, grounded


def _binding_names(bindings: dict[str, Any]) -> dict[str, str]:
    names: dict[str, str] = {}
    for param, node in bindings.items():
        if isinstance(node, ast.Name):
            names[param] = node.id
        else:
            is_lit, value = _literal(node)
            if is_lit:
                names[param] = str(value)
    return names


def verify_call_contract(
    call_code: str,
    callee_signature: dict[str, Any],
    contract: dict[str, Any],
) -> ContractVerdict:
    """Verifies one call site against a declared contract."""
    try:
        tree = ast.parse(call_code.strip(), mode="eval")
    except (SyntaxError, ValueError):
        return ContractVerdict("INCONCLUSIVE", "call expression is not parseable")
    if not isinstance(tree.body, ast.Call):
        return ContractVerdict("INCONCLUSIVE", "expression is not a call")

    call = tree.body
    callee = contract.get("callee")
    if callee:
        actual = (
            call.func.id
            if isinstance(call.func, ast.Name)
            else getattr(call.func, "attr", None)
        )
        if actual != callee:
            return ContractVerdict(
                "INCONCLUSIVE",
                f"callee '{actual}' does not match contract callee '{callee}'",
            )

    receiver: str | None = None
    if isinstance(call.func, ast.Attribute):
        receiver = (
            call.func.value.id
            if isinstance(call.func.value, ast.Name)
            else None
        )

    bindings, grounded = _bind(call, callee_signature, has_receiver=receiver is not None)
    names = _binding_names(bindings)

    receiver_state = _resolve_receiver(contract, receiver)
    if receiver_state == "bad":
        return ContractVerdict("FAIL", f"receiver '{receiver}' violates the contract")
    if receiver_state is None:
        return ContractVerdict(
            "INCONCLUSIVE", f"receiver type of '{receiver}' cannot be grounded"
        )

    # Forbidden bindings first: a violated prohibition is decidable regardless
    # of whether some other parameter stayed dynamic.
    #
    # Fail-closed is asymmetric here. For a *prohibition*, an undecidable value
    # cannot be proven absent, so it is reported as a violation. For a
    # *requirement*, an undecidable value is INCONCLUSIVE.
    def _may_equal(node: ast.AST, expected: Any) -> bool:
        is_lit, value = _literal(node)
        if is_lit:
            return value == expected
        return True

    for param, expected in (contract.get("forbidden_kwargs") or {}).items():
        node = bindings.get(param)
        if node is not None and _may_equal(node, expected):
            return ContractVerdict(
                "FAIL", f"forbidden kwarg '{param}'={expected!r} passed or unverifiable"
            )
    for param, expected in (contract.get("forbidden_args") or {}).items():
        node = bindings.get(param)
        if node is not None and _may_equal(node, expected):
            return ContractVerdict(
                "FAIL", f"forbidden arg '{param}'={expected!r} passed or unverifiable"
            )
    for param, expected in (contract.get("forbidden_param_bindings") or {}).items():
        if names.get(param) == expected:
            return ContractVerdict(
                "FAIL", f"forbidden binding '{param}={expected}'"
            )

    if not grounded:
        return ContractVerdict(
            "INCONCLUSIVE", "argument spread prevents a complete static binding"
        )

    for param, expected in (contract.get("required_kwargs") or {}).items():
        node = bindings.get(param)
        if node is None:
            return ContractVerdict(
                "INCONCLUSIVE", f"required kwarg '{param}' is unbound and has no default"
            )
        if _is_dynamic(node):
            return ContractVerdict(
                "INCONCLUSIVE", f"required kwarg '{param}' is a dynamic expression"
            )
        is_lit, value = _literal(node)
        if not is_lit or value != expected:
            return ContractVerdict(
                "FAIL", f"required kwarg '{param}' expected {expected!r}, got {value!r}"
            )

    for param, expected in (contract.get("required_args") or {}).items():
        node = bindings.get(param)
        if node is None:
            return ContractVerdict(
                "INCONCLUSIVE", f"required arg '{param}' is unbound and has no default"
            )
        if _is_dynamic(node):
            return ContractVerdict(
                "INCONCLUSIVE", f"required arg '{param}' is a dynamic expression"
            )
        is_lit, value = _literal(node)
        if not is_lit or value != expected:
            return ContractVerdict(
                "FAIL", f"required arg '{param}' expected {expected!r}, got {value!r}"
            )

    for param, expected in (contract.get("required_param_bindings") or {}).items():
        actual = names.get(param)
        if actual is None:
            return ContractVerdict(
                "INCONCLUSIVE", f"parameter '{param}' could not be bound"
            )
        if actual != expected:
            return ContractVerdict(
                "FAIL",
                f"parameter '{param}' bound to '{actual}', contract requires '{expected}'",
            )

    return ContractVerdict("VERIFIED", "all declared contract bindings hold")