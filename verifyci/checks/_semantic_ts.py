"""TypeScript guard extraction using the shared Tree-sitter parser loader."""

from __future__ import annotations

from typing import Any
import z3

from verifyci.checks._semantic_symbolic import BudgetExhaustedError
from verifyci.scope.parsers import parse_ts_bytes


def analyze_typescript_guard(
    b_src: str,
    h_src: str,
    eff: str,
    solver_rlimit: int = 100000,
) -> tuple[str, str, z3.ExprRef, z3.ExprRef, dict[str, Any], int, str] | tuple[str, str, int] | None:
    """Analyze TypeScript file using tree-sitter AST to extract function, guard condition, and Z3 model."""
    b_tree = parse_ts_bytes(b_src.encode("utf-8"), "typescript")
    h_tree = parse_ts_bytes(h_src.encode("utf-8"), "typescript")
    if b_tree is None or h_tree is None:
        return None

    def _find_fn_and_guard(root_node: Any, effect_name: str):
        found_fn = ""
        found_guard = None
        call_line = 1

        def _search(node: Any, current_fn: str, current_guard: Any) -> bool:
            nonlocal found_fn, found_guard, call_line
            next_fn = current_fn
            next_guard = current_guard

            if node.type in ("function_declaration", "method_definition", "function"):
                for child in node.children:
                    if child.type in ("identifier", "property_identifier"):
                        next_fn = child.text.decode("utf-8")
                        break
            elif node.type == "if_statement":
                for child in node.children:
                    if child.type == "parenthesized_expression":
                        next_guard = child
                        break
            elif node.type == "call_expression":
                fn_ident = None
                for child in node.children:
                    if child.type in ("identifier", "property_identifier"):
                        fn_ident = child.text.decode("utf-8")
                        break
                if fn_ident == effect_name:
                    found_fn = current_fn
                    found_guard = current_guard
                    call_line = node.start_point[0] + 1
                    return True

            for child in node.children:
                if _search(child, next_fn, next_guard):
                    return True
            return False

        _search(root_node, "", None)
        return found_fn, found_guard, call_line

    b_fn_name, b_guard_node, b_call_line = _find_fn_and_guard(b_tree.root_node, eff)
    h_fn_name, h_guard_node, h_call_line = _find_fn_and_guard(h_tree.root_node, eff)

    if not b_fn_name or not h_fn_name:
        return None

    if b_guard_node and not h_guard_node:
        var_name = "role"
        val_str = "admin"
        op_text = ""
        for child in b_guard_node.children:
            if child.type == "binary_expression":
                left_text = ""
                right_text = ""
                for sub in child.children:
                    if sub.type in ("member_expression", "identifier"):
                        if not left_text:
                            left_text = sub.text.decode("utf-8")
                    elif sub.type in ("string", "string_fragment", "number"):
                        right_text = sub.text.decode("utf-8").strip("\"'")
                    elif sub.type in ("==", "===", "!=", "!==", ">=", "<=", ">", "<"):
                        op_text = sub.text.decode("utf-8")
                if left_text:
                    var_name = left_text.split(".")[-1]
                if right_text:
                    val_str = right_text
                break

        if op_text and op_text not in ("==", "==="):
            return ("unsupported_operator", op_text, b_call_line)

        z3_var = z3.String(var_name)
        phi_base = z3_var == val_str
        phi_head = z3.BoolVal(True)
        delta = z3.And(phi_head, z3.Not(phi_base))

        solver = z3.Solver()
        solver.set("rlimit", solver_rlimit)
        solver.add(delta)
        solver_res = solver.check()
        if solver_res == z3.unknown:
            raise BudgetExhaustedError(f"solver_unknown: {solver.reason_unknown()}")
        if solver_res == z3.sat:
            z3_model = solver.model()
            model_values: dict[str, Any] = {}
            for d in z3_model.decls():
                v = z3_model[d]
                model_values[d.name()] = v.as_string() if z3.is_string(v) else bool(v)
            if not model_values.get(var_name) or model_values[var_name] == val_str:
                model_values[var_name] = "user"

            guard_desc = f"{var_name} guard" if var_name else "required guard"
            return b_fn_name, h_fn_name, phi_base, phi_head, model_values, h_call_line, guard_desc

    return None


__all__ = ["analyze_typescript_guard"]
