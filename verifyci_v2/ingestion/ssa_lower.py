from __future__ import annotations

import ast
import re

from verifyci_v2.contracts.canonical import content_digest_hex, canonical_jcs_bytes
from verifyci_v2.contracts.ssa_ir import (
    CPGEdge,
    FunctionUSSA,
    PhiNode,
    ParameterSpec,
    TaintSummary,
    USSABasicBlock,
    USSAInstruction,
)
from verifyci_v2.ingestion.stack_graphs import _module_prefix_from_path

_KNOWN_SINKS = frozenset(
    {
        "print",
        "logger.info",
        "logger.warning",
        "logger.error",
        "logger.debug",
        "logging.info",
        "logging.error",
        "requests.get",
        "requests.post",
        "httpx.get",
        "httpx.post",
        "os.system",
        "subprocess.run",
    }
)


class _SSABuilderContext:
    """Tracks SSA variable versions, basic blocks, CFG/DFG edges, and taint flow within a function."""

    def __init__(self, qualified_name: str, parameters: tuple[str, ...]) -> None:
        self.qualified_name = qualified_name
        self.parameters = parameters
        self.version_counters: dict[str, int] = {}
        self.current_env: dict[str, str] = {}
        self.var_defs: dict[
            str, str
        ] = {}  # ssa_var -> defining instruction or param ID
        self.tainted_by_params: dict[
            str, set[str]
        ] = {}  # ssa_var -> set of origin param names

        self.blocks: list[USSABasicBlock] = []
        self.cfg_edges: list[CPGEdge] = []
        self.dfg_edges: list[CPGEdge] = []
        self.call_targets: set[str] = set()
        self.mutated_globals: set[str] = set()
        self.raised_exceptions: set[str] = set()
        self.param_to_sinks: set[tuple[str, str]] = set()
        self.return_taint_params: set[str] = set()
        self._inst_seq = 0
        self._block_seq = 0

        for param in parameters:
            ssa_name = self.new_version(param)
            self.var_defs[ssa_name] = f"PARAM:{param}"
            self.tainted_by_params[ssa_name] = {param}

    def new_version(self, base_name: str) -> str:
        idx = self.version_counters.get(base_name, -1) + 1
        self.version_counters[base_name] = idx
        ssa_name = f"{base_name}_{idx}"
        self.current_env[base_name] = ssa_name
        return ssa_name

    def resolve_read(self, base_name: str) -> str:
        if base_name in self.current_env:
            return self.current_env[base_name]
        # Global or free variable read
        return f"global.{base_name}"

    def next_inst_id(self) -> str:
        self._inst_seq += 1
        return f"i{self._inst_seq}"

    def next_block_id(self, prefix: str) -> str:
        self._block_seq += 1
        return f"{prefix}_{self._block_seq}"

    def record_dfg(self, src_ssa: str, dst_ssa: str) -> None:
        if src_ssa == dst_ssa:
            return
        edge_uid = content_digest_hex(
            f"{self.qualified_name}:DFG:{src_ssa}->{dst_ssa}",
            domain="verifyci.v2.dfg",
        )[:24]
        self.dfg_edges.append(
            CPGEdge(
                edge_uid=edge_uid,
                src_node_uid=src_ssa,
                dst_node_uid=dst_ssa,
                edge_kind="DFG",
            )
        )
        if src_ssa in self.tainted_by_params:
            self.tainted_by_params.setdefault(dst_ssa, set()).update(
                self.tainted_by_params[src_ssa]
            )

    def record_cfg(
        self, src_block: str, dst_block: str, label: str | None = None
    ) -> None:
        edge_uid = content_digest_hex(
            f"{self.qualified_name}:CFG:{src_block}->{dst_block}:{label or ''}",
            domain="verifyci.v2.cfg",
        )[:24]
        self.cfg_edges.append(
            CPGEdge(
                edge_uid=edge_uid,
                src_node_uid=src_block,
                dst_node_uid=dst_block,
                edge_kind="CFG",
                predicate_label=label,
            )
        )


def _strip_docstring(stmts: list[ast.stmt]) -> list[ast.stmt]:
    """Removes leading docstring expression so comment/docstring edits never alter U-SSA."""
    if (
        stmts
        and isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        return stmts[1:]
    return stmts


def _expr_to_ssa_operands(
    expr: ast.AST, ctx: _SSABuilderContext
) -> tuple[str, list[str]]:
    """Returns a canonical expression string and list of referenced SSA variables."""
    used_vars: list[str] = []

    def _visit(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            ssa_v = ctx.resolve_read(node.id)
            used_vars.append(ssa_v)
            return ssa_v
        if isinstance(node, ast.Constant):
            return repr(node.value)
        if isinstance(node, ast.BinOp):
            left = _visit(node.left)
            right = _visit(node.right)
            op_name = type(node.op).__name__
            return f"({op_name} {left} {right})"
        if isinstance(node, ast.UnaryOp):
            operand = _visit(node.operand)
            op_name = type(node.op).__name__
            return f"({op_name} {operand})"
        if isinstance(node, ast.Compare):
            left = _visit(node.left)
            parts = [left]
            for op, comp in zip(node.ops, node.comparators):
                parts.append(type(op).__name__)
                parts.append(_visit(comp))
            return "(" + " ".join(parts) + ")"
        if isinstance(node, ast.BoolOp):
            op_name = type(node.op).__name__
            vals = " ".join(_visit(v) for v in node.values)
            return f"({op_name} {vals})"
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                callee = node.func.id
            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    callee = f"{node.func.value.id}.{node.func.attr}"
                else:
                    callee = node.func.attr
            else:
                callee = "indirect_call"
            ctx.call_targets.add(callee)
            arg_strs = [_visit(arg) for arg in node.args]
            for kw in sorted(node.keywords, key=lambda k: k.arg or ""):
                arg_strs.append(f"{kw.arg}={_visit(kw.value)}")
            # Check if any tainted variable flows into a sink call
            if callee in _KNOWN_SINKS:
                for v in used_vars:
                    for origin_param in ctx.tainted_by_params.get(v, ()):
                        ctx.param_to_sinks.add((origin_param, callee))
            return f"CALL({callee}, {', '.join(arg_strs)})"
        if isinstance(node, ast.Attribute):
            base = _visit(node.value)
            return f"{base}.{node.attr}"
        if isinstance(node, ast.Subscript):
            base = _visit(node.value)
            slc = _visit(node.slice)
            return f"{base}[{slc}]"
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return "[" + ", ".join(_visit(e) for e in node.elts) + "]"
        if isinstance(node, ast.Dict):
            pairs = []
            for k, v in zip(node.keys, node.values):
                k_str = _visit(k) if k is not None else "**"
                v_str = _visit(v)
                pairs.append(f"{k_str}:{v_str}")
            return "{" + ", ".join(pairs) + "}"
        if isinstance(node, ast.JoinedStr):
            parts_str = []
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    parts_str.append(f"{{{_visit(val.value)}}}")
                elif isinstance(val, ast.Constant):
                    parts_str.append(str(val.value))
            return "f'" + "".join(parts_str) + "'"
        if isinstance(node, ast.IfExp):
            cond_s = _visit(node.test)
            body_s = _visit(node.body)
            else_s = _visit(node.orelse)
            return f"(IfExp {cond_s} {body_s} {else_s})"
        return ast.unparse(node)

    rendered = _visit(expr)
    return rendered, used_vars


def _lower_stmt_list(
    stmts: list[ast.stmt],
    ctx: _SSABuilderContext,
    block_id: str,
    phi_nodes: tuple[PhiNode, ...] = (),
) -> str:
    """Lowers a sequence of AST statements into basic blocks and returns the terminating block ID."""
    instructions: list[USSAInstruction] = []
    current_block_id = block_id
    current_phis = phi_nodes

    def block_is_terminal(candidate_id: str) -> bool:
        for candidate in reversed(ctx.blocks):
            if candidate.block_id == candidate_id:
                return bool(candidate.instructions and candidate.instructions[-1].opcode in {"RETURN", "RAISE"})
        return bool(instructions and instructions[-1].opcode in {"RETURN", "RAISE"})

    for stmt in _strip_docstring(stmts):
        if instructions and instructions[-1].opcode in {"RETURN", "RAISE"}:
            break
        # A parent `if` may have terminated both branches. Do not emit a new
        # synthetic block or lower subsequent statements as reachable code.
        if not instructions and block_is_terminal(current_block_id):
            return current_block_id
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            val_node = stmt.value
            if val_node is None:
                continue
            expr_str, used_ssa = _expr_to_ssa_operands(val_node, ctx)
            for tgt in targets:
                if isinstance(tgt, ast.Name):
                    new_ssa = ctx.new_version(tgt.id)
                    for u in used_ssa:
                        ctx.record_dfg(u, new_ssa)
                    instructions.append(
                        USSAInstruction(
                            inst_id=ctx.next_inst_id(),
                            opcode="ASSIGN",
                            target_var=new_ssa,
                            operands=(expr_str, *used_ssa),
                            source_line=stmt.lineno,
                        )
                    )
                elif isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name):
                    attr_target = f"{tgt.value.id}.{tgt.attr}"
                    ctx.mutated_globals.add(attr_target)
                    instructions.append(
                        USSAInstruction(
                            inst_id=ctx.next_inst_id(),
                            opcode="STORE_ATTR",
                            target_var=attr_target,
                            operands=(expr_str, *used_ssa),
                            source_line=stmt.lineno,
                        )
                    )
                elif isinstance(tgt, ast.Subscript):
                    # A store into a container is an observable effect. Dropping
                    # it made the mutation invisible to the whole downstream
                    # pipeline, so two bodies differing only in a store lowered to
                    # the same USSA and compared equal.
                    container_str, ctl_used = _expr_to_ssa_operands(tgt.value, ctx)
                    index_str, idx_used = _expr_to_ssa_operands(tgt.slice, ctx)
                    for u in (*used_ssa, *ctl_used, *idx_used):
                        ctx.mutated_globals.add(u)
                    # A subscript store against a local container versions it, so
                    # later reads pick up the mutation (otherwise `a[k]=v`
                    # followed by `return a` collapses to the pre-mutation
                    # container and a store-only difference becomes invisible
                    # to equivalence).
                    if isinstance(tgt.value, ast.Name):
                        new_ssa = ctx.new_version(tgt.value.id)
                        ctx.record_dfg(container_str, new_ssa)
                        target_var = new_ssa
                    else:
                        target_var = f"{container_str}[{index_str}]"
                    instructions.append(
                        USSAInstruction(
                            inst_id=ctx.next_inst_id(),
                            opcode="STORE_SUBSCRIPT",
                            target_var=target_var,
                            operands=(
                                expr_str,
                                container_str,
                                index_str,
                                *used_ssa,
                                *ctl_used,
                                *idx_used,
                            ),
                            source_line=stmt.lineno,
                        )
                    )

        elif isinstance(stmt, ast.AugAssign):
            if isinstance(stmt.target, ast.Name):
                prev_ssa = ctx.resolve_read(stmt.target.id)
                rhs_str, used_ssa = _expr_to_ssa_operands(stmt.value, ctx)
                op_name = type(stmt.op).__name__
                new_ssa = ctx.new_version(stmt.target.id)
                ctx.record_dfg(prev_ssa, new_ssa)
                for u in used_ssa:
                    ctx.record_dfg(u, new_ssa)
                instructions.append(
                    USSAInstruction(
                        inst_id=ctx.next_inst_id(),
                        opcode="BINOP",
                        target_var=new_ssa,
                        operands=(
                            f"({op_name} {prev_ssa} {rhs_str})",
                            prev_ssa,
                            *used_ssa,
                        ),
                        source_line=stmt.lineno,
                    )
                )

        elif isinstance(stmt, ast.Return):
            if stmt.value is not None:
                ret_str, used_ssa = _expr_to_ssa_operands(stmt.value, ctx)
            else:
                ret_str, used_ssa = "None", []
            for u in used_ssa:
                for p in ctx.tainted_by_params.get(u, ()):
                    ctx.return_taint_params.add(p)
            instructions.append(
                USSAInstruction(
                    inst_id=ctx.next_inst_id(),
                    opcode="RETURN",
                    target_var=None,
                    operands=(ret_str, *used_ssa),
                    source_line=stmt.lineno,
                )
            )

        elif isinstance(stmt, ast.Raise):
            exc_name = "Exception"
            if isinstance(stmt.exc, ast.Call) and isinstance(stmt.exc.func, ast.Name):
                exc_name = stmt.exc.func.id
            elif isinstance(stmt.exc, ast.Name):
                exc_name = stmt.exc.id
            ctx.raised_exceptions.add(exc_name)
            instructions.append(
                USSAInstruction(
                    inst_id=ctx.next_inst_id(),
                    opcode="RAISE",
                    target_var=None,
                    operands=(exc_name,),
                    source_line=stmt.lineno,
                )
            )

        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call_str, used_ssa = _expr_to_ssa_operands(stmt.value, ctx)
            instructions.append(
                USSAInstruction(
                    inst_id=ctx.next_inst_id(),
                    opcode="CALL",
                    target_var=None,
                    operands=(call_str, *used_ssa),
                    source_line=stmt.lineno,
                )
            )

        elif isinstance(stmt, (ast.While, ast.For, ast.AsyncFor)):
            loop_kind = type(stmt).__name__
            cond_str = (
                ast.unparse(stmt.test)
                if hasattr(stmt, "test")
                else ast.unparse(stmt.iter)
            )
            instructions.append(
                USSAInstruction(
                    inst_id=ctx.next_inst_id(),
                    opcode=f"LOOP_{loop_kind.upper()}",
                    target_var=None,
                    operands=(cond_str,),
                    source_line=stmt.lineno,
                )
            )
            ctx.blocks.append(
                USSABasicBlock(
                    block_id=current_block_id,
                    phi_nodes=current_phis,
                    instructions=tuple(instructions),
                    terminator_condition=cond_str,
                )
            )
            instructions = []
            current_phis = ()
            loop_body_id = ctx.next_block_id(f"{loop_kind.lower()}_body")
            after_loop_id = ctx.next_block_id(f"{loop_kind.lower()}_exit")
            ctx.record_cfg(current_block_id, loop_body_id, label="loop_enter")
            ctx.record_cfg(current_block_id, after_loop_id, label="loop_exit")
            body_end_id = _lower_stmt_list(stmt.body, ctx, loop_body_id)
            if not block_is_terminal(body_end_id):
                ctx.record_cfg(body_end_id, after_loop_id, label="fallthrough")
            if stmt.orelse:
                else_block_id = ctx.next_block_id(f"{loop_kind.lower()}_else")
                ctx.record_cfg(current_block_id, else_block_id, label="loop_else")
                else_end_id = _lower_stmt_list(stmt.orelse, ctx, else_block_id)
                if not block_is_terminal(else_end_id):
                    ctx.record_cfg(else_end_id, after_loop_id, label="fallthrough")
            current_block_id = after_loop_id

        elif isinstance(stmt, ast.Try):
            instructions.append(
                USSAInstruction(
                    inst_id=ctx.next_inst_id(),
                    opcode="TRY_BLOCK",
                    target_var=None,
                    operands=(),
                    source_line=stmt.lineno,
                )
            )
            ctx.blocks.append(
                USSABasicBlock(
                    block_id=current_block_id,
                    phi_nodes=current_phis,
                    instructions=tuple(instructions),
                    terminator_condition=None,
                )
            )
            instructions = []
            current_phis = ()
            try_body_id = ctx.next_block_id("try_body")
            after_try_id = ctx.next_block_id("try_exit")
            ctx.record_cfg(current_block_id, try_body_id, label="try_enter")
            body_end_id = _lower_stmt_list(stmt.body, ctx, try_body_id)
            if not block_is_terminal(body_end_id):
                ctx.record_cfg(body_end_id, after_try_id, label="fallthrough")
            for handler in stmt.handlers:
                exc_id = ctx.next_block_id("except")
                ctx.record_cfg(current_block_id, exc_id, label="except")
                h_end_id = _lower_stmt_list(handler.body, ctx, exc_id)
                if not block_is_terminal(h_end_id):
                    ctx.record_cfg(h_end_id, after_try_id, label="fallthrough")
            if stmt.orelse:
                else_id = ctx.next_block_id("try_else")
                ctx.record_cfg(current_block_id, else_id, label="try_else")
                else_end = _lower_stmt_list(stmt.orelse, ctx, else_id)
                if not block_is_terminal(else_end):
                    ctx.record_cfg(else_end, after_try_id, label="fallthrough")
            if stmt.finalbody:
                finally_id = ctx.next_block_id("finally")
                ctx.record_cfg(current_block_id, finally_id, label="finally")
                _lower_stmt_list(stmt.finalbody, ctx, finally_id)
            current_block_id = after_try_id

        elif isinstance(stmt, ast.If):
            cond_str, cond_vars = _expr_to_ssa_operands(stmt.test, ctx)
            instructions.append(
                USSAInstruction(
                    inst_id=ctx.next_inst_id(),
                    opcode="BRANCH",
                    target_var=None,
                    operands=(cond_str, *cond_vars),
                    source_line=stmt.lineno,
                )
            )
            ctx.blocks.append(
                USSABasicBlock(
                    block_id=current_block_id,
                    phi_nodes=current_phis,
                    instructions=tuple(instructions),
                    terminator_condition=cond_str,
                )
            )
            instructions = []
            current_phis = ()

            pre_branch_env = dict(ctx.current_env)
            then_block_id = ctx.next_block_id("then")
            else_block_id = ctx.next_block_id("else")
            merge_block_id = ctx.next_block_id("merge")

            ctx.record_cfg(current_block_id, then_block_id, label=cond_str)
            ctx.record_cfg(current_block_id, else_block_id, label=f"NOT({cond_str})")

            # Lower THEN branch and record an edge to the merge only if it
            # actually falls through (RETURN/RAISE terminate the branch).
            ctx.current_env = dict(pre_branch_env)
            then_end_id = _lower_stmt_list(stmt.body, ctx, then_block_id)
            then_env = dict(ctx.current_env)
            then_falls = not block_is_terminal(then_end_id)
            if then_falls:
                ctx.record_cfg(then_end_id, merge_block_id, label="fallthrough")

            # Lower ELSE branch.
            ctx.current_env = dict(pre_branch_env)
            if stmt.orelse:
                else_end_id = _lower_stmt_list(stmt.orelse, ctx, else_block_id)
            else:
                ctx.blocks.append(USSABasicBlock(
                    block_id=else_block_id, phi_nodes=(), instructions=(), terminator_condition=None
                ))
                else_end_id = else_block_id
            else_env = dict(ctx.current_env)
            else_falls = not block_is_terminal(else_end_id)
            if else_falls:
                ctx.record_cfg(else_end_id, merge_block_id, label="fallthrough")

            if not then_falls and not else_falls:
                # No path reaches the merge; do not create a disconnected block.
                current_block_id = then_end_id
                current_phis = ()
                instructions = []
                ctx.current_env = dict(pre_branch_env)
                break
            if then_falls and not else_falls:
                merged_env = then_env
                merge_phis = []
            elif else_falls and not then_falls:
                merged_env = else_env
                merge_phis = []
            else:
                all_vars = sorted(set(then_env.keys()) | set(else_env.keys()))
                merge_phis = []
                merged_env = {}
                for var_name in all_vars:
                    v_then = then_env.get(var_name)
                    v_else = else_env.get(var_name)
                    if v_then == v_else and v_then is not None:
                        merged_env[var_name] = v_then
                    elif v_then is not None and v_else is not None:
                        phi_ssa = ctx.new_version(var_name)
                        merged_env[var_name] = phi_ssa
                        merge_phis.append(PhiNode(
                            target_var=phi_ssa,
                            incoming_branches=((then_end_id, v_then), (else_end_id, v_else)),
                        ))
                        ctx.record_dfg(v_then, phi_ssa)
                        ctx.record_dfg(v_else, phi_ssa)
                    else:
                        chosen = v_then or v_else
                        if chosen is not None:
                            merged_env[var_name] = chosen

            ctx.current_env = merged_env
            current_block_id = merge_block_id
            current_phis = tuple(merge_phis)

    # A block may already have been emitted as a terminal branch end.
    if not any(block.block_id == current_block_id for block in ctx.blocks):
        ctx.blocks.append(USSABasicBlock(
            block_id=current_block_id, phi_nodes=current_phis,
            instructions=tuple(instructions), terminator_condition=None,
        ))
    return current_block_id


def compute_ussa_digests(func_ussa: FunctionUSSA) -> tuple[str, str]:
    """
    Computes the Salsa-style (H_body, H_interface) BLAKE3 digests for a FunctionUSSA.
    Line numbers are excluded from H_body so shifting lines above a function does not invalidate it.
    """
    normalized_blocks = [
        {
            "block_id": b.block_id,
            "phi_nodes": [
                {"target": p.target_var, "incoming": list(p.incoming_branches)}
                for p in b.phi_nodes
            ],
            "instructions": [
                {
                    "opcode": inst.opcode,
                    "target": inst.target_var,
                    "operands": list(inst.operands),
                    "callee_symbol": inst.callee_symbol,
                }
                for inst in b.instructions
            ],
            "terminator": b.terminator_condition,
        }
        for b in func_ussa.basic_blocks
    ]
    h_body = content_digest_hex(
        canonical_jcs_bytes(normalized_blocks),
        domain="verifyci.v2.ussa.body",
    )

    interface_payload = {
        "qualified_name": func_ussa.qualified_name,
        "canonical_signature": func_ussa.canonical_signature,
        "is_pure": func_ussa.taint_summary.is_pure,
        "param_to_return": list(func_ussa.taint_summary.param_to_return),
        "param_to_sinks": [
            list(pair) for pair in func_ussa.taint_summary.param_to_sinks
        ],
        "mutated_globals": list(func_ussa.taint_summary.mutated_globals),
        "raised_exceptions": list(func_ussa.taint_summary.raised_exceptions),
    }
    h_interface = content_digest_hex(
        canonical_jcs_bytes(interface_payload),
        domain="verifyci.v2.ussa.interface",
    )
    return h_body, h_interface


def lower_python_function(
    stmt: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    file_path: str,
    repo_id: str = "default-repo",
    scope: str = "",
) -> FunctionUSSA:
    mod_prefix = _module_prefix_from_path(file_path)
    qname = f"{mod_prefix}.{scope}{stmt.name}"
    ordered_args = [*stmt.args.posonlyargs, *stmt.args.args]
    if stmt.args.vararg is not None:
        ordered_args.append(stmt.args.vararg)
    ordered_args.extend(stmt.args.kwonlyargs)
    if stmt.args.kwarg is not None:
        ordered_args.append(stmt.args.kwarg)
    params = tuple(arg.arg for arg in ordered_args)
    positional_defaults = list(stmt.args.defaults)
    positional_args = [*stmt.args.posonlyargs, *stmt.args.args]
    default_start = len(positional_args) - len(positional_defaults)
    param_specs: list[ParameterSpec] = []
    for index, arg in enumerate(stmt.args.posonlyargs):
        param_specs.append(ParameterSpec(name=arg.arg, kind="POSONLY", has_default=index >= default_start))
    for index, arg in enumerate(stmt.args.args, start=len(stmt.args.posonlyargs)):
        param_specs.append(ParameterSpec(name=arg.arg, kind="POS_OR_KW", has_default=index >= default_start))
    if stmt.args.vararg is not None:
        param_specs.append(ParameterSpec(name=stmt.args.vararg.arg, kind="VAR_POSITIONAL", has_default=False))
    for arg, default in zip(stmt.args.kwonlyargs, stmt.args.kw_defaults):
        param_specs.append(ParameterSpec(name=arg.arg, kind="KWONLY", has_default=default is not None))
    if stmt.args.kwarg is not None:
        param_specs.append(ParameterSpec(name=stmt.args.kwarg.arg, kind="VAR_KEYWORD", has_default=False))
    ret_ann = ast.unparse(stmt.returns) if stmt.returns is not None else "Any"
    # The interface digest must change when defaults, parameter kinds, or
    # annotations change; these affect callers even if the function body does not.
    try:
        args_repr = ast.unparse(stmt.args)
    except Exception:
        args_repr = ", ".join(params)
    canonical_sig = f"def {stmt.name}({args_repr}) -> {ret_ann}"

    ctx = _SSABuilderContext(qualified_name=qname, parameters=params)
    _lower_stmt_list(stmt.body, ctx, block_id="entry")

    is_pure = (
        len(ctx.mutated_globals) == 0
        and len(ctx.param_to_sinks) == 0
        and not any(c in _KNOWN_SINKS for c in ctx.call_targets)
    )
    taint_summary = TaintSummary(
        param_to_return=tuple(sorted(ctx.return_taint_params)),
        param_to_sinks=tuple(sorted(ctx.param_to_sinks)),
        mutated_globals=tuple(sorted(ctx.mutated_globals)),
        raised_exceptions=tuple(sorted(ctx.raised_exceptions)),
        is_pure=is_pure,
    )

    draft = FunctionUSSA(
        node_uid="",
        repo_id=repo_id,
        qualified_name=qname,
        file_path=file_path,
        language="python",
        start_line=stmt.lineno,
        end_line=getattr(stmt, "end_lineno", stmt.lineno),
        canonical_signature=canonical_sig,
        parameters=params,
        return_annotation=ret_ann,
        basic_blocks=tuple(ctx.blocks),
        cfg_edges=tuple(ctx.cfg_edges),
        dfg_edges=tuple(ctx.dfg_edges),
        call_targets=tuple(sorted(ctx.call_targets)),
        taint_summary=taint_summary,
        param_specs=tuple(param_specs),
    )
    h_body, h_interface = compute_ussa_digests(draft)
    node_uid = content_digest_hex(
        f"{repo_id}:{qname}:{h_body}",
        domain="verifyci.v2.node_uid",
    )
    return FunctionUSSA(
        node_uid=node_uid,
        repo_id=draft.repo_id,
        qualified_name=draft.qualified_name,
        file_path=draft.file_path,
        language=draft.language,
        start_line=draft.start_line,
        end_line=draft.end_line,
        canonical_signature=draft.canonical_signature,
        parameters=draft.parameters,
        return_annotation=draft.return_annotation,
        basic_blocks=draft.basic_blocks,
        cfg_edges=draft.cfg_edges,
        dfg_edges=draft.dfg_edges,
        call_targets=draft.call_targets,
        taint_summary=draft.taint_summary,
        h_body=h_body,
        h_interface=h_interface,
        param_specs=draft.param_specs,
    )


_POLYGLOT_FUNC_HEADER_RE = re.compile(
    r"(?:export\s+)?(?:async\s+)?(?:function\s+|(?P<ret>[A-Za-z_][\w\s\*]*?)\s+)"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*(?::\s*(?P<ts_ret>[A-Za-z_][\w<>|]*))?\s*\{",
    re.MULTILINE,
)


def lower_file_to_ussa(
    file_path: str,
    source: str,
    *,
    language: str = "python",
    repo_id: str = "default-repo",
) -> tuple[FunctionUSSA, ...]:
    """Lowers all functions in a source file into canonical FunctionUSSA representations."""
    if language == "python":
        tree = ast.parse(source, filename=file_path)
        return lower_module_to_ussa(
            file_path, tree, source, language=language, repo_id=repo_id
        )

    # Polyglot lowering for C/C++ and TypeScript/JavaScript
    mod_prefix = _module_prefix_from_path(file_path)
    results: list[FunctionUSSA] = []
    matches = list(_POLYGLOT_FUNC_HEADER_RE.finditer(source))
    for idx, m in enumerate(matches):
        name = m.group("name")
        if name in {"if", "for", "while", "switch", "catch"}:
            continue
        raw_params = [p.strip() for p in m.group("params").split(",") if p.strip()]
        param_names = tuple(p.split(":")[0].split()[-1].lstrip("*") for p in raw_params)
        ret_type = (m.group("ts_ret") or m.group("ret") or "void").strip()
        qname = f"{mod_prefix}.{name}"
        start_line = source.count("\n", 0, m.start()) + 1
        end_offset = matches[idx + 1].start() if idx + 1 < len(matches) else len(source)
        body_text = source[m.end() : end_offset]
        end_line = start_line + body_text.count("\n")

        # Strip C/TS single-line and block comments so comment edits preserve H_body
        clean_body = re.sub(
            r"//.*?$|/\*.*?\*/", "", body_text, flags=re.MULTILINE | re.DOTALL
        )
        insts = [
            USSAInstruction(
                inst_id=f"i{line_idx + 1}",
                opcode="RAW_STMT",
                target_var=None,
                operands=(line.strip(),),
                source_line=start_line + line_idx,
            )
            for line_idx, line in enumerate(clean_body.splitlines())
            if line.strip() and line.strip() != "}"
        ]
        block = USSABasicBlock(
            block_id="entry",
            phi_nodes=(),
            instructions=tuple(insts),
            terminator_condition=None,
        )
        taint = TaintSummary(
            param_to_return=param_names,
            param_to_sinks=(),
            mutated_globals=(),
            raised_exceptions=(),
            is_pure=True,
        )
        draft = FunctionUSSA(
            node_uid="",
            repo_id=repo_id,
            qualified_name=qname,
            file_path=file_path,
            language=language,
            start_line=start_line,
            end_line=end_line,
            canonical_signature=f"{name}({', '.join(param_names)}) -> {ret_type}",
            parameters=param_names,
            return_annotation=ret_type,
            basic_blocks=(block,),
            cfg_edges=(),
            dfg_edges=(),
            call_targets=(),
            taint_summary=taint,
        )
        h_body, h_interface = compute_ussa_digests(draft)
        node_uid = content_digest_hex(
            f"{repo_id}:{qname}:{h_body}", domain="verifyci.v2.node_uid"
        )
        results.append(
            FunctionUSSA(
                node_uid=node_uid,
                repo_id=draft.repo_id,
                qualified_name=draft.qualified_name,
                file_path=draft.file_path,
                language=draft.language,
                start_line=draft.start_line,
                end_line=draft.end_line,
                canonical_signature=draft.canonical_signature,
                parameters=draft.parameters,
                return_annotation=draft.return_annotation,
                basic_blocks=draft.basic_blocks,
                cfg_edges=draft.cfg_edges,
                dfg_edges=draft.dfg_edges,
                call_targets=draft.call_targets,
                taint_summary=draft.taint_summary,
                h_body=h_body,
                h_interface=h_interface,
            )
        )
    return tuple(results)


def lower_module_to_ussa(
    file_path: str,
    tree: ast.Module,
    source: str,
    *,
    language: str = "python",
    repo_id: str = "default-repo",
) -> tuple[FunctionUSSA, ...]:
    """Lower an already-parsed Python module without reparsing source text.

    This is the pipeline-owned lowering entry point. `source` is retained for
    source-sensitive digests and line metadata; `tree` is the exact AST that was
    parsed and indexed by the compiler.
    """
    if language != "python":
        raise ValueError("lower_module_to_ussa accepts Python ASTs only")
    functions: list[FunctionUSSA] = []

    def _collect(body: list[ast.stmt], scope: str) -> None:
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(lower_python_function(stmt, file_path=file_path, repo_id=repo_id, scope=scope))
                # Nested functions have independent identities; analyze them
                # separately so their bodies cannot disappear from the diff graph.
                _collect(stmt.body, f"{scope}{stmt.name}.")
            elif isinstance(stmt, ast.ClassDef):
                _collect(stmt.body, f"{scope}{stmt.name}.")
            else:
                for child in ast.iter_child_nodes(stmt):
                    if isinstance(child, ast.stmt):
                        _collect([child], scope)

    _collect(tree.body, "")
    return tuple(functions)
