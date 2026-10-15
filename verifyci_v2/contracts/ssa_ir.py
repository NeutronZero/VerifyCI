from __future__ import annotations

import msgspec
from typing import Literal

ScopeNodeKind = Literal["ROOT", "SCOPE", "PUSH_SYMBOL", "POP_SYMBOL", "EXPORT"]
EdgeKind = Literal["CFG", "DFG", "SUMMARY", "CALLS", "FFI_BRIDGE", "HTTP_BRIDGE"]
CutoffStatus = Literal[
    "CACHE_HIT_BODY_IDENTICAL",
    "CUTOFF_INTERFACE_INVARIANT",
    "PROPAGATE_INTERFACE_CHANGED",
    "NEW_FUNCTION",
]


class StackGraphNode(msgspec.Struct, frozen=True, kw_only=True):
    node_id: str
    file_path: str
    kind: ScopeNodeKind
    symbol: str
    qualified_name: str
    line: int
    is_exported: bool = False


class StackGraphEdge(msgspec.Struct, frozen=True, kw_only=True):
    src_id: str
    dst_id: str
    precedence: int = 0


class FileStackGraph(msgspec.Struct, frozen=True, kw_only=True):
    file_path: str
    language: str
    file_xxh3: str
    nodes: tuple[StackGraphNode, ...]
    edges: tuple[StackGraphEdge, ...]
    defined_symbols: tuple[str, ...]
    referenced_symbols: tuple[str, ...]
    imports: tuple[tuple[str, str], ...] = ()  # (local_alias, target_module_or_symbol)


class PhiNode(msgspec.Struct, frozen=True, kw_only=True):
    target_var: str
    incoming_branches: tuple[tuple[str, str], ...]  # ((block_id, ssa_var), ...)


class USSAInstruction(msgspec.Struct, frozen=True, kw_only=True):
    inst_id: str
    opcode: str  # 'ASSIGN' | 'BINOP' | 'CALL' | 'RETURN' | 'RAISE' | 'BRANCH'
    target_var: str | None
    operands: tuple[str, ...]
    callee_symbol: str | None = None
    source_line: int = 0


class USSABasicBlock(msgspec.Struct, frozen=True, kw_only=True):
    block_id: str
    phi_nodes: tuple[PhiNode, ...]
    instructions: tuple[USSAInstruction, ...]
    terminator_condition: str | None = None


class CPGEdge(msgspec.Struct, frozen=True, kw_only=True):
    edge_uid: str
    src_node_uid: str
    dst_node_uid: str
    edge_kind: EdgeKind
    predicate_label: str | None = None
    static_weight: float = 1.0
    coverage_hit_freq: float = 0.0


class TaintSummary(msgspec.Struct, frozen=True, kw_only=True):
    param_to_return: tuple[str, ...]
    param_to_sinks: tuple[tuple[str, str], ...]  # ((param_name, sink_symbol), ...)
    mutated_globals: tuple[str, ...]
    raised_exceptions: tuple[str, ...]
    is_pure: bool


class FunctionUSSA(msgspec.Struct, frozen=True, kw_only=True):
    node_uid: str
    repo_id: str
    qualified_name: str
    file_path: str
    language: str
    start_line: int
    end_line: int
    canonical_signature: str
    parameters: tuple[str, ...]
    return_annotation: str
    basic_blocks: tuple[USSABasicBlock, ...]
    cfg_edges: tuple[CPGEdge, ...]
    dfg_edges: tuple[CPGEdge, ...]
    call_targets: tuple[str, ...]
    taint_summary: TaintSummary
    h_body: str = ""
    h_interface: str = ""


class CutoffEvaluation(msgspec.Struct, frozen=True, kw_only=True):
    qualified_name: str
    file_path: str
    status: CutoffStatus
    previous_h_body: str | None
    current_h_body: str
    previous_h_interface: str | None
    current_h_interface: str
    requires_local_verification: bool
    propagate_to_callers: bool


USSAFunction = FunctionUSSA
