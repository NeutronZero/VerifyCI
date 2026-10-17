"""Frozen extension protocols and typed result structures for modular capabilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Protocol, Sequence

from verifyci.contracts.capabilities import Capability, CapabilityDeclaration, ExecutionStatus
from verifyci.contracts.verdict import VerificationFinding


class EquivalenceStatus(str, Enum):
    """Authoritative result status for formal SMT equivalence solving.

    UNKNOWN or TIMEOUT must never be treated as PROVEN_EQUIVALENT.
    """

    PROVEN_EQUIVALENT = "proven_equivalent"
    PROVEN_DIVERGENT = "proven_divergent"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass(frozen=True)
class SymbolicResult:
    """Auditable result from symbolic equivalence and counterexample analysis."""

    status: EquivalenceStatus
    target_symbol: str
    counterexamples: tuple[Mapping[str, Any], ...] = ()
    proof_trace: str = ""
    duration_ms: float = 0.0
    findings: tuple[VerificationFinding, ...] = ()

    @property
    def execution_status(self) -> ExecutionStatus:
        if self.status in (EquivalenceStatus.PROVEN_EQUIVALENT, EquivalenceStatus.PROVEN_DIVERGENT):
            return ExecutionStatus.COMPLETED
        if self.status == EquivalenceStatus.TIMEOUT:
            return ExecutionStatus.TIMED_OUT
        if self.status == EquivalenceStatus.UNAVAILABLE:
            return ExecutionStatus.UNAVAILABLE
        return ExecutionStatus.FAILED_CLOSED


class EGraphStatus(str, Enum):
    """Result status for equality saturation e-graph rewriting."""

    EQUIVALENT_UNDER_RULES = "equivalent_under_rules"
    REWRITE_SATURATED = "rewrite_saturated"
    STEP_LIMIT_EXCEEDED = "step_limit_exceeded"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass(frozen=True)
class EGraphResult:
    """Auditable result from e-graph equality saturation."""

    status: EGraphStatus
    target_expression: str
    applied_rules_count: int = 0
    duration_ms: float = 0.0
    detail: str = ""


class SymbolicProverProtocol(Protocol):
    """Protocol for formal SMT solvers (Z3)."""

    def prove_function_diff(
        self,
        file_path: str,
        base_source: str,
        head_source: str,
        timeout_ms: int = 3000,
    ) -> Sequence[SymbolicResult]:
        """Verify semantic equivalence or generate counterexamples for modified functions."""
        ...


class EGraphRewriterProtocol(Protocol):
    """Protocol for equality saturation and term rewriting (Egglog)."""

    def check_algebraic_equivalence(
        self,
        base_expr: str,
        cand_expr: str,
        step_limit: int = 5000,
    ) -> EGraphResult:
        """Prove algebraic equivalence under defined rewrite rules."""
        ...


@dataclass(frozen=True)
class GraphNode:
    """CPG node representation."""

    node_uid: str
    node_kind: str
    file_path: str
    symbol_name: str
    start_line: int
    end_line: int
    properties: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    """CPG edge representation."""

    edge_uid: str
    src_node_uid: str
    dst_node_uid: str
    edge_kind: str
    properties: Mapping[str, Any] = field(default_factory=dict)


class GraphStoreProtocol(Protocol):
    """Protocol for bitemporal Code Property Graph persistence and queries."""

    def record_commit_snapshot(
        self,
        commit_sha: str,
        nodes: Sequence[GraphNode],
        edges: Sequence[GraphEdge],
    ) -> None:
        """Atomically record nodes and edges for a commit snapshot."""
        ...

    def get_nodes_as_of(self, commit_sha: str) -> Sequence[GraphNode]:
        """Query nodes active as of the given commit snapshot."""
        ...

    def get_edges_as_of(self, commit_sha: str) -> Sequence[GraphEdge]:
        """Query edges active as of the given commit snapshot."""
        ...


@dataclass(frozen=True)
class SandboxResult:
    """Outcome of isolated plugin execution."""

    output: Any
    fuel_consumed: int
    memory_bytes: int
    duration_ms: float
    error: str | None = None


class SandboxProtocol(Protocol):
    """Protocol for fuel-metered, memory-constrained untrusted checker execution."""

    def execute_plugin(
        self,
        plugin_id: str,
        plugin_wasm: bytes,
        inputs: Sequence[Any],
        fuel_limit: int = 1_000_000,
        memory_limit_bytes: int = 64 * 1024 * 1024,
    ) -> SandboxResult:
        ...


class AttestationLedgerProtocol(Protocol):
    """Protocol for cryptographic and git-level attestation ledgering."""

    def append_rsl_entry(
        self,
        ref_name: str,
        target_commit_sha: str,
        ussa_root: str,
        dsse_envelope: Mapping[str, Any],
    ) -> str:
        ...

    def verify_rsl_lineage(self, ref_name: str, expected_head_commit: str) -> bool:
        ...


class BaseSourceProvider(Protocol):
    """Protocol providing access to base revision source content."""

    def get_file_content(self, file_path: str) -> str | None:
        """Retrieve source text for a path in the base revision."""
        ...


class DictBaseSourceProvider:
    """In-memory dictionary base source provider."""

    def __init__(self, sources: Mapping[str, str]) -> None:
        self._sources = dict(sources)

    def get_file_content(self, file_path: str) -> str | None:
        norm = file_path.replace("\\", "/").strip()
        while norm.startswith("./"):
            norm = norm[2:]
        return self._sources.get(norm)
