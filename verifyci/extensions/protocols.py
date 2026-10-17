"""Extension protocols for modular capabilities."""

from __future__ import annotations

from typing import Any, Mapping, Protocol, Sequence

from verifyci.contracts.verdict import VerificationFinding
from verifyci.core.diff_parser import DiffFileEntry


class SymbolicProverProtocol(Protocol):
    """Protocol for formal SMT/equality-saturation solvers."""

    def prove_function_diff(
        self,
        file_path: str,
        base_source: str,
        head_source: str,
    ) -> Sequence[VerificationFinding]:
        ...

    def prove_equivalence(
        self,
        base_source: str,
        cand_source: str,
    ) -> tuple[bool, str]:
        ...


class GraphStoreProtocol(Protocol):
    """Protocol for bitemporal Code Property Graph persistence."""

    def record_commit_snapshot(
        self,
        commit_sha: str,
        nodes: Sequence[Any],
        edges: Sequence[Any],
    ) -> None:
        ...

    def get_edges_as_of(self, commit_sha: str) -> Sequence[Any]:
        ...


class SandboxProtocol(Protocol):
    """Protocol for isolated execution of untrusted checkers."""

    def execute_plugin(
        self,
        plugin_id: str,
        inputs: Sequence[Any],
    ) -> Any:
        ...


class AttestationLedgerProtocol(Protocol):
    """Protocol for cryptographic and git-level attestation ledgering."""

    def append_attestation(
        self,
        ref_name: str,
        commit_sha: str,
        payload_digest: str,
        envelope_data: Mapping[str, Any],
    ) -> str:
        ...
