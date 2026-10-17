"""Modular extension interfaces, protocols, and adapters."""

from __future__ import annotations

from verifyci.extensions.attestation_adapter import InTotoDSSEAdapter
from verifyci.extensions.egglog_adapter import EgglogRewriterAdapter
from verifyci.extensions.protocols import (
    AttestationLedgerProtocol,
    BaseSourceProvider,
    DictBaseSourceProvider,
    EGraphResult,
    EGraphRewriterProtocol,
    EGraphStatus,
    EquivalenceStatus,
    GraphEdge,
    GraphNode,
    GraphStoreProtocol,
    SandboxProtocol,
    SandboxResult,
    SymbolicProverProtocol,
    SymbolicResult,
)
from verifyci.extensions.storage.duckdb_store import DuckDBGraphStore
from verifyci.extensions.storage.sqlite_store import SQLiteGraphStore
from verifyci.extensions.wasm_sandbox import WasmFuelExhaustedError, WasmtimeSandboxAdapter
from verifyci.extensions.z3_adapter import Z3ProverAdapter

__all__ = [
    "AttestationLedgerProtocol",
    "BaseSourceProvider",
    "DictBaseSourceProvider",
    "DuckDBGraphStore",
    "EGraphResult",
    "EGraphRewriterProtocol",
    "EGraphStatus",
    "EgglogRewriterAdapter",
    "EquivalenceStatus",
    "GraphEdge",
    "GraphNode",
    "GraphStoreProtocol",
    "InTotoDSSEAdapter",
    "SQLiteGraphStore",
    "SandboxProtocol",
    "SandboxResult",
    "SymbolicProverProtocol",
    "SymbolicResult",
    "WasmFuelExhaustedError",
    "WasmtimeSandboxAdapter",
    "Z3ProverAdapter",
]
