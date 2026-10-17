"""Modular extension interfaces and capability protocols."""

from __future__ import annotations

from verifyci.extensions.protocols import (
    AttestationLedgerProtocol,
    GraphStoreProtocol,
    SandboxProtocol,
    SymbolicProverProtocol,
)

__all__ = [
    "AttestationLedgerProtocol",
    "GraphStoreProtocol",
    "SandboxProtocol",
    "SymbolicProverProtocol",
]
