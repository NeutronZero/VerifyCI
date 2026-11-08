"""Deterministic budget accounting and limits for VerifyCI v3.1."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any


@dataclass(frozen=True)
class WorkBudget:
    max_entities: int = 1000
    max_references: int = 10000
    max_symbolic_paths: int = 64
    max_taint_depth: int = 16
    max_taint_iterations: int = 100
    solver_rlimit: int = 1000000
    max_file_bytes: int = 2 * 1024 * 1024  # 2MB
    max_ast_depth: int = 128
    max_ast_nodes: int = 50000

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_entities": self.max_entities,
            "max_references": self.max_references,
            "max_symbolic_paths": self.max_symbolic_paths,
            "max_taint_depth": self.max_taint_depth,
            "max_taint_iterations": self.max_taint_iterations,
            "solver_rlimit": self.solver_rlimit,
            "max_file_bytes": self.max_file_bytes,
            "max_ast_depth": self.max_ast_depth,
            "max_ast_nodes": self.max_ast_nodes,
        }

    def digest(self) -> str:
        canonical_bytes = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()


DEFAULT_BUDGET = WorkBudget()
