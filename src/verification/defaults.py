"""Project-default invariants applied at every verification gate.

Single source of truth for the CLI, MCP, and scheduler paths — previously
duplicated in two modules. Both entries map to real checkers in
``intent_align`` (fail-closed); neither is aspirational.
"""
from src.contracts.verification_ir import Invariant


def default_invariants() -> list[Invariant]:
    return [
        Invariant(invariant_id="secrets_scan", rule="no hardcoded secrets",
                  compiled_query="secrets_scan", blocking=True),
        Invariant(invariant_id="provenance_check", rule="claims traceable to files",
                  compiled_query="provenance_check", blocking=False),
    ]
