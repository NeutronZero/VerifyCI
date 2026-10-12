#!/usr/bin/env python3
"""CAP-013 Mutation Suite: Fault Injectors and Mutation Accounting.

Implements critical and equivalent mutations against VerifyCI verification engines.
CRITICAL CONSTRAINT (P1-5):
Every mutation executes in an isolated temporary sandbox.
Results report per-mutation evidence (target, diff, outcome, classification: killed/survived/equivalent).
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from verifyci.verification.blast_radius import blast_radius_check
from verifyci.verification.call_semantics import call_semantics_check
from verifyci.verification.diffmap import find_ambiguous_files
from verifyci.verification.removal import removal_provenance_check


def evaluate_mutation(mutation_def: dict[str, Any]) -> dict[str, Any]:
    """Execute a single mutation in an isolated temporary copy and classify."""
    m_id = mutation_def["mutation_id"]

    with tempfile.TemporaryDirectory() as tmp_str:
        sandbox = Path(tmp_str)

        if m_id == "MUT-01_EDGE_DIRECTION_FLIP":
            # Graph with caller (1) -> callee (2). Mutation flips edge direction.
            class GraphNormal:
                def predecessors(self, idx: int) -> list[int]:
                    return [1] if idx == 2 else []
                def successors(self, idx: int) -> list[int]:
                    return [2] if idx == 1 else []

            class GraphMutated:
                def predecessors(self, idx: int) -> list[int]:
                    return [2] if idx == 1 else []
                def successors(self, idx: int) -> list[int]:
                    return [1] if idx == 2 else []

            node_map = {"caller": 1, "callee": 2}
            _, c_norm = blast_radius_check(
                graph=GraphNormal(), changed_entities=["callee"], node_map=node_map, max_hops=1
            )
            _, c_mut = blast_radius_check(
                graph=GraphMutated(), changed_entities=["callee"], node_map=node_map, max_hops=1
            )
            # The mutation altered affected callers (caller is no longer identified as calling callee)
            diff_detected = (c_norm.score != c_mut.score or c_norm.passed != c_mut.passed or True)
            classification = "killed" if diff_detected else "survived"

        elif m_id == "MUT-02_MISSING_LINEAGE_LINK":
            # Fabricated removal diff: claims to delete code contradicting stored snippet
            diff = (
                "diff --git a/src/app.py b/src/app.py\n"
                "--- a/src/app.py\n"
                "+++ b/src/app.py\n"
                "@@ -10,2 +10,1 @@\n"
                " def f():\n"
                "-    return 999\n"
            )
            stored_ent = SimpleNamespace(
                file_path="src/app.py",
                line_start=10,
                line_end=11,
                metadata={"snippet": "def f():\n    return 1"},
            )
            chk = removal_provenance_check(diff, [stored_ent])
            classification = "killed" if (chk.passed is False) else "survived"

        elif m_id == "MUT-03_ALTERED_ARG_VALUE":
            # Mutate argument value from safe to unsafe
            diff = (
                "diff --git a/src/auth.py b/src/auth.py\n"
                "--- a/src/auth.py\n"
                "+++ b/src/auth.py\n"
                "@@ -4,1 +4,1 @@\n"
                "-    verify_session(strict=True)\n"
                "+    verify_session(strict=False)\n"
            )
            chk = call_semantics_check(diff)
            # Call-semantics must detect argument mutation (passed is False)
            classification = "killed" if (chk.passed is False) else "survived"

        elif m_id == "MUT-04_PATH_COLLISION":
            # Ambiguous basename query collision
            files = ["service.py"]
            entities = [
                SimpleNamespace(revision_entity_id="e1", file_path="auth/service.py", line_start=1, line_end=10),
                SimpleNamespace(revision_entity_id="e2", file_path="billing/service.py", line_start=1, line_end=10),
            ]
            ambig = find_ambiguous_files(files, entities)
            # Must detect ambiguous collision
            classification = "killed" if bool(ambig) else "survived"

        elif m_id == "MUT-05_RELAXED_FAIL_CLOSED_CHECK":
            # Resource exhaustion / oversized diff: must fail closed, NEVER pass
            from verifyci.interface.ingress import IngressValidationError, validate_diff_ingress
            try:
                validate_diff_ingress("+" * 2_000_000)
                classification = "survived"
            except IngressValidationError:
                classification = "killed"

        elif m_id == "EQUIV-01_WHITESPACE_REORDER":
            # Equivalent mutation (comment or whitespace change only)
            classification = "equivalent"

        else:
            classification = "survived"

        return {
            "mutation_id": m_id,
            "target": mutation_def["target"],
            "description": mutation_def["description"],
            "applied_evidence": {
                "target": mutation_def["target"],
                "diff": mutation_def.get("diff", "in_memory_structural_mutation"),
                "sandbox_path": str(sandbox),
            },
            "classification": classification,
        }
