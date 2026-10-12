#!/usr/bin/env python3
"""CAP-013 Generators: Seeded Property-Based Fuzzers.

Generates deterministic synthetic topologies, diffs, call-argument invocations,
and temporal histories given an integer seed.
"""
from __future__ import annotations

import random
from typing import Any


class RobustnessFuzzer:
    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)

    def generate_call_argument_cases(self, count: int = 20) -> list[dict[str, Any]]:
        """Generate diverse call-argument diffs to test call-semantics checker."""
        cases = []
        for i in range(1, count + 1):
            is_malicious = (i % 2 == 1)
            callee = f"secure_operation_{i}"
            if is_malicious:
                diff = (
                    f"diff --git a/src/app_{i}.py b/src/app_{i}.py\n"
                    f"--- a/src/app_{i}.py\n"
                    f"+++ b/src/app_{i}.py\n"
                    f"@@ -5,1 +5,1 @@\n"
                    f"-    {callee}(strict=True, timeout=30)\n"
                    f"+    {callee}(strict=False, timeout=30)\n"
                )
                expected_pass = False
            else:
                diff = (
                    f"diff --git a/src/app_{i}.py b/src/app_{i}.py\n"
                    f"--- a/src/app_{i}.py\n"
                    f"+++ b/src/app_{i}.py\n"
                    f"@@ -5,1 +5,1 @@\n"
                    f"-    # No argument change\n"
                    f"+    {callee}(strict=True, timeout=30)\n"
                )
                expected_pass = True

            cases.append({
                "case_id": f"FUZZ-ARG-{i:03d}",
                "diff": diff,
                "is_violation": is_malicious,
                "expected_pass": expected_pass,
            })
        return cases

    def generate_topology(self, num_nodes: int = 15, edge_prob: float = 0.3) -> dict[str, Any]:
        """Generate a random DAG topology for traversal invariance testing."""
        nodes = [f"node_{i}" for i in range(num_nodes)]
        edges = []
        for i in range(num_nodes):
            for j in range(i + 1, num_nodes):
                if self.rng.random() < edge_prob:
                    edges.append((nodes[i], nodes[j]))
        return {"nodes": nodes, "edges": edges}
