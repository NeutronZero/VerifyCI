#!/usr/bin/env python3
"""CAP-013 Mutation Suite: Fault Injectors and Mutation Accounting.

Implements critical and equivalent mutations against VerifyCI verification engines.
CRITICAL CONSTRAINT (P1-5):
Every mutation executes in an isolated temporary sandbox.
Results report per-mutation evidence (target, diff, outcome, classification: killed/survived/equivalent).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent

# Predeclared production mutation specifications
PRODUCTION_MUTATION_MAP: dict[str, dict[str, Any]] = {
    "MUT-01_EDGE_DIRECTION_FLIP": {
        "rel_path": "verifyci/graph/traverse.py",
        "search": 'direction == "incoming"',
        "replace": 'direction == "outgoing"',
        "test_args": ["tests/evaluation/test_blast_eval.py", "-k", "test_blast_finds_true_caller", "-q"],
        "patch_desc": 'Flip traversal direction: direction == "incoming" -> direction == "outgoing"',
    },
    "MUT-02_MISSING_LINEAGE_LINK": {
        "rel_path": "verifyci/verification/removal.py",
        "search": "verdict = _classify_removed(",
        "replace": 'verdict = "verified"\n            if False: verdict = _classify_removed(',
        "test_args": [
            "tests/verification/test_removal_cap003a.py",
            "-k",
            "test_deep_deletion_catches_fabrication_past_snippet_truncation",
            "-q",
        ],
        "patch_desc": 'Bypass removal provenance: force verdict = "verified"',
    },
    "MUT-03_ALTERED_ARG_VALUE": {
        "rel_path": "verifyci/verification/call_semantics.py",
        "search": "if _is_call_argument_mutation(rc, ac):",
        "replace": "if False:  # mutated: suppress call argument check",
        "test_args": [
            "tests/verification/test_call_semantics_cap004.py",
            "-k",
            "test_cap002_n_s4_falsifier_resolved",
            "-q",
        ],
        "patch_desc": "Disable call argument mutation detector: if False",
    },
    "MUT-04_PATH_COLLISION": {
        "rel_path": "verifyci/verification/diffmap.py",
        "search": "return {f: sorted(paths) for f, paths in hits.items() if len(paths) > 1}",
        "replace": "return {}  # mutated: drop ambiguous collision map",
        "test_args": [
            "tests/verification/test_diffmap.py",
            "-k",
            "test_suffix_ambiguity_flagged_not_silent",
            "-q",
        ],
        "patch_desc": "Suppress path ambiguity detection: return empty collision dict",
    },
    "MUT-05_RELAXED_FAIL_CLOSED_CHECK": {
        "rel_path": "verifyci/interface/ingress.py",
        "search": "max_chars: int = MAX_DIFF_CHARS",
        "replace": "max_chars: int = 100_000_000  # mutated: relax ingress limit",
        "test_args": [
            "tests/interface/test_ingress.py",
            "-k",
            "test_validate_diff_ingress_oversized",
            "-q",
        ],
        "patch_desc": "Relax ingress size limit: 1M -> 100M chars",
    },
    "EQUIV-01_WHITESPACE_REORDER": {
        "rel_path": "verifyci/interface/limits.py",
        "search": "# Input complexity limits (single-pass diff pre-scan)",
        "replace": "# Input complexity limits (single-pass diff pre-scan) - harmless refactor comment",
        "test_args": [
            "tests/interface/test_ingress.py",
            "-k",
            "test_validate_diff_ingress_valid",
            "-q",
        ],
        "patch_desc": "Benign documentation comment modification",
    },
}


def evaluate_mutation(mutation_def: dict[str, Any]) -> dict[str, Any]:
    """Execute a single mutation in an isolated temporary copy and classify."""
    m_id = mutation_def["mutation_id"]

    if m_id not in PRODUCTION_MUTATION_MAP:
        raise ValueError(f"Unknown mutation id: {m_id}")

    spec = PRODUCTION_MUTATION_MAP[m_id]

    with tempfile.TemporaryDirectory() as tmp_str:
        sandbox = Path(tmp_str)
        # 1. Copy production verifyci source tree into isolated sandbox
        shutil.copytree(REPO_ROOT / "verifyci", sandbox / "verifyci")

        # 2. Apply the declared production source mutation
        target_file = sandbox / spec["rel_path"]
        orig_content = target_file.read_text(encoding="utf-8")
        if spec["search"] not in orig_content:
            raise RuntimeError(f"Target pattern {spec['search']!r} not found in {spec['rel_path']}")

        mutated_content = orig_content.replace(spec["search"], spec["replace"], 1)
        target_file.write_text(mutated_content, encoding="utf-8")

        # 3. Execute relevant regression tests against mutated production source
        # Force sys.path[0] to point to sandbox so mutated modules are imported
        runner_script = sandbox / "_run_test.py"
        repo_abs = str(REPO_ROOT).lower()
        runner_code = (
            "import sys, os, importlib.util, pytest\n"
            f"sandbox_dir = r'{sandbox}'\n"
            f"sys.path = [p for p in sys.path if os.path.abspath(p).lower() != r'{repo_abs}']\n"
            "sys.path.insert(0, sandbox_dir)\n"
            "pkg_init = os.path.join(sandbox_dir, 'verifyci', '__init__.py')\n"
            "pkg_spec = importlib.util.spec_from_file_location('verifyci', pkg_init, submodule_search_locations=[os.path.join(sandbox_dir, 'verifyci')])\n"
            "mod = importlib.util.module_from_spec(pkg_spec)\n"
            "sys.modules['verifyci'] = mod\n"
            "pkg_spec.loader.exec_module(mod)\n"
            f"sys.exit(pytest.main({spec['test_args']!r}))\n"
        )
        runner_script.write_text(runner_code, encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(runner_script)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

        # 4. Classify outcome
        if m_id == "EQUIV-01_WHITESPACE_REORDER":
            classification = "equivalent"
        else:
            # Critical mutation killed if regression tests fail (exit code != 0)
            classification = "killed" if proc.returncode != 0 else "survived"

        return {
            "mutation_id": m_id,
            "target": mutation_def["target"],
            "description": mutation_def["description"],
            "applied_evidence": {
                "target": mutation_def["target"],
                "diff": mutation_def.get("diff", spec["patch_desc"]),
                "target_file": spec["rel_path"],
                "patch_applied": spec["patch_desc"],
                "sandbox_path": str(sandbox),
                "test_command": "pytest " + " ".join(spec["test_args"]),
                "exit_status": proc.returncode,
                "stdout_summary": (proc.stdout or "").strip().splitlines()[-1] if proc.stdout else "",
            },
            "classification": classification,
        }
