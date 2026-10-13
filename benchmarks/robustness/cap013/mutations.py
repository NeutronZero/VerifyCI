#!/usr/bin/env python3
"""CAP-013 Mutation Suite: Fault Injectors and Mutation Accounting.

Implements critical and equivalent mutations against VerifyCI verification engines.
CRITICAL CONSTRAINT (P1-5):
Every mutation executes in an isolated temporary sandbox.
Results report per-mutation evidence (target, diff, outcome, classification: killed/survived/equivalent).
"""
from __future__ import annotations

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
        "replace": "max_chars: int = 100_000_000",
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
        # 1. Copy production verifyci source tree, test suite, and configuration into isolated sandbox
        shutil.copytree(REPO_ROOT / "verifyci", sandbox / "verifyci")
        shutil.copytree(REPO_ROOT / "tests", sandbox / "tests")
        shutil.copy(REPO_ROOT / "pyproject.toml", sandbox / "pyproject.toml")

        # 2. Apply the declared production source mutation
        target_file = sandbox / spec["rel_path"]
        orig_content = target_file.read_text(encoding="utf-8")
        if spec["search"] not in orig_content:
            raise RuntimeError(f"Target pattern {spec['search']!r} not found in {spec['rel_path']}")

        mutated_content = orig_content.replace(spec["search"], spec["replace"], 1)
        target_file.write_text(mutated_content, encoding="utf-8")

        # 3. Execute relevant regression tests against mutated production source entirely within sandbox
        runner_script = sandbox / "_run_test.py"
        runner_code = (
            "import sys, os, pytest, verifyci\n"
            "from pathlib import Path\n"
            "sb = Path(__file__).resolve().parent\n"
            "v_path = Path(verifyci.__file__).resolve()\n"
            "print(f'VERIFYCI_LOCATION:{v_path}')\n"
            "if not str(v_path).startswith(str(sb)):\n"
            "    print(f'ERROR: verifyci loaded outside sandbox: {v_path}', file=sys.stderr)\n"
            "    sys.exit(99)\n"
            f"args = {spec['test_args']!r}\n"
            "exit_code = pytest.main(args)\n"
            "sys.exit(int(exit_code))\n"
        )
        runner_script.write_text(runner_code, encoding="utf-8")

        proc = subprocess.run(
            [sys.executable, str(runner_script)],
            cwd=str(sandbox),
            capture_output=True,
            text=True,
        )

        first_line = ""
        for line in (proc.stdout or "").splitlines():
            if line.startswith("VERIFYCI_LOCATION:"):
                first_line = line
                break

        stdout_summary = ""
        for line in reversed((proc.stdout or "").splitlines()):
            if "failed" in line or "passed" in line or "error" in line:
                stdout_summary = line.strip()
                break

        # 4. Classify outcome based on observed test execution and exit status
        # Behavioral classification:
        # - EQUIV: passes suite (exit 0) -> equivalent, fails suite -> killed.
        # - Critical mutation: exit code 1 with test failure -> killed.
        # - Critical mutation: exit code 0 -> survived.
        # - Any test/collection error (exit code 2 or error reported) -> invalid_test_error (never killed).
        if m_id.startswith("EQUIV-"):
            classification = "equivalent" if proc.returncode == 0 else "killed"
        else:
            if proc.returncode == 1 and "failed" in stdout_summary.lower() and "error" not in stdout_summary.lower():
                classification = "killed"
            elif proc.returncode == 0:
                classification = "survived"
            else:
                classification = "invalid_test_error"

        return {
            "mutation_id": m_id,
            "target": mutation_def["target"],
            "description": mutation_def["description"],
            "applied_evidence": {
                "target": mutation_def["target"],
                "diff": mutation_def.get("diff", spec["patch_desc"]),
                "target_file": spec["rel_path"],
                "patch_applied": spec["patch_desc"],
                "sandbox_path": "<SANDBOX>",
                "cwd": "<SANDBOX>",
                "verified_module_path": first_line.replace("\\", "/").replace(str(sandbox).replace("\\", "/"), "<SANDBOX>"),
                "test_command": "pytest " + " ".join(spec["test_args"]),
                "exit_status": proc.returncode,
                "stdout_summary": stdout_summary,
                "stderr_summary": (proc.stderr or "").strip().splitlines()[-1] if proc.stderr else "",
            },
            "classification": classification,
        }

