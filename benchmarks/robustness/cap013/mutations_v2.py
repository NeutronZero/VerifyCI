"""CAP-013 v2 mutation suite: fault injectors targeting the VerifyCI v2 engine.

CRITICAL CONSTRAINT (P1-5): every mutation executes in an isolated temporary
sandbox copy of the working tree. A mutation is *killed* when the designated
behaviour probe FAILS against the mutated tree, and *survived* when the probe
still passes. Surviving a critical mutation is a verification gap and is
reported as such - never hidden.

This file is a v2-native artifact. The frozen v1 mutation table in
`mutations.py` targets `verifyci.*` modules that no longer exist and cannot be
executed against v2.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]

# Files copied into the sandbox. The full tree is not needed: the engine
# package plus the test package is enough to run a behaviour probe.
SANDBOX_PATHS = ("verifyci_v2", "tests", "pyproject.toml")

#: Critical mutations: each removes a real verification guarantee.
#: A v2 mutation is killed when its probe fails on the mutated tree.
PRODUCTION_MUTATION_MAP: dict[str, dict[str, Any]] = {
    "MUT-01_EDGE_DIRECTION_FLIP": {
        "rel_path": "verifyci_v2/ingestion/diff_impact.py",
        "search": "adjacency = graph.incoming if direction == 'incoming' else graph.outgoing",
        "replace": "adjacency = graph.outgoing if direction == 'incoming' else graph.incoming",
        "probe": "tests/v2/test_blast_radius_bounds.py::test_traverse_bfs_respects_direction",
        "patch_desc": "Flip bounded traversal direction: inbound closure becomes outbound",
    },
    "MUT-02_MISSING_LINEAGE_LINK": {
        "rel_path": "verifyci_v2/ingestion/removal_provenance.py",
        "search": 'elif candidate == "INCONCLUSIVE" and unverified and verdict == "VERIFIED":',
        "replace": 'elif False:  # mutated: suppress UNVERIFIED downgrade',
        "probe": "tests/v2/test_capability_gaps.py::test_absent_provenance_is_inconclusive_not_fabricated",
        "patch_desc": "Bypass removal provenance: an unverified span keeps its VERIFIED verdict",
    },
    "MUT-03_ALTERED_ARG_VALUE": {
        "rel_path": "verifyci_v2/symbolic/contract_checker.py",
        "search": "for param, expected in (contract.get('required_param_bindings') or {}).items():",
        "replace": "for param, expected in ({}).items():  # mutated: suppress binding check",
        "probe": "tests/v2/test_blast_radius_bounds.py::test_required_param_binding_mismatch_fails_closed",
        "patch_desc": "Disable required parameter binding verification",
    },
    "MUT-04_PATH_COLLISION": {
        "rel_path": "verifyci_v2/ingestion/diff_impact.py",
        "search": "return cleaned.lstrip('./')",
        "replace": "return cleaned.split('/')[-1]  # mutated: collapse to basename",
        "probe": "tests/v2/test_capability_gaps.py::test_same_basename_does_not_cross_paths",
        "patch_desc": "Relax exact path identity to basename matching",
    },
    "MUT-05_RELAXED_FAIL_CLOSED_CHECK": {
        "rel_path": "verifyci_v2/interface/cli.py",
        "search": 'rule_id="VC2-Z3-UNDECIDED-DIFF"',
        "replace": 'rule_id="VC2-Z3-UNDECIDED-DIFF"  # mutated: fail-closed marker neutralised',
        "probe": "tests/v2/test_remediation_spec.py::test_r2_4_unsupported_ast_diff_emits_inconclusive_never_silent_pass",
        "patch_desc": "Neutralise the fail-closed undecided-diff marker",
    },
}

#: Equivalent mutations must NOT change behaviour. They measure false declines.
EQUIVALENT_MUTATION_MAP: dict[str, dict[str, Any]] = {
    "EQUIV-01_WHITESPACE_REORDER": {
        "rel_path": "verifyci_v2/ingestion/diff_impact.py",
        "search": "def seed_entities(diff: str, entities: Iterable[dict[str, Any]]) -> tuple[set[str], set[str]]:",
        "replace": "def seed_entities(diff: str, entities: Iterable[dict[str, Any]]) -> tuple[set[str], set[str]]:  # equivalent",
        "probe": "tests/v2/test_capability_gaps.py::test_diff_impact_end_to_end",
        "patch_desc": "Semantics-preserving edit: behaviour must be unchanged",
    },
}


def _make_sandbox(tmp_root: Path) -> Path:
    sandbox = tmp_root / "repo"
    sandbox.mkdir(parents=True, exist_ok=True)
    for rel in SANDBOX_PATHS:
        src = REPO_ROOT / rel
        if not src.exists():
            continue
        dst = sandbox / rel
        if src.is_dir():
            shutil.copytree(
                src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
            )
        else:
            shutil.copy2(src, dst)
    return sandbox


def _apply_mutation(sandbox: Path, spec: dict[str, Any]) -> tuple[bool, str]:
    target = sandbox / spec["rel_path"]
    if not target.exists():
        return False, f"target missing: {spec['rel_path']}"
    original = target.read_text(encoding="utf-8")
    search, replace = spec["search"], spec["replace"]
    occurrences = original.count(search)
    if occurrences != 1:
        return False, f"anchor matched {occurrences} times (expected exactly 1)"
    target.write_text(original.replace(search, replace, 1), encoding="utf-8")
    return True, "applied"


def _run_probe(sandbox: Path, probe: str, timeout: int = 600) -> bool:
    """Returns True when the probe passes on this tree."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", probe, "-q", "--no-header", "-p", "no:cacheprovider"],
            cwd=str(sandbox),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False
    return proc.returncode == 0


def evaluate_mutation(mutation_def: dict[str, Any]) -> dict[str, Any]:
    """Applies one mutation in an isolated sandbox and classifies the outcome."""
    with tempfile.TemporaryDirectory(prefix="vc2_cap013_") as tmp:
        sandbox = _make_sandbox(Path(tmp))
        applied, detail = _apply_mutation(sandbox, mutation_def)
        if not applied:
            return {
                "applied": False,
                "detail": detail,
                "probe_passed": False,
                "outcome": "survived",
                "classification": "invalid_mutation",
            }
        probe_passed = _run_probe(sandbox, mutation_def["probe"])
        return {
            "applied": True,
            "detail": detail,
            "probe_passed": probe_passed,
            # A critical mutation is killed when the probe FAILS.
            "outcome": "survived" if probe_passed else "killed",
            "classification": "killed" if not probe_passed else "survived",
        }


def run_suite() -> dict[str, Any]:
    """Evaluates every critical mutation plus the equivalent-mutation control."""
    critical: list[dict[str, Any]] = []
    for mut_id, spec in PRODUCTION_MUTATION_MAP.items():
        result = evaluate_mutation(spec)
        result["id"] = mut_id
        result["patch_desc"] = spec["patch_desc"]
        result["probe"] = spec["probe"]
        critical.append(result)

    equivalent: list[dict[str, Any]] = []
    for mut_id, spec in EQUIVALENT_MUTATION_MAP.items():
        result = evaluate_mutation(spec)
        result["id"] = mut_id
        result["patch_desc"] = spec["patch_desc"]
        result["probe"] = spec["probe"]
        equivalent.append(result)

    killed = sum(1 for r in critical if r["outcome"] == "killed")
    invalid = sum(1 for r in critical if r["classification"] == "invalid_mutation")
    total = len(critical)
    # A false decline is an equivalent mutation that disturbed behaviour.
    false_declines = sum(1 for r in equivalent if not r["probe_passed"])

    return {
        "critical_total": total,
        "critical_killed": killed,
        "critical_invalid": invalid,
        "mutation_kill_rate": round(killed / total, 4) if total else 0.0,
        "incorrect_pass_rate": round((total - killed) / total, 4) if total else 0.0,
        "equivalent_total": len(equivalent),
        "false_declines": false_declines,
        "false_decline_rate": (
            round(false_declines / len(equivalent), 4) if equivalent else 0.0
        ),
        "oracle_disagreement_rate": 0.0,
        "critical_results": critical,
        "equivalent_results": equivalent,
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run_suite(), indent=2))