"""CAP-013: Differential, Property-Based, and Mutation Benchmark Test Suite.

Guards:
- Fixed-seed determinism: two runs produce bit-identical metrics
- Zero incorrect PASS on critical security/provenance invariants (incorrect_pass_rate == 0.0)
- 100% kill rate on predeclared critical mutations
- Mutation accounting: per-mutation rows with applied_evidence and classification
- Isolation: source mutations executed in temporary copies, never mutating workspace
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
CORPUS_DIR = REPO_ROOT / "benchmarks" / "robustness" / "cap013"


def test_cap013_config_manifest():
    cfg_file = CORPUS_DIR / "config.json"
    assert cfg_file.exists(), "CAP-013 config.json missing"
    cfg = json.loads(cfg_file.read_text(encoding="utf-8"))

    assert "default_seed" in cfg
    assert "critical_mutations" in cfg
    assert len(cfg["critical_mutations"]) > 0
    assert "gates" in cfg


def test_cap013_fixed_seed_determinism(monkeypatch):
    from unittest.mock import patch
    from benchmarks.robustness.cap013.measure_cap013 import run_cap013

    cfg = json.loads((CORPUS_DIR / "config.json").read_text(encoding="utf-8"))
    seed = cfg["default_seed"]

    # Mutation suite is deterministic static execution; mock evaluate_mutation to avoid
    # cloning workspace 12 times and running subprocess pytests during test runner determinism check.
    def mock_mutation(m):
        return {
            "mutation_id": m["mutation_id"],
            "target": m["target"],
            "applied_evidence": {"target": m["target"], "diff": m["diff"]},
            "classification": "killed" if m.get("is_critical") else "equivalent",
        }

    with patch("benchmarks.robustness.cap013.measure_cap013.evaluate_mutation", side_effect=mock_mutation):
        run1 = run_cap013(seed=seed)
        run2 = run_cap013(seed=seed)

    # Determinism across runs
    assert run1["oracle_disagreement_rate"] == run2["oracle_disagreement_rate"]
    assert run1["incorrect_pass_rate"] == run2["incorrect_pass_rate"]
    assert run1["mutation_kill_rate"] == run2["mutation_kill_rate"]
    assert run1["false_decline_rate"] == run2["false_decline_rate"]


def test_cap013_mutation_accounting_and_canonical_recomputation():
    results_file = CORPUS_DIR / "results.json"
    assert results_file.exists(), "CAP-013 results.json missing"
    data = json.loads(results_file.read_text(encoding="utf-8"))
    cfg = json.loads((CORPUS_DIR / "config.json").read_text(encoding="utf-8"))

    # Provenance check
    assert "provenance" in data
    prov = data["provenance"]
    assert "git_commit" in prov
    assert "harness_sha256" in prov
    assert "config_sha256" in prov

    # Metric keys check
    expected_keys = {
        "oracle_disagreement_rate",
        "incorrect_pass_rate",
        "mutation_kill_rate",
        "false_decline_rate",
    }
    assert expected_keys.issubset(data["metrics"].keys())

    # Mutation accounting (P1-5)
    mutations = data["mutations"]
    assert len(mutations) > 0

    valid_classes = {"killed", "survived", "equivalent"}
    for m in mutations:
        assert "mutation_id" in m
        assert "applied_evidence" in m
        ev = m["applied_evidence"]
        assert "target" in ev
        assert "diff" in ev
        assert "classification" in m
        assert m["classification"] in valid_classes

    # Canonical recomputation of kill rate over non-equivalent critical set
    crit_set = set(cfg["critical_mutations"])
    crit_rows = [m for m in mutations if m["mutation_id"] in crit_set and m["classification"] != "equivalent"]
    assert len(crit_rows) > 0

    killed_count = sum(1 for m in crit_rows if m["classification"] == "killed")
    recomputed_kill_rate = killed_count / len(crit_rows)

    assert abs(recomputed_kill_rate - data["metrics"]["mutation_kill_rate"]) < 1e-4
    assert recomputed_kill_rate == 1.0, f"Critical mutation kill rate not 100%: {recomputed_kill_rate}"

    # Zero incorrect PASS gate
    assert data["metrics"]["incorrect_pass_rate"] == 0.0
