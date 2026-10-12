"""CAP-009: End-to-End Diff-to-Impact Correctness Benchmark Test Suite.

Guards:
- Cryptographic freeze hashes for CAP-009 corpus and labels
- Clean-room oracle independence (no diffmap imports in author_cap009.py)
- Zero false passes on critical adversarial cases (rename-plus-same-basename collision)
- Precision and recall recomputed canonically from per-case rows
- Provenance binding check in results.json
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
CORPUS_DIR = REPO_ROOT / "benchmarks" / "diff_impact_corpus" / "cap009"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_cap009_freeze_pins():
    cfg_file = CORPUS_DIR / "config.json"
    cases_file = CORPUS_DIR / "cases.jsonl"
    labels_file = CORPUS_DIR / "labels.jsonl"
    corpus_sha_file = CORPUS_DIR / "CORPUS_SHA256"
    label_sha_file = CORPUS_DIR / "LABEL_SHA256"

    assert cfg_file.exists(), "CAP-009 config.json missing"
    assert cases_file.exists(), "CAP-009 cases.jsonl missing"
    assert labels_file.exists(), "CAP-009 labels.jsonl missing"
    assert corpus_sha_file.exists(), "CAP-009 CORPUS_SHA256 missing"
    assert label_sha_file.exists(), "CAP-009 LABEL_SHA256 missing"

    cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
    c_hash = _sha256(cases_file)
    l_hash = _sha256(labels_file)

    assert c_hash == cfg["corpus_sha256"], f"Corpus SHA-256 drift: {c_hash} != {cfg['corpus_sha256']}"
    assert l_hash == cfg["label_sha256"], f"Label SHA-256 drift: {l_hash} != {cfg['label_sha256']}"
    assert corpus_sha_file.read_text(encoding="utf-8").strip() == c_hash
    assert label_sha_file.read_text(encoding="utf-8").strip() == l_hash


def test_cap009_oracle_independence_static_audit():
    author_file = CORPUS_DIR / "author_cap009.py"
    assert author_file.exists(), "author_cap009.py missing"
    code = author_file.read_text(encoding="utf-8")
    assert "verifyci.verification.diffmap" not in code, (
        "Ground-truth independence violation: author_cap009 imports diffmap"
    )
    assert "seed_entities_for_diff" not in code, (
        "Ground-truth independence violation: author_cap009 references production seeder"
    )


def test_cap009_results_canonical_recomputation():
    from benchmarks.diff_impact_corpus.cap009.measure_cap009 import run_cap009

    cases_file = CORPUS_DIR / "cases.jsonl"
    labels_file = CORPUS_DIR / "labels.jsonl"
    results_file = CORPUS_DIR / "results.json"

    assert results_file.exists(), "results.json missing"
    data = json.loads(results_file.read_text(encoding="utf-8"))
    cfg = json.loads((CORPUS_DIR / "config.json").read_text(encoding="utf-8"))

    # Verify provenance binding
    assert "provenance" in data, "results.json missing provenance block"
    prov = data["provenance"]
    assert "git_commit" in prov
    assert "git_dirty" in prov
    assert "harness_sha256" in prov
    assert "oracle_sha256" in prov
    assert "config_sha256" in prov
    assert "python_version" in prov
    assert "platform" in prov

    # Recompute metrics from canonical rows
    rows = data["cases"]
    assert len(rows) == cfg["case_count"]
    assert len({r["case_id"] for r in rows}) == cfg["case_count"]
    assert len(rows) >= 200, f"Corpus minimum >= 200 not met: {len(rows)}"

    # Recompute aggregate metrics from per-case rows
    rep_rows = [r for r in rows if not r.get("is_critical_adversarial", False)]
    adv_rows = [r for r in rows if r.get("is_critical_adversarial", False)]

    # Critical adversarial gate: zero false passes
    adv_false_passes = [r for r in adv_rows if r.get("false_pass", False)]
    assert len(adv_false_passes) == 0, f"Critical adversarial false passes: {adv_false_passes}"

    # Representative slice precision and recall >= 95%
    total_seed_tp = sum(r["seed_tp"] for r in rep_rows)
    total_seed_fp = sum(r["seed_fp"] for r in rep_rows)
    total_seed_fn = sum(r["seed_fn"] for r in rep_rows)

    seed_p = total_seed_tp / max(1, total_seed_tp + total_seed_fp)
    seed_r = total_seed_tp / max(1, total_seed_tp + total_seed_fn)
    assert seed_p >= 0.95, f"Seed precision under 95%: {seed_p:.4f}"
    assert seed_r >= 0.95, f"Seed recall under 95%: {seed_r:.4f}"

    total_impact_tp = sum(r["impact_tp"] for r in rep_rows)
    total_impact_fp = sum(r["impact_fp"] for r in rep_rows)
    total_impact_fn = sum(r["impact_fn"] for r in rep_rows)

    impact_p = total_impact_tp / max(1, total_impact_tp + total_impact_fp)
    impact_r = total_impact_tp / max(1, total_impact_tp + total_impact_fn)
    assert impact_p >= 0.95, f"Impact precision under 95%: {impact_p:.4f}"
    assert impact_r >= 0.95, f"Impact recall under 95%: {impact_r:.4f}"

    # Verify run_cap009 interface return keys
    res = run_cap009(str(cases_file), str(labels_file))
    expected_keys = {
        "seed_precision",
        "seed_recall",
        "impact_precision",
        "impact_recall",
        "empty_seed_rate",
        "fp_impact_rate",
        "p95_ms",
    }
    assert expected_keys.issubset(res.keys()), f"Missing keys in run_cap009 result: {expected_keys - set(res.keys())}"
