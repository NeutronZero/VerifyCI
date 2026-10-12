"""CAP-010: Retrieval Generalization and Hard Negatives Benchmark Test Suite.

Guards:
- Cryptographic freeze hashes for CAP-010 corpus and labels
- Held-out repos disjoint from dev repos
- Per-category denominators match labeled query counts
- No-answer queries excluded from nDCG calculation (P0-2)
- Canonical recomputation of aggregate metrics from per-query rows
- Abstention behavior scored separately (correct_abstention_rate, false_relevant_rate)
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
CORPUS_DIR = REPO_ROOT / "benchmarks" / "retrieval_generalization" / "cap010"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_cap010_freeze_pins_and_manifest():
    cfg_file = CORPUS_DIR / "config.json"
    cases_file = CORPUS_DIR / "cases.jsonl"
    labels_file = CORPUS_DIR / "labels.jsonl"
    corpus_sha_file = CORPUS_DIR / "CORPUS_SHA256"
    label_sha_file = CORPUS_DIR / "LABEL_SHA256"

    assert cfg_file.exists(), "CAP-010 config.json missing"
    assert cases_file.exists(), "CAP-010 cases.jsonl missing"
    assert labels_file.exists(), "CAP-010 labels.jsonl missing"
    assert corpus_sha_file.exists(), "CAP-010 CORPUS_SHA256 missing"
    assert label_sha_file.exists(), "CAP-010 LABEL_SHA256 missing"

    cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
    c_hash = _sha256(cases_file)
    l_hash = _sha256(labels_file)

    assert c_hash == cfg["corpus_sha256"], f"Corpus SHA-256 drift: {c_hash} != {cfg['corpus_sha256']}"
    assert l_hash == cfg["label_sha256"], f"Label SHA-256 drift: {l_hash} != {cfg['label_sha256']}"
    assert corpus_sha_file.read_text(encoding="utf-8").strip() == c_hash
    assert label_sha_file.read_text(encoding="utf-8").strip() == l_hash


def test_cap010_workload_and_repo_disjointness():
    cfg = json.loads((CORPUS_DIR / "config.json").read_text(encoding="utf-8"))

    dev_repos = set(cfg["dev_repos"])
    held_out_repos = set(cfg["held_out_repos"])
    assert dev_repos.isdisjoint(held_out_repos), f"Dev and held-out repos overlap: {dev_repos & held_out_repos}"

    all_repos = dev_repos | held_out_repos
    assert len(all_repos) >= 10, f"Expected >= 10 repos, found {len(all_repos)}"
    assert cfg["doc_count"] >= 1000, f"Expected >= 1000 docs, found {cfg['doc_count']}"
    assert cfg["query_count"] >= 200, f"Expected >= 200 queries, found {cfg['query_count']}"

    labels = [json.loads(line) for line in (CORPUS_DIR / "labels.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(labels) == cfg["query_count"]

    # Category denominators match labeled counts
    cat_counts: dict[str, int] = {}
    for lbl in labels:
        cat = lbl["category"]
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    denom_map = cfg["category_denominators"]
    for cat, count in cat_counts.items():
        assert denom_map[cat] == count, f"Category denominator mismatch for {cat}: {denom_map[cat]} != {count}"


def test_cap010_results_canonical_recomputation():
    from benchmarks.retrieval_generalization.cap010.measure_cap010 import run_cap010

    cases_file = CORPUS_DIR / "cases.jsonl"
    labels_file = CORPUS_DIR / "labels.jsonl"
    results_file = CORPUS_DIR / "results.json"

    assert results_file.exists(), "results.json missing"
    data = json.loads(results_file.read_text(encoding="utf-8"))
    cfg = json.loads((CORPUS_DIR / "config.json").read_text(encoding="utf-8"))

    # Check provenance
    assert "provenance" in data
    prov = data["provenance"]
    assert "git_commit" in prov
    assert "git_dirty" in prov
    assert "harness_sha256" in prov
    assert "oracle_sha256" in prov
    assert "config_sha256" in prov

    queries = data["queries"]
    assert len(queries) == cfg["query_count"]
    assert len({q["qid"] for q in queries}) == cfg["query_count"]

    # Check no-answer queries excluded from nDCG mean
    no_answer_queries = [q for q in queries if q["category"] == "no_relevant_result"]
    answer_queries = [q for q in queries if q["category"] != "no_relevant_result"]

    assert len(no_answer_queries) > 0, "No-relevant-result queries must be present"
    for na_q in no_answer_queries:
        assert na_q["ndcg_at_10"] is None, "No-answer query must have null ndcg_at_10, not 0.0 or a number"

    # Recompute nDCG mean over answer queries only
    recomputed_ndcg = sum(q["ndcg_at_10"] for q in answer_queries) / len(answer_queries)
    assert abs(recomputed_ndcg - data["metrics"]["ndcg_at_10"]) < 1e-4

    # Recompute abstention rates over no_answer queries
    correct_abstentions = sum(1 for q in no_answer_queries if q["abstention_correct"])
    false_relevants = sum(1 for q in no_answer_queries if not q["abstention_correct"])

    recomputed_abstention_rate = correct_abstentions / len(no_answer_queries)
    recomputed_false_rel_rate = false_relevants / len(no_answer_queries)

    assert abs(recomputed_abstention_rate - data["metrics"]["correct_abstention_rate"]) < 1e-4
    assert abs(recomputed_false_rel_rate - data["metrics"]["false_relevant_rate"]) < 1e-4

    # Check run_cap010 interface keys
    res = run_cap010(str(cases_file), str(labels_file))
    expected_keys = {
        "recall_at_5",
        "recall_at_20",
        "ndcg_at_10",
        "mrr",
        "correct_abstention_rate",
        "false_relevant_rate",
        "per_category",
    }
    assert expected_keys.issubset(res.keys())
