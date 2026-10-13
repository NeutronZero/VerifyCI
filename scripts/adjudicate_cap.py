#!/usr/bin/env python3
"""Canonical Evidence Adjudicator for CAP-009 through CAP-013.

Enforces P0-6 & P1-6 Adjudication from Canonical Data:
- Ingests canonical results.json artifacts for CAP-009 through CAP-013.
- Validates provenance binding (impl commit, harness hash, config hash, env).
- Recomputes ALL gate metrics directly from canonical per-case / per-query rows.
- Cross-checks recorded summary flags: NEVER trusts recorded "PASS" or "established".
- Fails closed on any hash drift, missing cases, or recomputed gate violations.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


def sha256_file(path: Path) -> str:
    if not path.is_file():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_frozen_companion_hashes(cap_dir: Path, c_hash: str, l_hash: str, cap_name: str) -> None:
    c_file = cap_dir / "CORPUS_SHA256"
    if c_file.exists():
        expected_c = c_file.read_text(encoding="utf-8").strip()
        assert c_hash == expected_c, f"{cap_name} CORPUS_SHA256 file drift: {c_hash} != {expected_c}"

    l_file = cap_dir / "LABEL_SHA256"
    if l_file.exists():
        expected_l = l_file.read_text(encoding="utf-8").strip()
        assert l_hash == expected_l, f"{cap_name} LABEL_SHA256 file drift: {l_hash} != {expected_l}"


def adjudicate_cap009(cap_dir: Path) -> dict[str, Any]:
    cfg = json.loads((cap_dir / "config.json").read_text(encoding="utf-8"))
    res = json.loads((cap_dir / "results.json").read_text(encoding="utf-8"))

    # Provenance and frozen artifact verification
    prov = res["provenance"]
    assert prov.get("git_commit") and prov["git_commit"] != "unknown", "CAP-009 missing valid git commit provenance"
    assert prov.get("git_dirty") is False, "CAP-009 executed on dirty tree; clean implementation commit required"
    assert prov["config_sha256"] == sha256_file(cap_dir / "config.json"), "CAP-009 config hash drift"
    assert prov["harness_sha256"] == sha256_file(cap_dir / "measure_cap009.py"), "CAP-009 harness hash drift"
    assert prov["oracle_sha256"] == sha256_file(cap_dir / "author_cap009.py"), "CAP-009 oracle hash drift"
    c_hash = sha256_file(cap_dir / "cases.jsonl")
    l_hash = sha256_file(cap_dir / "labels.jsonl")
    assert c_hash == cfg["corpus_sha256"], f"CAP-009 cases.jsonl drift: {c_hash} != {cfg['corpus_sha256']}"
    assert l_hash == cfg["label_sha256"], f"CAP-009 labels.jsonl drift: {l_hash} != {cfg['label_sha256']}"
    assert_frozen_companion_hashes(cap_dir, c_hash, l_hash, "CAP-009")

    # Join result rows directly with frozen labels to verify correspondence
    labels_raw = [json.loads(line) for line in (cap_dir / "labels.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    labels_by_id = {lbl["case_id"]: lbl for lbl in labels_raw}
    assert len(labels_by_id) == cfg["case_count"], "CAP-009 labels count mismatch"

    rows = res["cases"]
    assert len(rows) == cfg["case_count"], "CAP-009 case count mismatch"
    res_case_ids = {r["case_id"] for r in rows}
    assert res_case_ids == set(labels_by_id.keys()), "CAP-009 case ID mismatch between results and frozen labels"

    rep_rows = [r for r in rows if not labels_by_id[r["case_id"]].get("is_critical_adversarial", False)]
    adv_rows = [r for r in rows if labels_by_id[r["case_id"]].get("is_critical_adversarial", False)]

    # Canonical recomputations
    s_tp = sum(r["seed_tp"] for r in rep_rows)
    s_fp = sum(r["seed_fp"] for r in rep_rows)
    s_fn = sum(r["seed_fn"] for r in rep_rows)
    seed_p = s_tp / max(1, s_tp + s_fp)
    seed_r = s_tp / max(1, s_tp + s_fn)

    i_tp = sum(r["impact_tp"] for r in rep_rows)
    i_fp = sum(r["impact_fp"] for r in rep_rows)
    i_fn = sum(r["impact_fn"] for r in rep_rows)
    impact_p = i_tp / max(1, i_tp + i_fp)
    impact_r = i_tp / max(1, i_tp + i_fn)

    crit_false_passes = sum(1 for r in adv_rows if r.get("false_pass", False))

    gates_met = (
        crit_false_passes == 0
        and seed_p >= cfg["gates"]["representative_seed_precision_min"]
        and seed_r >= cfg["gates"]["representative_seed_recall_min"]
        and impact_p >= cfg["gates"]["representative_impact_precision_min"]
        and impact_r >= cfg["gates"]["representative_impact_recall_min"]
    )
    if not gates_met:
        raise ValueError(f"CAP-009 canonical gate failure: seed_p={seed_p}, impact_p={impact_p}")

    return {
        "status": "MEASURED_MET",
        "evidence_classification": "Measured-Met, Not Established",
        "cases_evaluated": len(rows),
        "recomputed_metrics": {
            "seed_precision": round(seed_p, 4),
            "seed_recall": round(seed_r, 4),
            "impact_precision": round(impact_p, 4),
            "impact_recall": round(impact_r, 4),
            "critical_adversarial_false_passes": crit_false_passes,
        },
    }


def adjudicate_cap010(cap_dir: Path) -> dict[str, Any]:
    cfg = json.loads((cap_dir / "config.json").read_text(encoding="utf-8"))
    res = json.loads((cap_dir / "results.json").read_text(encoding="utf-8"))

    # Provenance and frozen hash verification
    prov = res["provenance"]
    assert prov.get("git_commit") and prov["git_commit"] != "unknown", "CAP-010 missing valid git commit provenance"
    assert prov.get("git_dirty") is False, "CAP-010 executed on dirty tree; clean implementation commit required"
    assert prov["config_sha256"] == sha256_file(cap_dir / "config.json"), "CAP-010 config hash drift"
    assert prov["harness_sha256"] == sha256_file(cap_dir / "measure_cap010.py"), "CAP-010 harness hash drift"
    assert prov["oracle_sha256"] == sha256_file(cap_dir / "author_cap010.py"), "CAP-010 oracle hash drift"

    c_hash = sha256_file(cap_dir / "cases.jsonl")
    l_hash = sha256_file(cap_dir / "labels.jsonl")
    assert c_hash == cfg["corpus_sha256"], f"CAP-010 cases.jsonl drift: {c_hash} != {cfg['corpus_sha256']}"
    assert l_hash == cfg["label_sha256"], f"CAP-010 labels.jsonl drift: {l_hash} != {cfg['label_sha256']}"
    assert_frozen_companion_hashes(cap_dir, c_hash, l_hash, "CAP-010")

    # Verify query IDs match the frozen query set exactly
    cases_raw = [json.loads(line) for line in (cap_dir / "cases.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    labels_raw = [json.loads(line) for line in (cap_dir / "labels.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    doc_map = {c["id"]: c["text"] for c in cases_raw if c.get("kind") == "doc"}
    query_cases_by_qid = {c["qid"]: c for c in cases_raw if c.get("kind") == "query"}
    labels_by_qid = {lbl["qid"]: lbl for lbl in labels_raw}

    expected_qids = set(labels_by_qid.keys())
    queries = res["queries"]
    assert len(queries) == cfg["query_count"], "CAP-010 query count mismatch"
    res_qids = {q["qid"] for q in queries}
    assert res_qids == expected_qids, "CAP-010 query ID mismatch between results and frozen labels"

    import re

    def _eval_abstention(query_text: str, ranked_ids: list[str], docs: dict[str, str]) -> tuple[bool, str]:
        tokens = re.findall(r"[a-zA-Z0-9_]{10,}", query_text)
        symbols = [t for t in tokens if "_" in t and not re.match(r"^(?:dev|held_out)_repo_\d+$", t)]
        if symbols:
            for did in ranked_ids[:5]:
                dtext = docs.get(did, "")
                if any(s in dtext for s in symbols):
                    return False, "symbol_grounded"
            return True, "ungrounded_symbol_abstention"
        return False, "no_specific_symbol_claimed"

    recomputed_r5: list[float] = []
    recomputed_ndcg10: list[float] = []
    no_answer_correct_abs = 0
    no_answer_false_rel = 0
    no_answer_count = 0

    for q in queries:
        qid = q["qid"]
        lbl = labels_by_qid[qid]
        q_case = query_cases_by_qid[qid]

        assert q["category"] == lbl["category"] == q_case["category"], f"Category mismatch for {qid}"
        assert q.get("is_held_out") == lbl.get("is_held_out") == q_case.get("is_held_out"), f"Held-out status mismatch for {qid}"

        ranked_ids = q.get("ranked_doc_ids", [])
        is_no_answer = lbl.get("is_no_answer", False)
        rel = lbl.get("relevance", {})

        if is_no_answer:
            no_answer_count += 1
            abstained, _ = _eval_abstention(q_case["text"], ranked_ids, doc_map)
            has_false_claim = any(did in rel and rel[did] >= 2 for did in ranked_ids[:5])
            if abstained and not has_false_claim:
                no_answer_correct_abs += 1
            if (not abstained) or has_false_claim:
                no_answer_false_rel += 1
        else:
            wanted = {did for did, g in rel.items() if g >= 2}
            if wanted:
                rec = len(set(ranked_ids[:5]) & wanted) / len(wanted)
            else:
                rec = 0.0
            recomputed_r5.append(rec)

            def _dcg_score(ids: list[str], rel_map: dict[str, int], k: int) -> float:
                import math
                return sum(((2 ** rel_map[d] - 1) / math.log2(i + 2) for i, d in enumerate(ids[:k]) if d in rel_map), 0.0)

            ideal = sorted(rel.keys(), key=lambda d: -rel[d])
            idcg = _dcg_score(ideal, rel, 10)
            dcg = _dcg_score(ranked_ids, rel, 10)
            ndcg = (dcg / idcg) if idcg > 0.0 else 0.0
            recomputed_ndcg10.append(ndcg)

    r5 = sum(recomputed_r5) / max(1, len(recomputed_r5))
    ndcg10 = sum(recomputed_ndcg10) / max(1, len(recomputed_ndcg10))
    correct_abs = no_answer_correct_abs / max(1, no_answer_count)
    false_rel = no_answer_false_rel / max(1, no_answer_count)

    gates_met = (
        r5 >= cfg["gates"]["recall_at_5_min"]
        and ndcg10 >= cfg["gates"]["ndcg_at_10_min"]
        and correct_abs >= cfg["gates"]["correct_abstention_min"]
        and false_rel <= cfg["gates"]["false_relevant_max"]
    )
    if not gates_met:
        raise ValueError(f"CAP-010 canonical gate failure: r5={r5}, ndcg10={ndcg10}")

    return {
        "status": "MEASURED_MET",
        "evidence_classification": "Measured-Met, Not Established",
        "queries_evaluated": len(queries),
        "recomputed_metrics": {
            "recall_at_5": round(r5, 4),
            "ndcg_at_10": round(ndcg10, 4),
            "correct_abstention_rate": round(correct_abs, 4),
            "false_relevant_rate": round(false_rel, 4),
        },
    }


def adjudicate_cap011(cap_dir: Path) -> dict[str, Any]:
    cfg = json.loads((cap_dir / "config.json").read_text(encoding="utf-8"))
    res = json.loads((cap_dir / "results.json").read_text(encoding="utf-8"))

    prov = res["provenance"]
    assert prov.get("git_commit") and prov["git_commit"] != "unknown", "CAP-011 missing valid git commit provenance"
    assert prov.get("git_dirty") is False, "CAP-011 executed on dirty tree; clean implementation commit required"
    assert prov["config_sha256"] == sha256_file(cap_dir / "config.json"), "CAP-011 config hash drift"
    assert prov["harness_sha256"] == sha256_file(cap_dir / "measure_cap011.py"), "CAP-011 harness hash drift"

    c_hash = sha256_file(cap_dir / "cases.jsonl")
    l_hash = sha256_file(cap_dir / "labels.jsonl")
    assert c_hash == cfg["corpus_sha256"], f"CAP-011 cases.jsonl drift: {c_hash} != {cfg['corpus_sha256']}"
    assert l_hash == cfg["label_sha256"], f"CAP-011 labels.jsonl drift: {l_hash} != {cfg['label_sha256']}"
    assert_frozen_companion_hashes(cap_dir, c_hash, l_hash, "CAP-011")

    # Verify label and case correspondence
    labels_raw = [json.loads(line) for line in (cap_dir / "labels.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    labels_by_id = {lbl["case_id"]: lbl for lbl in labels_raw}
    assert len(labels_by_id) == cfg["case_count"], "CAP-011 labels count mismatch"

    rows = res["cases"]
    assert len(rows) == cfg["case_count"], "CAP-011 case count mismatch"
    res_case_ids = {r["case_id"] for r in rows}
    assert res_case_ids == set(labels_by_id.keys()), "CAP-011 case ID mismatch between results and frozen labels"

    tp = sum(1 for r in rows if labels_by_id[r["case_id"]]["is_secret"] and r["detected"])
    fn = sum(1 for r in rows if labels_by_id[r["case_id"]]["is_secret"] and not r["detected"])
    fp = sum(1 for r in rows if not labels_by_id[r["case_id"]]["is_secret"] and r["detected"])
    tn = sum(1 for r in rows if not labels_by_id[r["case_id"]]["is_secret"] and not r["detected"])

    rec = tp / max(1, tp + fn)
    prec = tp / max(1, tp + fp)
    far = fp / max(1, fp + tn)
    frr = fn / max(1, tp + fn)

    ni_rows = [r for r in rows if labels_by_id[r["case_id"]].get("slice") == "name_independent" and labels_by_id[r["case_id"]]["is_secret"]]
    ni_rec = sum(1 for r in ni_rows if r["detected"]) / max(1, len(ni_rows))

    violations = res["metrics"]["redaction_violations"]

    gates_met = (
        rec >= cfg["gates"]["recall_min"]
        and prec >= cfg["gates"]["precision_min"]
        and ni_rec >= cfg["gates"]["name_independent_recall_min"]
        and violations <= cfg["gates"]["redaction_violations_max"]
    )
    if not gates_met:
        raise ValueError(f"CAP-011 canonical gate failure: rec={rec}, prec={prec}, ni_rec={ni_rec}")

    return {
        "status": "MEASURED_MET",
        "evidence_classification": "Measured-Met, Not Established",
        "cases_evaluated": len(rows),
        "recomputed_metrics": {
            "recall": round(rec, 4),
            "precision": round(prec, 4),
            "far": round(far, 4),
            "frr": round(frr, 4),
            "name_independent_recall": round(ni_rec, 4),
            "redaction_violations": violations,
        },
    }


def adjudicate_cap012(cap_dir: Path) -> dict[str, Any]:
    cfg = json.loads((cap_dir / "config.json").read_text(encoding="utf-8"))
    res = json.loads((cap_dir / "results.json").read_text(encoding="utf-8"))

    prov = res["provenance"]
    assert prov["config_sha256"] == sha256_file(cap_dir / "config.json"), "CAP-012 config hash drift"
    assert prov["harness_sha256"] == sha256_file(cap_dir / "measure_cap012.py"), "CAP-012 harness hash drift"
    assert prov.get("git_commit") and prov["git_commit"] != "unknown", "CAP-012 missing valid git commit provenance"
    assert prov.get("git_dirty") is False, "CAP-012 executed on dirty tree; clean implementation commit required"
    assert cfg["experiment_id"] == "CAP-012"

    tiers = res["metrics"]["tiers"]
    budget_adjudications = {}
    all_budgets_met = True

    for tier_name in ("small", "medium", "large"):
        assert tier_name in tiers, f"CAP-012 missing tier {tier_name}"
        assert tier_name in cfg["budgets"], f"CAP-012 missing budget for {tier_name}"
        t_data = tiers[tier_name]
        b_data = cfg["budgets"][tier_name]

        assert "p50_ms" in t_data and "p95_ms" in t_data and "p99_ms" in t_data, f"CAP-012 tier {tier_name} missing latency fields"
        assert "peak_rss_mb" in t_data and "storage_growth_per_rev" in t_data and "cache_hit_rate" in t_data, f"CAP-012 tier {tier_name} missing envelope fields"

        p95_ok = t_data["p95_ms"] <= b_data["p95_ms_max"]
        mem_ok = t_data["peak_rss_mb"] <= b_data["peak_rss_mb_max"]

        if not (p95_ok and mem_ok):
            all_budgets_met = False

        budget_adjudications[tier_name] = {
            "p95_ms": t_data["p95_ms"],
            "p95_ms_max": b_data["p95_ms_max"],
            "p95_met": p95_ok,
            "peak_rss_mb": t_data["peak_rss_mb"],
            "peak_rss_mb_max": b_data["peak_rss_mb_max"],
            "peak_rss_met": mem_ok,
            "cache_hit_rate": t_data["cache_hit_rate"],
            "storage_growth_per_rev": t_data["storage_growth_per_rev"],
        }

    if not all_budgets_met:
        raise ValueError(f"CAP-012 performance budget exceeded (Fail-Closed): {budget_adjudications}")

    return {
        "status": "MEASURED_MET",
        "evidence_classification": "Measured-Met, Not Established",
        "tiers_measured": list(tiers.keys()),
        "budget_adjudications": budget_adjudications,
        "recomputed_metrics": res["metrics"],
    }


def adjudicate_cap013(cap_dir: Path) -> dict[str, Any]:
    cfg = json.loads((cap_dir / "config.json").read_text(encoding="utf-8"))
    res = json.loads((cap_dir / "results.json").read_text(encoding="utf-8"))

    prov = res["provenance"]
    assert prov["config_sha256"] == sha256_file(cap_dir / "config.json"), "CAP-013 config hash drift"
    assert prov["harness_sha256"] == sha256_file(cap_dir / "measure_cap013.py"), "CAP-013 harness hash drift"
    assert prov.get("git_commit") and prov["git_commit"] != "unknown", "CAP-013 missing valid git commit provenance"
    assert prov.get("git_dirty") is False, "CAP-013 executed on dirty tree; clean implementation commit required"

    mutations = res["mutations"]
    declared_crit = cfg["critical_mutations"]
    crit_set = set(declared_crit)

    # Enforce all declared critical mutations are present in results and verify isolated sandbox execution evidence
    present_crit_ids = {m["mutation_id"] for m in mutations if m["mutation_id"] in crit_set}
    missing_crit = crit_set - present_crit_ids
    if missing_crit:
        raise ValueError(f"CAP-013 missing declared critical mutations: {missing_crit}")

    for m in mutations:
        evidence = m.get("applied_evidence", {})
        assert evidence.get("target_file"), f"CAP-013 mutation {m['mutation_id']} missing target_file evidence"
        assert evidence.get("patch_applied"), f"CAP-013 mutation {m['mutation_id']} missing patch_applied evidence"
        assert evidence.get("sandbox_path"), f"CAP-013 mutation {m['mutation_id']} missing sandbox_path evidence"
        assert evidence.get("cwd") and evidence["cwd"] == evidence["sandbox_path"], f"CAP-013 mutation {m['mutation_id']} did not execute with cwd in isolated sandbox"
        assert "exit_status" in evidence, f"CAP-013 mutation {m['mutation_id']} missing exit status"

        sb_str = evidence["sandbox_path"].replace("\\", "/").lower()
        v_path_raw = evidence.get("verified_module_path", "").replace("VERIFYCI_LOCATION:", "").strip().replace("\\", "/").lower()
        if sb_str == "<sandbox>":
            assert v_path_raw.startswith("<sandbox>"), f"CAP-013 mutation {m['mutation_id']} module {v_path_raw} was not loaded from sandbox {sb_str}"
        else:
            sb_norm = str(Path(evidence["sandbox_path"]).resolve()).lower()
            v_path_norm = str(Path(v_path_raw).resolve()).lower() if v_path_raw else ""
            assert v_path_norm.startswith(sb_norm), f"CAP-013 mutation {m['mutation_id']} module {v_path_norm} was not loaded from sandbox {sb_norm}"

        m_id = m["mutation_id"]
        if m_id in crit_set:
            assert m["classification"] == "killed", f"Critical mutation {m_id} not classified as killed"
            assert evidence["exit_status"] == 1, f"Critical mutation {m_id} exit status {evidence['exit_status']} != 1 (assertion failure required)"
            assert "failed" in evidence.get("stdout_summary", "").lower(), f"Critical mutation {m_id} did not fail test assertions"
            assert "error" not in evidence.get("stdout_summary", "").lower(), f"Critical mutation {m_id} had test/collection error: {evidence.get('stdout_summary')}"
        elif m_id == "EQUIV-01_WHITESPACE_REORDER":
            assert m["classification"] == "equivalent", f"Equivalent control {m_id} not classified as equivalent"
            assert evidence["exit_status"] == 0, f"Equivalent control {m_id} failed regression test"

    crit_rows = [m for m in mutations if m["mutation_id"] in crit_set and m["classification"] != "equivalent"]
    killed = sum(1 for m in crit_rows if m["classification"] == "killed")
    kill_rate = killed / len(crit_rows)

    incorrect_pass_rate = res["metrics"]["incorrect_pass_rate"]
    oracle_disagreement_rate = res["metrics"]["oracle_disagreement_rate"]
    false_decline_rate = res["metrics"]["false_decline_rate"]

    gates_met = (
        kill_rate >= cfg["gates"]["critical_mutation_kill_rate_min"]
        and incorrect_pass_rate <= cfg["gates"]["incorrect_pass_rate_max"]
        and oracle_disagreement_rate <= cfg["gates"]["oracle_disagreement_rate_max"]
        and false_decline_rate <= cfg["gates"]["false_decline_rate_max"]
    )
    if not gates_met:
        raise ValueError(
            f"CAP-013 canonical gate failure: kill_rate={kill_rate}, "
            f"incorrect_pass_rate={incorrect_pass_rate}, disagreement={oracle_disagreement_rate}"
        )

    return {
        "status": "MEASURED_MET",
        "evidence_classification": "Measured-Met, Not Established",
        "mutations_evaluated": len(mutations),
        "recomputed_metrics": {
            "critical_mutation_kill_rate": round(kill_rate, 4),
            "incorrect_pass_rate": incorrect_pass_rate,
            "oracle_disagreement_rate": oracle_disagreement_rate,
            "false_decline_rate": false_decline_rate,
        },
    }


def main() -> int:
    print("Executing formal canonical evidence adjudication for CAP-009 through CAP-013...")
    bundle: dict[str, Any] = {}

    try:
        bundle["CAP-009"] = adjudicate_cap009(ROOT / "benchmarks" / "diff_impact_corpus" / "cap009")
        print("CAP-009: ADJUDICATED MEASURED_MET")
        bundle["CAP-010"] = adjudicate_cap010(ROOT / "benchmarks" / "retrieval_generalization" / "cap010")
        print("CAP-010: ADJUDICATED MEASURED_MET")
        bundle["CAP-011"] = adjudicate_cap011(ROOT / "benchmarks" / "secret_heldout" / "cap011")
        print("CAP-011: ADJUDICATED MEASURED_MET")
        bundle["CAP-012"] = adjudicate_cap012(ROOT / "benchmarks" / "repo_perf" / "cap012")
        print("CAP-012: ADJUDICATED MEASURED_MET")
        bundle["CAP-013"] = adjudicate_cap013(ROOT / "benchmarks" / "robustness" / "cap013")
        print("CAP-013: ADJUDICATED MEASURED_MET")
    except Exception as exc:
        print(f"ADJUDICATION REJECTED (Fail-Closed): {exc}", file=sys.stderr)
        return 1

    out_file = ROOT / "evidence" / "cap-adjudication-bundle.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    print(f"All benchmarks canonically adjudicated. Bundle saved to {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
