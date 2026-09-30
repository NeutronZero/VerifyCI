"""C2 measurement: blast-radius coverage vs frozen topology truth.

Detection path is exactly what the gate runs: parse_diff_files ->
seed_entities_for_diff -> compute_blast_radius (2 hops, CALL_FLOW_TYPES,
seed excluded). Nothing is tuned; misses are reported.

Per case: expected set (frozen topology), detected set
(affected_callers | affected_callees mapped to names), TP/FN/FP, recall.
Coverage = mean recall over cases with non-empty expected; a secondary
coverage over `mode=seeded` cases separates traversal quality from the
pre-labeled tail-insertion gap.
"""
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def ingest_fixture():
    from verifyci.interface.commands.init import run_init
    from verifyci.interface.commands.ingest import run_ingest
    work = Path(tempfile.mkdtemp()) / "blastrepo"
    shutil.copytree(HERE / "fixture", work)
    run_init(str(work))
    run_ingest(str(work))
    return work


def names_of(entity_ids, ents):
    by = {e.revision_entity_id: getattr(e, "name", "?") for e in ents}
    return {by.get(i, f"?{i[:6]}") for i in entity_ids}


def run_case(graph, node_map, entities, diff):
    from verifyci.retrieval.blast_radius import compute_blast_radius
    from verifyci.verification.diffmap import parse_diff_files, seed_entities_for_diff
    files = parse_diff_files(diff)
    mapping = seed_entities_for_diff(files, entities, diff)
    changed = sorted({e for v in mapping.values() for e in v})
    blast = compute_blast_radius(graph=graph, changed_entities=changed,
                                 test_entities=set(), node_map=node_map or None)
    detected = names_of(set(blast.affected_callers) | set(blast.affected_callees), entities)
    return changed, detected, blast.risk_score


def load_cases():
    return [json.loads(line) for line in
            (HERE / "cases.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def collect():
    from verifyci.interface.commands.graph_loader import load_graph
    work = ingest_fixture()
    try:
        db = str(work / ".verifyci" / "verifyci.db")
        graph, node_map, entities = load_graph(db)
        rows = []
        for c in load_cases():
            changed, detected, risk = run_case(graph, node_map, entities, c["diff"])
            exp = set(c["expected_impacted"])
            tp, fn, fp = len(detected & exp), len(exp - detected), len(detected - exp)
            rec = (tp / len(exp)) if exp else (1.0 if not detected else 0.0)
            prec = (tp / len(detected)) if detected else (1.0 if not exp else None)
            rows.append({"id": c["id"], "mode": c["mode"], "seed": c["seed"],
                         "n_changed_entities": len(changed), "risk": round(risk, 2),
                         "expected": sorted(exp), "detected": sorted(detected),
                         "TP": tp, "FN": fn, "FP": fp, "recall": round(rec, 4),
                         "precision": prec})
        return rows
    finally:
        shutil.rmtree(work.parent, ignore_errors=True)


def compute_metrics(rows):
    exp_rows = [r for r in rows if r["expected"]]
    all_cov = (sum(r["recall"] for r in exp_rows) / len(exp_rows)) if exp_rows else 0.0
    seeded = [r["recall"] for r in exp_rows if r["mode"] == "seeded"]
    seeded_cov = (sum(seeded) / len(seeded)) if seeded else 0.0
    contract_fns = [r["id"] for r in exp_rows if r["recall"] < 1.0 and r["mode"] != "known_gap"]
    known_gap_fns = [r["id"] for r in exp_rows if r["recall"] < 1.0 and r["mode"] == "known_gap"]
    return {"coverage_all": round(all_cov, 4), "coverage_seeded_only": round(seeded_cov, 4),
            "contract_fn_ids": contract_fns, "known_gap_miss_ids": known_gap_fns,
            "total_fp": sum(r["FP"] for r in rows)}


def main():
    rows = collect()
    m = compute_metrics(rows)
    print(f"{'id':24}{'mode':16}{'c-ent':>6}{'risk':>6}{'TP':>4}{'FN':>4}{'FP':>4}{'recall':>8}")
    for r in rows:
        flag = "   <-- contract FN" if r["id"] in m["contract_fn_ids"] else ""
        print(f"{r['id']:24}{r['mode']:16}{r['n_changed_entities']:>6}{r['risk']:>6}"
              f"{r['TP']:>4}{r['FN']:>4}{r['FP']:>4}{r['recall']:>8.2f}{flag}")
    cov = m["coverage_all"]
    print(f"\nCOVERAGE (all cases with non-empty expected): {cov:.4f} "
          f"(gate >= 0.90 -> {'MET' if cov >= 0.90 else 'NOT MET'})")
    print(f"Coverage excluding labeled known-gap cases:    {m['coverage_seeded_only']:.4f}")
    print(f"contract-level false negatives: {m['contract_fn_ids']}")
    print(f"labeled known-gap misses: {m['known_gap_miss_ids']}")
    print(f"total FP: {m['total_fp']}")
    report = {"frozen": {"cases_sha256": hashlib.sha256(
                (HERE / "cases.jsonl").read_bytes()).hexdigest()[:16]},
              "cases": rows, "metrics": m}
    (HERE / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nreport -> {HERE/'results.json'}")


if __name__ == "__main__":
    main()
