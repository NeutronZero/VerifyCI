"""C1 measurement: run the frozen patch corpus through the real gate.

One freshly ingested copy of `base/` + repo invariants (forbid_call:eval,
forbid_import:subprocess). Every case diff applies to that single
unmodified base state; run_verify is called per case (no repo mutation
between verifies). Emits results.json with the metric block and the
per-case verdict table. The verifier/gate is frozen: this measures, it
does not tune.
"""
import json
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent.parent
sys.path.insert(0, str(ROOT))


def _ingest_base():
    from verifyci.interface.commands.init import run_init
    from verifyci.interface.commands.ingest import run_ingest
    work = Path(tempfile.mkdtemp()) / "repo"
    shutil.copytree(BASE / "base", work)
    run_init(str(work))
    (work / ".verifyci" / "invariants.yaml").write_text(
        "invariants:\n"
        "  - id: no-eval\n    rule: forbid eval\n"
        "    query: forbid_call:eval\n    blocking: true\n"
        "  - id: no-subprocess\n    rule: forbid subprocess\n"
        "    query: forbid_import:subprocess\n    blocking: true\n",
        encoding="utf-8")
    run_ingest(str(work))
    return work, str(work / ".verifyci" / "verifyci.db")


def load_cases():
    return [json.loads(line) for line in
            (BASE / "cases.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def run():
    from verifyci.interface.commands.verify import run_verify
    work, db = _ingest_base()
    try:
        table = []
        for c in load_cases():
            r = run_verify(c["diff"], db_path=db)
            table.append({
                "id": c["id"], "ground_truth": c["ground_truth"],
                "category": c["category"], "expected": c["expected_status"],
                "status": r["status"], "rationale": r["rationale"],
            })
    finally:
        shutil.rmtree(work.parent, ignore_errors=True)
    return table


def compute_metrics(table):
    correct = [t for t in table if t["ground_truth"] == "correct"]
    wrong = [t for t in table if t["ground_truth"] == "wrong"]
    fails = [t for t in table if t["status"] == "FAIL"]

    eq_hits = sum(1 for t in correct if t["status"] == t["expected"])
    equivalence = eq_hits / len(correct) if correct else 0.0
    precision = (sum(1 for t in fails if t["ground_truth"] == "wrong") / len(fails)
                 if fails else float("nan"))

    det = [t for t in wrong if t["category"] in ("forbid_call", "forbid_import",
                                                 "secret", "fabricated_removal")]
    det_catch = (sum(1 for t in det if t["status"] == "FAIL") / len(det)) if det else float("nan")
    sem = [t for t in wrong if t["category"] == "semantic"]
    sem_false_accept = (sum(1 for t in sem if t["status"] == "PASS") / len(sem)) if sem else float("nan")
    sem_decline = (sum(1 for t in sem if t["status"] in ("INCONCLUSIVE", "HUMAN_REVIEW"))
                   / len(sem)) if sem else float("nan")

    false_rejects = [t["id"] for t in correct if t["status"] == "FAIL"]
    fp_fails = [t["id"] for t in fails if t["ground_truth"] == "correct"]
    missed_deterministic = [t["id"] for t in det if t["status"] != "FAIL"]
    # False confidence accounting (roadmap item 12): a wrong patch the
    # gate PASSed is the costliest outcome — worse than a decline — so
    # the accepting ids are listed explicitly, not just rated. Today
    # these are the four semantic wrongs the gate admits it cannot judge
    # (documented V1 scope limit, not a surprise).
    wrong_accepted_ids = [t["id"] for t in wrong if t["status"] == "PASS"]
    # Confusion (verdict vs semantic ground_truth): caught=FAIL, missed=PASS,
    # declined=INCONCLUSIVE/HUMAN_REVIEW.
    def bucket(rows):
        return {
            "caught": sum(1 for t in rows if t["status"] == "FAIL"),
            "accepted": sum(1 for t in rows if t["status"] == "PASS"),
            "declined": sum(1 for t in rows
                            if t["status"] in ("INCONCLUSIVE", "HUMAN_REVIEW")),
        }
    confusion = {
        "wrong_all": bucket(wrong), "correct_all": bucket(correct),
        "wrong_deterministic": bucket(det), "wrong_semantic": bucket(sem),
    }
    overall_agreement = (sum(1 for t in table if t["status"] == t["expected"])
                         / len(table)) if table else 0.0
    return {
        "counts": Counter(t["status"] for t in table),
        "patch_equivalence": round(equivalence, 4),
        "overall_agreement": round(overall_agreement, 4),
        "verification_precision": (round(precision, 4) if fails else None),
        "deterministic_catch_rate": round(det_catch, 4),
        "semantic_false_accept_rate": round(sem_false_accept, 4),
        "semantic_decline_rate": round(sem_decline, 4),
        "false_reject_ids": false_rejects,
        "false_positive_fail_ids": fp_fails,
        "missed_deterministic_ids": missed_deterministic,
        "wrong_accepted_ids": wrong_accepted_ids,
        "confusion": confusion,
        "n_correct": len(correct), "n_wrong": len(wrong), "n_fail": len(fails),
    }


def main():
    table = run()
    m = compute_metrics(table)
    print(f"{'id':22}{'gt':8}{'cat':18}{'expected':14}{'status':14}rationale")
    for t in table:
        flag = "" if t["status"] == t["expected"] else "   <-- differs"
        print(f"{t['id']:22}{t['ground_truth']:8}{t['category']:18}"
              f"{t['expected']:14}{t['status']:14}{t['rationale'][:34]}{flag}")
    print("\n== metrics ==")
    print("status counts:", dict(m["counts"]))
    print(f"patch_equivalence          {m['patch_equivalence']}  "
          f"(gate >=0.90) -> {'MET' if m['patch_equivalence']>=0.90 else 'NOT MET'}")
    vp = m["verification_precision"]
    print(f"verification_precision      {vp}  (gate >=0.85) -> "
          f"{'MET' if (vp is not None and vp>=0.85) else 'NOT MET'}")
    print(f"deterministic_catch_rate    {m['deterministic_catch_rate']}")
    print(f"semantic_false_accept_rate  {m['semantic_false_accept_rate']}")
    print(f"semantic_decline_rate       {m['semantic_decline_rate']}")
    print("false_rejects:", m["false_reject_ids"])
    print("false_positive_fails:", m["false_positive_fail_ids"])
    print("missed_deterministic:", m["missed_deterministic_ids"])
    print("wrong_accepted (false PASS):", m["wrong_accepted_ids"])
    print("\n== FP/FN breakdown (caught=FAIL, accepted=PASS, declined=INCONCLUSIVE/HUMAN_REVIEW) ==")
    for k, v in m["confusion"].items():
        print(f"  {k:20} {v}")
    report = {"frozen": {"cases_sha256": __import__("hashlib").sha256(
                (BASE / "cases.jsonl").read_bytes()).hexdigest()[:16]},
              "verdicts": table,
              "metrics": {k: (v if not isinstance(v, Counter) else dict(v))
                          for k, v in m.items()}}
    (BASE / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nreport -> {BASE/'results.json'}")


if __name__ == "__main__":
    main()
