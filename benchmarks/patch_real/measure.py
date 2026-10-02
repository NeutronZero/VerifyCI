"""H4-C measurement: run the frozen real-patch corpus through the frozen gate.

Executes exactly once across the 20 frozen real-patch cases.
For each case:
  1. Sets up the frozen base snapshot for the case's base_tree.
  2. Runs run_init and writes repo invariants (forbid_call:eval, forbid_import:subprocess).
  3. Runs run_ingest on the base tree.
  4. Calls run_verify(case["diff"], db_path=db).
  5. Records the outcome and computes confusion and gate metrics.
Emits results_h4.json with the full per-case verdict table and metrics.
"""
import hashlib
import json
import shutil
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

EXPECTED_CASES_SHA256 = "5e50316bbaaf4ef296b65cfd3a5bc51bb41c7d8856321d4ed77c1957715816ce"
EXPECTED_CONFIG_SHA256 = "d4b05c1cdfe32e535575fa5038d4d69351749975aee24740768f6e6597f67146"


def verify_frozen_hashes():
    cases_path = HERE / "cases.jsonl"
    config_path = HERE / "config.json"
    assert cases_path.exists(), f"Missing {cases_path}"
    assert config_path.exists(), f"Missing {config_path}"

    cases_sha = hashlib.sha256(cases_path.read_bytes()).hexdigest()
    config_sha = hashlib.sha256(config_path.read_bytes()).hexdigest()

    assert cases_sha == EXPECTED_CASES_SHA256, (
        f"cases.jsonl hash mismatch: got {cases_sha}, expected {EXPECTED_CASES_SHA256}"
    )
    assert config_sha == EXPECTED_CONFIG_SHA256, (
        f"config.json hash mismatch: got {config_sha}, expected {EXPECTED_CONFIG_SHA256}"
    )
    return cases_sha, config_sha


def load_cases():
    return [
        json.loads(line)
        for line in (HERE / "cases.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _setup_base_and_ingest(base_rev: str):
    from verifyci.interface.commands.init import run_init
    from verifyci.interface.commands.ingest import run_ingest

    base_dir = HERE / "base" / base_rev
    assert base_dir.exists(), f"Base directory missing: {base_dir}"

    work_parent = Path(tempfile.mkdtemp(prefix="h4_base_"))
    work = work_parent / "repo"
    shutil.copytree(base_dir, work)

    db_path = run_init(str(work))
    (work / ".verifyci" / "invariants.yaml").write_text(
        "invariants:\n"
        "  - id: no-eval\n    rule: forbid eval\n"
        "    query: forbid_call:eval\n    blocking: true\n"
        "    target_scope: code_core\n"
        "  - id: no-subprocess\n    rule: forbid subprocess\n"
        "    query: forbid_import:subprocess\n    blocking: true\n"
        "    target_scope: code_core\n",
        encoding="utf-8",
    )
    run_ingest(str(work))
    return work_parent, db_path


def run():
    from verifyci.interface.commands.verify import run_verify

    cases = load_cases()
    assert len(cases) == 20, f"Expected exactly 20 cases, found {len(cases)}"

    table = []
    execution_failures = []

    for c in cases:
        base_rev = c["provenance"]["base_tree"]
        work_parent = None
        t0 = time.perf_counter()
        try:
            work_parent, db_path = _setup_base_and_ingest(base_rev)
            r = run_verify(c["diff"], db_path=db_path)
            dt_ms = (time.perf_counter() - t0) * 1e3
            table.append({
                "id": c["id"],
                "ground_truth": c["ground_truth"],
                "category": c["category"],
                "expected": c["expected_status"],
                "status": r["status"],
                "rationale": r["rationale"],
                "elapsed_ms": round(dt_ms, 2),
                "provenance": c["provenance"],
            })
        except Exception as e:
            dt_ms = (time.perf_counter() - t0) * 1e3
            execution_failures.append({
                "id": c["id"],
                "error": str(e),
                "elapsed_ms": round(dt_ms, 2),
            })
            table.append({
                "id": c["id"],
                "ground_truth": c["ground_truth"],
                "category": c["category"],
                "expected": c["expected_status"],
                "status": "EXECUTION_FAILURE",
                "rationale": str(e),
                "elapsed_ms": round(dt_ms, 2),
                "provenance": c["provenance"],
            })
        finally:
            if work_parent and work_parent.exists():
                shutil.rmtree(work_parent, ignore_errors=True)

    return table, execution_failures


def compute_metrics(table):
    correct = [t for t in table if t["ground_truth"] == "correct"]
    wrong = [t for t in table if t["ground_truth"] == "wrong"]
    fails = [t for t in table if t["status"] == "FAIL"]

    # Predeclared H4 metrics mirroring patch_corpus
    eq_hits = sum(1 for t in correct if t["status"] == t["expected"])
    equivalence = eq_hits / len(correct) if correct else 0.0

    precision = (
        sum(1 for t in fails if t["ground_truth"] == "wrong") / len(fails)
        if fails else float("nan")
    )

    det = [
        t for t in wrong
        if t["category"] in ("forbid_call", "forbid_import", "secret", "fabricated_removal")
    ]
    det_catch = (
        sum(1 for t in det if t["status"] == "FAIL") / len(det)
        if det else float("nan")
    )

    sem = [t for t in wrong if t["category"] == "semantic"]
    sem_false_accept = (
        sum(1 for t in sem if t["status"] == "PASS") / len(sem)
        if sem else float("nan")
    )
    sem_decline = (
        sum(1 for t in sem if t["status"] in ("INCONCLUSIVE", "HUMAN_REVIEW")) / len(sem)
        if sem else float("nan")
    )

    false_rejects = [t["id"] for t in correct if t["status"] == "FAIL"]
    fp_fails = [t["id"] for t in fails if t["ground_truth"] == "correct"]

    # Binary classification metrics:
    # Condition Positive = Wrong patch (defect present)
    # Condition Negative = Correct patch (no defect)
    # Test Outcome Positive = FAIL verdict
    # Test Outcome Negative = non-FAIL verdict (PASS / INCONCLUSIVE / HUMAN_REVIEW)
    tp = sum(1 for t in wrong if t["status"] == "FAIL")
    fn = sum(1 for t in wrong if t["status"] != "FAIL")
    fp = sum(1 for t in correct if t["status"] == "FAIL")
    tn = sum(1 for t in correct if t["status"] != "FAIL")

    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    fa_rate = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    fr_rate = fp / (tn + fp) if (tn + fp) > 0 else 0.0

    def bucket(rows):
        return {
            "caught": sum(1 for t in rows if t["status"] == "FAIL"),
            "accepted": sum(1 for t in rows if t["status"] == "PASS"),
            "declined": sum(1 for t in rows if t["status"] in ("INCONCLUSIVE", "HUMAN_REVIEW")),
            "error": sum(1 for t in rows if t["status"] == "EXECUTION_FAILURE"),
        }

    confusion = {
        "wrong_all": bucket(wrong),
        "correct_all": bucket(correct),
        "wrong_deterministic": bucket(det),
        "wrong_semantic": bucket(sem),
    }

    overall_agreement = (
        sum(1 for t in table if t["status"] == t["expected"]) / len(table)
        if table else 0.0
    )

    return {
        "counts": Counter(t["status"] for t in table),
        "patch_equivalence": round(equivalence, 4),
        "overall_agreement": round(overall_agreement, 4),
        "verification_precision": round(precision, 4) if fails else None,
        "deterministic_catch_rate": (
            round(det_catch, 4) if not (det_catch != det_catch) else None  # NaN check
        ),
        "semantic_false_accept_rate": round(sem_false_accept, 4),
        "semantic_decline_rate": round(sem_decline, 4),
        "binary_classification": {
            "TP": tp,
            "TN": tn,
            "FP": fp,
            "FN": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "specificity": round(spec, 4),
            "false_accept_rate": round(fa_rate, 4),
            "false_reject_rate": round(fr_rate, 4),
        },
        "false_reject_ids": false_rejects,
        "false_positive_fail_ids": fp_fails,
        "confusion": confusion,
        "n_correct": len(correct),
        "n_wrong": len(wrong),
        "n_fail": len(fails),
    }


def main():
    cases_sha, config_sha = verify_frozen_hashes()
    print("Corpus hashes verified before measurement:")
    print(f"  cases.jsonl: {cases_sha}")
    print(f"  config.json: {config_sha}")

    table, failures = run()
    m = compute_metrics(table)

    print(f"\n{'id':20}{'gt':8}{'cat':10}{'expected':10}{'status':14}rationale")
    print("-" * 75)
    for t in table:
        flag = "" if t["status"] == t["expected"] else "   <-- differs"
        print(
            f"{t['id']:20}{t['ground_truth']:8}{t['category']:10}"
            f"{t['expected']:10}{t['status']:14}{t['rationale'][:25]}{flag}"
        )

    print("\n== Metrics Summary ==")
    print("status counts:", dict(m["counts"]))
    print(f"patch_equivalence:          {m['patch_equivalence']} (gate >=0.90) -> "
          f"{'MET' if m['patch_equivalence'] >= 0.90 else 'NOT MET'}")
    vp = m["verification_precision"]
    print(f"verification_precision:     {vp} (gate >=0.85) -> "
          f"{'MET' if (vp is not None and vp >= 0.85) else 'NOT MET'}")
    print(f"semantic_false_accept_rate: {m['semantic_false_accept_rate']}")
    print(f"semantic_decline_rate:      {m['semantic_decline_rate']}")
    print("binary metrics:", m["binary_classification"])
    print("execution failures:", len(failures))

    gates = {
        "patch_equivalence_ge_0.90": m["patch_equivalence"] >= 0.90,
        "verification_precision_ge_0.85": (vp is not None and vp >= 0.85),
    }

    report = {
        "protocol": "benchmarks/patch_real/config.json (frozen)",
        "protocol_sha256": config_sha,
        "cases_sha256": cases_sha,
        "provenance_limitation": "Checker-aware authoring limitation explicitly preserved.",
        "execution_failures": failures,
        "gates": gates,
        "metrics": {
            k: (v if not isinstance(v, Counter) else dict(v))
            for k, v in m.items()
        },
        "verdicts": table,
    }

    out_file = HERE / "results_h4.json"
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nWrote results to {out_file}")


if __name__ == "__main__":
    main()
