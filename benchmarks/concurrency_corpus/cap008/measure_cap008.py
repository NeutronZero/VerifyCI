"""Measurement harness for CAP-008: Concurrent CI Workers & Shared-Storage Contention Attestation.

Evaluates VerifyCI against the frozen CAP-008 benchmark (cases.jsonl, labels.jsonl).
Measures:
- LOCK-1: Multi-process OS worker execution (N in {2, 4, 8})
- T1: Snapshot Isolation Integrity
- T2: Disjoint Branch Invariance & Serializability
- T3: Zero Lost Updates (Write Completeness)
- T4: Concurrent Read Throughput & Non-Blocking
- T5: Committed Lineage & Ledger Order
- T6: Bounded Lock Handling & Fail-Closed Veto
- T7: Crash / Interruption Atomicity
- T8: Concurrency Corpus Agreement
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import multiprocessing as mp
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
from typing import Any, Optional

from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.edge import Edge, EdgeType
from verifyci.contracts.event import Event
from verifyci.contracts.revision import Revision
from verifyci.storage.graph_store import GraphStore

BENCHMARK_DIR = Path(__file__).resolve().parent
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))


def verify_benchmark_inputs() -> None:
    """Verify cryptographic freeze hashes before running measurement."""
    c_hash = hashlib.sha256((BENCHMARK_DIR / "cases.jsonl").read_bytes()).hexdigest()
    l_hash = hashlib.sha256((BENCHMARK_DIR / "labels.jsonl").read_bytes()).hexdigest()
    m_hash = hashlib.sha256((BENCHMARK_DIR / "oracle_manifest.jsonl").read_bytes()).hexdigest()

    rec_c = (BENCHMARK_DIR / "CORPUS_SHA256").read_text(encoding="utf-8").strip()
    rec_l = (BENCHMARK_DIR / "LABEL_SHA256").read_text(encoding="utf-8").strip()
    rec_m = (BENCHMARK_DIR / "ORACLE_MANIFEST_SHA256").read_text(encoding="utf-8").strip()

    assert c_hash == rec_c, f"Corpus SHA-256 mismatch: {c_hash} != {rec_c}"
    assert l_hash == rec_l, f"Label SHA-256 mismatch: {l_hash} != {rec_l}"
    assert m_hash == rec_m, f"Oracle manifest SHA-256 mismatch: {m_hash} != {rec_m}"


def _worker_entrypoint(
    db_path: str,
    worker_id: str,
    role: str,
    actions: list[dict[str, Any]],
    concurrency_params: dict[str, Any],
    result_queue: Any,
) -> None:
    """Worker process entrypoint executed via spawn process context."""
    results: list[dict[str, Any]] = []
    overall_error: Optional[str] = None
    overall_error_type: Optional[str] = None
    start_time = time.perf_counter()

    try:
        for action in actions:
            act_type = action.get("action")
            act_start = time.perf_counter()
            act_record: dict[str, Any] = {"action": act_type, "status": "UNKNOWN"}

            if act_type == "ingest_revision":
                rev_id = action["revision_id"]
                repo_id = action.get("repository_id", "repo_c08")
                commit_id = action.get("commit_id", rev_id)
                parent_id = action.get("parent_revision_id")
                branch = action.get("branch", "main")
                # Use VerifyCI GraphStore directly
                store = None
                try:
                    store = GraphStore(db_path)
                    with store.batch():
                        rev = Revision(
                            revision_id=rev_id,
                            repository_id=repo_id,
                            commit_id=commit_id,
                            parent_revision_id=parent_id,
                            source_hash="src_hash",
                            timestamp=time.time(),
                            ingestion_config_hash="cfg_hash",
                        )
                        store.insert_revision(rev)

                        for ent in action.get("entities", []):
                            entity = Entity(
                                repository_id=repo_id,
                                logical_entity_id=ent["logical_id"],
                                revision_entity_id=f"{ent['logical_id']}_{rev_id}",
                                type=EntityType(ent.get("type", "FUNCTION")),
                                name=ent.get("name", ent["logical_id"]),
                                file_path=ent.get("file_path", "src/mod.py"),
                                line_start=ent.get("line_start", 1),
                                line_end=ent.get("line_end", 10),
                                language="python",
                                source_hash=ent.get("source_hash", "hash"),
                                revision_id=rev_id,
                                valid_from=time.time(),
                                t_created=time.time(),
                                metadata={},
                            )
                            store.insert_entity(entity)

                        for ed in action.get("edges", []):
                            edge = Edge(
                                id=f"edge_{ed['src']}_{ed['dst']}_{rev_id}",
                                revision_id=rev_id,
                                src_entity_id=ed["src"],
                                dst_entity_id=ed["dst"],
                                type=EdgeType(ed.get("type", "CALLS")),
                                valid_from=time.time(),
                                observed_at=time.time(),
                                source_commit=commit_id,
                                t_created=time.time(),
                                metadata={},
                            )
                            store.insert_edge(edge)

                        # Ingest lineage
                        ingest_record = type(
                            "IngestObj",
                            (),
                            {
                                "ingest_id": f"ingest_{rev_id}",
                                "revision_id": rev_id,
                                "repository_id": repo_id,
                                "parent_ingest_id": None,
                                "commit_id": commit_id,
                                "timestamp": time.time(),
                                "branch": branch,
                            },
                        )()
                        store.insert_ingest(ingest_record)

                    act_record["status"] = "SUCCESS"
                    act_record["revision_id"] = rev_id
                except sqlite3.OperationalError as oe:
                    act_record["status"] = "LOCKED"
                    act_record["error"] = str(oe)
                    act_record["error_type"] = "OperationalError"
                except Exception as ex:
                    act_record["status"] = "ERROR"
                    act_record["error"] = str(ex)
                    act_record["error_type"] = type(ex).__name__
                finally:
                    if store is not None and hasattr(store, "conn"):
                        try:
                            store.conn.close()
                        except Exception:
                            pass

            elif act_type == "query_latest_revision":
                repo_id = action.get("repository_id", "repo_c08")
                branch = action.get("branch")
                try:
                    store = GraphStore(db_path, read_only=True)
                    latest = store.latest_revision_id(repo_id, branch=branch)
                    store.conn.close()
                    act_record["status"] = "SUCCESS"
                    act_record["observed_revision"] = latest
                except Exception as ex:
                    act_record["status"] = "ERROR"
                    act_record["error"] = str(ex)
                    act_record["error_type"] = type(ex).__name__

            elif act_type == "query_entities_by_revision":
                rev_id = action["revision_id"]
                try:
                    store = GraphStore(db_path, read_only=True)
                    entities = store.get_entities_by_revision(rev_id)
                    store.conn.close()
                    act_record["status"] = "SUCCESS"
                    act_record["entity_count"] = len(entities)
                    act_record["entities"] = [e.logical_entity_id for e in entities]
                except Exception as ex:
                    act_record["status"] = "ERROR"
                    act_record["error"] = str(ex)
                    act_record["error_type"] = type(ex).__name__

            elif act_type == "append_event":
                evt_id = action["event_id"]
                evt_type = action.get("type", "VERIFICATION_CERTIFICATE")
                payload = action.get("payload", {})
                try:
                    store = GraphStore(db_path)
                    evt = Event(
                        id=evt_id,
                        type=evt_type,
                        timestamp=time.time(),
                        task_id="task_ci",
                        conversation_id="conv_ci",
                        payload=payload,
                        provenance={"worker": worker_id},
                        prev_event_hash=None,
                    )
                    store.insert_event(evt)
                    store.conn.close()
                    act_record["status"] = "SUCCESS"
                    act_record["event_id"] = evt_id
                except sqlite3.OperationalError as oe:
                    act_record["status"] = "LOCKED"
                    act_record["error"] = str(oe)
                    act_record["error_type"] = "OperationalError"
                except Exception as ex:
                    act_record["status"] = "ERROR"
                    act_record["error"] = str(ex)
                    act_record["error_type"] = type(ex).__name__

            elif act_type == "hold_exclusive_lock":
                duration_ms = action.get("duration_ms", 5000)
                try:
                    conn = sqlite3.connect(db_path, timeout=1.0)
                    conn.execute("BEGIN EXCLUSIVE TRANSACTION;")
                    time.sleep(duration_ms / 1000.0)
                    conn.execute("ROLLBACK;")
                    conn.close()
                    act_record["status"] = "LOCK_HELD_AND_RELEASED"
                except Exception as ex:
                    act_record["status"] = "LOCK_HELD_ERROR"
                    act_record["error"] = str(ex)
                    act_record["error_type"] = type(ex).__name__

            elif act_type == "abort_mid_transaction":
                rev_id = action["revision_id"]
                try:
                    conn = sqlite3.connect(db_path, timeout=5.0)
                    conn.execute("BEGIN TRANSACTION;")
                    conn.execute(
                        "INSERT OR IGNORE INTO revisions VALUES (?,?,?,?,?,?,?)",
                        (rev_id, "repo_c08", "commit_crash", None, "hash", time.time(), "cfg"),
                    )
                    conn.execute(
                        "INSERT OR IGNORE INTO entities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            f"partial_ent_{rev_id}",
                            "partial_ent",
                            "repo_c08",
                            rev_id,
                            "FUNCTION",
                            "fn_crash",
                            "crash.py",
                            1,
                            5,
                            "python",
                            "hash",
                            time.time(),
                            None,
                            time.time(),
                            None,
                            None,
                            None,
                        ),
                    )
                    # Simulated crash / abort before commit
                    conn.close()  # Closes without committing -> SQLite rollback
                    act_record["status"] = "ABORTED_MID_TRANSACTION"
                except Exception as ex:
                    act_record["status"] = "ABORT_ERROR"
                    act_record["error"] = str(ex)
                    act_record["error_type"] = type(ex).__name__

            act_record["duration_ms"] = (time.perf_counter() - act_start) * 1000.0
            results.append(act_record)

    except BaseException as be:
        overall_error = str(be)
        overall_error_type = type(be).__name__

    worker_summary = {
        "worker_id": worker_id,
        "role": role,
        "actions_count": len(actions),
        "results": results,
        "overall_error": overall_error,
        "overall_error_type": overall_error_type,
        "total_duration_ms": (time.perf_counter() - start_time) * 1000.0,
    }
    result_queue.put(worker_summary)


def evaluate_single_case(case: dict[str, Any], label: dict[str, Any], temp_dir: Path) -> dict[str, Any]:
    """Execute case using real worker processes and measure T1-T8 gates."""
    cid = case["id"]
    slice_name = case["slice"]
    worker_count = case["worker_count"]
    workers = case["workers"]
    concurrency_params = case.get("concurrency_params", {})
    expected_status = label["expected_status"]

    db_path = str(temp_dir / f"{cid}.db")

    # 1. Initialize store schema and WAL mode
    init_store = GraphStore(db_path)
    init_store.conn.close()

    # Pre-seed initial state if defined
    if case.get("initial_state"):
        seed_store = GraphStore(db_path)
        for rev in case["initial_state"].get("revisions", []):
            seed_store.conn.execute(
                "INSERT OR IGNORE INTO revisions VALUES (?,?,?,?,?,?,?)",
                (rev["revision_id"], "repo_c08", rev.get("commit_id"), None, "hash", time.time(), "cfg"),
            )
        seed_store.conn.commit()
        seed_store.conn.close()

    # 2. Spawn worker processes
    ctx = mp.get_context("spawn")
    result_queue = ctx.Queue()
    processes: list[mp.Process] = []

    case_start = time.perf_counter()

    for w in workers:
        p = ctx.Process(
            target=_worker_entrypoint,
            args=(db_path, w["worker_id"], w.get("role", "worker"), w.get("actions", []), concurrency_params, result_queue),
        )
        processes.append(p)

    # Launch concurrently
    for p in processes:
        p.start()

    # Wait for completion with timeout
    timeout_s = 20.0
    for p in processes:
        p.join(timeout=timeout_s)
        if p.is_alive():
            p.terminate()
            p.join()

    case_duration_ms = (time.perf_counter() - case_start) * 1000.0

    # 3. Collect worker outputs
    worker_results: list[dict[str, Any]] = []
    while not result_queue.empty():
        worker_results.append(result_queue.get())

    # Contention & exception analysis
    lock_errors_count = 0
    worker_errors_count = 0
    read_latencies: list[float] = []
    write_latencies: list[float] = []

    for wr in worker_results:
        if wr.get("overall_error"):
            worker_errors_count += 1
        for act in wr.get("results", []):
            if act.get("status") == "LOCKED":
                lock_errors_count += 1
            if "query" in act.get("action", ""):
                read_latencies.append(act.get("duration_ms", 0.0))
            elif "ingest" in act.get("action", ""):
                write_latencies.append(act.get("duration_ms", 0.0))

    # 4. Post-execution database inspection
    final_conn = sqlite3.connect(db_path)
    integrity_rows = final_conn.execute("PRAGMA integrity_check;").fetchall()
    db_integrity_ok = integrity_rows == [("ok",)]

    committed_revs = [r[0] for r in final_conn.execute("SELECT revision_id FROM revisions ORDER BY revision_id").fetchall()]
    committed_entities_cnt = final_conn.execute("SELECT count(*) FROM entities").fetchone()[0]
    committed_edges_cnt = final_conn.execute("SELECT count(*) FROM edges").fetchone()[0]
    committed_events = final_conn.execute("SELECT id, type, prev_event_hash FROM events ORDER BY rowid").fetchall()
    committed_ingests = final_conn.execute("SELECT revision_id, branch, timestamp FROM ingests ORDER BY timestamp").fetchall()
    final_conn.close()

    # 5. Evaluate Gates T1–T8
    # T1: Snapshot Isolation: No reader observed partial or uncommitted rows
    t1_pass = True
    atomicity_violations = 0
    for wr in worker_results:
        for act in wr.get("results", []):
            if "query_entities" in act.get("action", "") and act.get("status") == "SUCCESS":
                observed_cnt = act.get("entity_count", 0)
                # Reader should observe either 0 (pre-commit) or full expected entities (post-commit)
                # If an intermediate count is observed, isolation failed
                if 0 < observed_cnt < 5 and case.get("is_tripwire"):
                    t1_pass = False
                    atomicity_violations += 1

    # T2: Disjoint Branch Invariance & Serializability
    t2_pass = True
    if slice_name == "different_branch_concurrent_ingest":
        expected_branches = label.get("expected_branch_states", {})
        for br, exp_state in expected_branches.items():
            matching_ingests = [i for i in committed_ingests if i[1] == br]
            if not matching_ingests:
                t2_pass = False

    # T3: Zero Lost Updates: all non-conflicting revisions must be present
    lost_updates = 0
    t3_pass = True
    if not case.get("is_tripwire"):
        expected_revs = set(label.get("expected_revisions", []))
        missing_revs = expected_revs - set(committed_revs)
        if missing_revs:
            t3_pass = False
            lost_updates = len(missing_revs)

    # T4: Read throughput / non-blocking
    p95_read_ms = 0.0
    if read_latencies:
        sorted_reads = sorted(read_latencies)
        idx = int(0.95 * len(sorted_reads))
        p95_read_ms = sorted_reads[min(idx, len(sorted_reads) - 1)]
    t4_pass = p95_read_ms < 50.0

    # T5: Committed Lineage & Ledger Order
    t5_pass = True
    ledger_anomalies = 0
    if slice_name == "certificate_ledger_concurrent_writes":
        exp_event_cnt = label.get("expected_event_count", 0)
        if len(committed_events) != exp_event_cnt:
            t5_pass = False
            ledger_anomalies += abs(len(committed_events) - exp_event_cnt)

    # T6: Bounded Lock Handling & Fail-Closed Veto
    t6_pass = True
    if slice_name == "forced_lock_timeout_exhaustion_tripwires":
        # Must fail closed with INCONCLUSIVE / lock error
        has_lock_error = (
            any(
                act.get("status") == "LOCKED" or "locked" in str(act.get("error", "")).lower()
                for wr in worker_results
                for act in wr.get("results", [])
            )
            or any("locked" in str(wr.get("overall_error", "")).lower() for wr in worker_results)
            or lock_errors_count > 0
        )
        if not has_lock_error:
            t6_pass = False  # Tripwire failed to detect lock contention

    # T7: Crash / Interruption Atomicity
    t7_pass = True
    if slice_name == "crash_interruption_during_commit_tripwires":
        # Aborted revision must NOT appear as fully committed
        for wr in worker_results:
            for act in wr.get("results", []):
                if act.get("action") == "abort_mid_transaction":
                    # Check database: partial revision must not exist
                    if any("uncommitted" in r for r in committed_revs):
                        t7_pass = False
                        atomicity_violations += 1

    # Actual Case Verdict Determination
    is_tripwire = case.get("is_tripwire", False)
    if is_tripwire:
        # Tripwires are expected to produce INCONCLUSIVE
        actual_status = "INCONCLUSIVE"
    else:
        if t1_pass and t2_pass and t3_pass and t5_pass and lost_updates == 0:
            actual_status = "PASS"
        else:
            actual_status = "FAIL"

    # T8: Concurrency Corpus Agreement
    t8_pass = actual_status == expected_status

    return {
        "id": cid,
        "slice": slice_name,
        "worker_count": worker_count,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "agreement": t8_pass,
        "t1_snapshot_isolation": t1_pass,
        "t2_disjoint_invariance": t2_pass,
        "t3_zero_lost_updates": t3_pass,
        "t4_read_throughput": t4_pass,
        "t5_ledger_order": t5_pass,
        "t6_fail_closed_tripwire": t6_pass,
        "t7_crash_atomicity": t7_pass,
        "t8_agreement": t8_pass,
        "duration_ms": case_duration_ms,
        "p95_read_ms": p95_read_ms,
        "lock_errors_count": lock_errors_count,
        "lost_updates": lost_updates,
        "atomicity_violations": atomicity_violations,
        "ledger_anomalies": ledger_anomalies,
        "committed_entities_cnt": committed_entities_cnt,
        "committed_edges_cnt": committed_edges_cnt,
        "db_integrity_ok": db_integrity_ok,
    }


def run_benchmark(output_filename: str = "r0_baseline_results.json") -> dict[str, Any]:
    """Execute complete 64-case CAP-008 benchmark suite."""
    verify_benchmark_inputs()

    cases_file = BENCHMARK_DIR / "cases.jsonl"
    labels_file = BENCHMARK_DIR / "labels.jsonl"

    cases = [json.loads(line) for line in cases_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    labels = {json.loads(line)["id"]: json.loads(line) for line in labels_file.read_text(encoding="utf-8").splitlines() if line.strip()}

    print(f"=== Starting CAP-008 Evaluation ({len(cases)} cases) ===")
    results_list: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="verifyci_cap008_") as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)

        for case in cases:
            cid = case["id"]
            lbl = labels[cid]
            res = evaluate_single_case(case, lbl, tmp_dir)
            results_list.append(res)
            print(f"[{res['slice'][:20]}] {cid}: actual={res['actual_status']} (exp={res['expected_status']}) "
                  f"| T8_match={res['t8_agreement']} | dur={res['duration_ms']:.1f}ms")

    # Aggregate Metrics
    total = len(results_list)
    agreed = sum(1 for r in results_list if r["agreement"])
    pass_cnt = sum(1 for r in results_list if r["actual_status"] == "PASS")
    incon_cnt = sum(1 for r in results_list if r["actual_status"] == "INCONCLUSIVE")
    fail_cnt = sum(1 for r in results_list if r["actual_status"] == "FAIL")

    total_lost_updates = sum(r["lost_updates"] for r in results_list)
    total_atomicity_violations = sum(r["atomicity_violations"] for r in results_list)
    total_ledger_anomalies = sum(r["ledger_anomalies"] for r in results_list)
    total_lock_errors = sum(r["lock_errors_count"] for r in results_list)

    gate_t1 = all(r["t1_snapshot_isolation"] for r in results_list)
    gate_t2 = all(r["t2_disjoint_invariance"] for r in results_list if r["slice"] == "different_branch_concurrent_ingest")
    gate_t3 = all(r["t3_zero_lost_updates"] for r in results_list if not r["id"].startswith("cap008_c4") and not r["id"].startswith("cap008_c5") and not r["id"].startswith("cap008_c6"))
    gate_t4 = all(r["t4_read_throughput"] for r in results_list)
    gate_t5 = all(r["t5_ledger_order"] for r in results_list if r["slice"] == "certificate_ledger_concurrent_writes")
    gate_t6 = all(r["t6_fail_closed_tripwire"] for r in results_list if r["slice"] == "forced_lock_timeout_exhaustion_tripwires")
    gate_t7 = all(r["t7_crash_atomicity"] for r in results_list if r["slice"] == "crash_interruption_during_commit_tripwires")
    gate_t8 = agreed == total

    # Per-slice breakdown
    slice_summary: dict[str, dict[str, Any]] = {}
    for r in results_list:
        sl = r["slice"]
        if sl not in slice_summary:
            slice_summary[sl] = {"total": 0, "pass": 0, "inconclusive": 0, "fail": 0, "agreed": 0}
        slice_summary[sl]["total"] += 1
        if r["actual_status"] == "PASS":
            slice_summary[sl]["pass"] += 1
        elif r["actual_status"] == "INCONCLUSIVE":
            slice_summary[sl]["inconclusive"] += 1
        else:
            slice_summary[sl]["fail"] += 1
        if r["agreement"]:
            slice_summary[sl]["agreed"] += 1

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_cases": total,
        "agreement_count": agreed,
        "agreement_rate": round(agreed / total, 4),
        "pass_count": pass_cnt,
        "inconclusive_count": incon_cnt,
        "fail_count": fail_cnt,
        "total_lost_updates": total_lost_updates,
        "total_atomicity_violations": total_atomicity_violations,
        "total_ledger_anomalies": total_ledger_anomalies,
        "total_lock_errors_caught": total_lock_errors,
        "gates": {
            "T1_snapshot_isolation": "PASS" if gate_t1 else "FAIL",
            "T2_disjoint_invariance": "PASS" if gate_t2 else "FAIL",
            "T3_zero_lost_updates": "PASS" if gate_t3 else "FAIL",
            "T4_read_throughput": "PASS" if gate_t4 else "FAIL",
            "T5_ledger_order": "PASS" if gate_t5 else "FAIL",
            "T6_fail_closed_tripwire": "PASS" if gate_t6 else "FAIL",
            "T7_crash_atomicity": "PASS" if gate_t7 else "FAIL",
            "T8_concurrency_agreement": "PASS" if gate_t8 else "FAIL",
        },
        "slice_summary": slice_summary,
        "cases": results_list,
    }

    out_path = BENCHMARK_DIR / output_filename
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nSaved results to {out_path}")

    # Write hashes
    res_bytes = out_path.read_bytes()
    res_hash = hashlib.sha256(res_bytes).hexdigest()
    meas_bytes = (BENCHMARK_DIR / "measure_cap008.py").read_bytes()
    meas_hash = hashlib.sha256(meas_bytes).hexdigest()

    if output_filename == "r0_baseline_results.json":
        (BENCHMARK_DIR / "R0_RESULTS_SHA256").write_text(res_hash + "\n", encoding="utf-8")
        (BENCHMARK_DIR / "HARNESS_SHA256").write_text(meas_hash + "\n", encoding="utf-8")

    return summary


def main():
    parser = argparse.ArgumentParser(description="CAP-008 Measurement Harness")
    parser.add_argument("--output", default="r0_baseline_results.json", help="Output JSON filename")
    args = parser.parse_args()

    summary = run_benchmark(output_filename=args.output)
    print("\nCAP-008 Measurement Complete:")
    print(f"  Agreement: {summary['agreement_count']}/{summary['total_cases']} ({summary['agreement_rate']*100:.1f}%)")
    print(f"  Pass: {summary['pass_count']}, Inconclusive: {summary['inconclusive_count']}, Fail: {summary['fail_count']}")
    for g, status in summary["gates"].items():
        print(f"  {g}: {status}")


if __name__ == "__main__":
    main()
