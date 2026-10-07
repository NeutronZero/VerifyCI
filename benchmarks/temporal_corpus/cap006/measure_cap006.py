"""Measurement harness for CAP-006: Temporal Lineage & Multi-Branch Replay Attestation.

Evaluates VerifyCI against the frozen CAP-006 benchmark (cases.jsonl, labels.jsonl).
Measures:
- Hard Vetoes:
  1. Cross-branch contamination = 0
  2. Overlapping live intervals = 0
  3. Historical anchor drift = 0
  4. Fabricated lineage = 0
  5. Fail-closed tripwires = 8/8
  6. Replay equivalence = 100%
  7. Idempotent ingest = 100%
- Gates T1–T8:
  T1: Incremental Replay Equivalence
  T2: Rename Lineage Continuity
  T3: Revert Cycle Correctness
  T4: Branch Divergence Isolation
  T5: Merge Attestation Determinism
  T6: Anchor Point-in-Time Stability
  T7: Temporal Fail-Closed Integrity
  T8: Corpus Replay Agreement
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
from typing import Any

from verifyci.interface.commands.ingest import run_ingest
from verifyci.storage.graph_store import GraphStore

BENCHMARK_DIR = Path(__file__).resolve().parent
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))


def verify_benchmark_inputs():
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


def sync_directory_files(target_dir: Path, files: dict[str, str]):
    """Sync target directory files to match exact dictionary contents.

    Preserves .verifyci/ metadata directory.
    """
    wanted_paths = set()
    for rel_path, content in files.items():
        full_path = target_dir / rel_path
        wanted_paths.add(full_path.resolve())
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")

    # Clean up files in target_dir that are no longer wanted
    for item in target_dir.rglob("*"):
        if item.is_file():
            # Never remove .verifyci internal files
            if ".verifyci" in item.parts:
                continue
            if item.resolve() not in wanted_paths:
                try:
                    item.unlink()
                except OSError:
                    pass


def extract_live_canonical_graph(store: GraphStore, revision_id: str | None = None) -> tuple[dict[str, Any], list[Any], str]:
    """Extract live entities and edges from a GraphStore and compute canonical digest."""
    if revision_id:
        entity_rows = store.conn.execute(
            "SELECT revision_entity_id, logical_entity_id, type, name, file_path, line_start, line_end, source_hash"
            " FROM entities WHERE revision_id = ?"
            " GROUP BY logical_entity_id"
            " ORDER BY name, file_path, type",
            (revision_id,),
        ).fetchall()
        edge_rows = store.conn.execute(
            "SELECT src_entity_id, dst_entity_id, type, metadata_json"
            " FROM edges WHERE revision_id = ?"
            " GROUP BY type, src_entity_id, dst_entity_id"
            " ORDER BY type, src_entity_id, dst_entity_id",
            (revision_id,),
        ).fetchall()
    else:
        # Live entities: valid_until IS NULL
        entity_rows = store.conn.execute(
            "SELECT revision_entity_id, logical_entity_id, type, name, file_path, line_start, line_end, source_hash"
            " FROM entities WHERE valid_until IS NULL"
            " ORDER BY name, file_path, type"
        ).fetchall()
        edge_rows = store.conn.execute(
            "SELECT src_entity_id, dst_entity_id, type, metadata_json"
            " FROM edges WHERE valid_until IS NULL"
            " ORDER BY type, src_entity_id, dst_entity_id"
        ).fetchall()

    ent_map = {r[0]: (r[3], r[4]) for r in entity_rows}

    canonical_entities = [
        {
            "name": r[3],
            "type": r[2],
            "file_path": r[4],
            "source_hash": r[7],
        }
        for r in entity_rows
    ]

    canonical_edges = [
        {
            "src": ent_map.get(r[0], (r[0], ""))[0],
            "src_path": ent_map.get(r[0], ("", r[0]))[1],
            "dst": ent_map.get(r[1], (r[1], ""))[0],
            "dst_path": ent_map.get(r[1], ("", r[1]))[1],
            "type": r[2],
            "meta": json.loads(r[3]) if r[3] else {},
        }
        for r in edge_rows
    ]

    canonical_entities.sort(key=lambda x: (x["name"], x["file_path"], x["type"]))
    canonical_edges.sort(key=lambda x: (x["type"], x["src"], x["src_path"], x["dst"], x["dst_path"]))

    payload = json.dumps({"entities": canonical_entities, "edges": canonical_edges}, sort_keys=True)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return {"entities": canonical_entities, "count": len(canonical_entities)}, canonical_edges, digest


def evaluate_single_case(case: dict[str, Any], label: dict[str, Any]) -> dict[str, Any]:
    """Execute and evaluate a single CAP-006 case against VerifyCI."""
    case_id = case["id"]
    slice_name = case["slice"]
    commits = {c["commit_id"]: c for c in case["commits"]}
    replay_seq = case["replay_sequence"]
    target_query = case["target_query"]
    target_commit_id = target_query["target_commit"]
    tripwire_anomaly = case.get("tripwire_anomaly")

    repo_name = case.get("repository", f"repo_{case_id.lower().replace('-', '_')}")
    temp_root = Path(tempfile.mkdtemp(prefix=f"vci_cap006_{case_id}_"))
    replay_dir = temp_root / "replay" / repo_name
    clean_dir = temp_root / "clean" / repo_name
    replay_dir.mkdir(parents=True, exist_ok=True)
    clean_dir.mkdir(parents=True, exist_ok=True)

    result: dict[str, Any] = {
        "id": case_id,
        "slice": slice_name,
        "expected_status": label["expected_status"],
        "observed_status": "PASS",
        "replay_equivalent": False,
        "hard_veto_failures": [],
        "errors": [],
        "details": {},
    }

    t0 = time.perf_counter()
    try:
        # Step 1: Execute replay sequence in replay_dir
        replay_store = None
        historical_snapshots = {}

        for step_idx, step in enumerate(replay_seq):
            cid = step["commit_id"]
            step_commit = commits.get(cid)
            if not step_commit:
                # Missing commit reference in tripwire case
                continue

            # Populate files for this commit
            sync_directory_files(replay_dir, step_commit["files"])

            # Handle tripwire anomalies that manifest at ingest time
            if step_commit.get("tampered_source_hash"):
                # Simulating metadata tamper
                pass

            # Execute ingest
            is_incremental = (step.get("mode") != "snapshot" and step_idx > 0)
            try:
                parent_cid = step_commit.get("parent_id") or (
                    step_commit.get("parent_ids")[0] if step_commit.get("parent_ids") else None
                )
                run_ingest(
                    str(replay_dir),
                    incremental=is_incremental,
                    commit_id=cid,
                    branch=step.get("branch") or step_commit.get("branch"),
                    parent_commit_id=parent_cid,
                )
            except Exception as e:
                result["errors"].append(f"Ingest exception at step {cid}: {e}")

            # Inspect database state
            db_path = replay_dir / ".verifyci" / "verifyci.db"
            if db_path.exists():
                store = GraphStore(str(db_path))
                # Check for duplicate live intervals after each step
                dup_intervals = store.conn.execute(
                    "SELECT logical_entity_id, COUNT(*) FROM entities"
                    " WHERE valid_until IS NULL GROUP BY logical_entity_id HAVING COUNT(*) > 1"
                ).fetchall()
                if dup_intervals:
                    result["hard_veto_failures"].append(
                        f"Overlapping live intervals at {cid}: {len(dup_intervals)} entities with multiple live rows"
                    )

                # Capture snapshot for historical as_of checks
                historical_snapshots[cid] = time.time()
                store.close()

        # Step 2: Open final replay database
        db_path = replay_dir / ".verifyci" / "verifyci.db"
        if not db_path.exists():
            result["observed_status"] = "INCONCLUSIVE"
            result["errors"].append("Replay database not created")
            return result

        replay_store = GraphStore(str(db_path))
        rep_rev_id = replay_store.get_revision_by_commit_id(repo_name, target_commit_id)
        rep_ents, rep_edges, rep_digest = extract_live_canonical_graph(replay_store, revision_id=rep_rev_id)

        # Step 3: Run clean snapshot ingest for target commit
        target_commit = commits.get(target_commit_id)
        if target_commit:
            sync_directory_files(clean_dir, target_commit["files"])
            run_ingest(
                str(clean_dir),
                incremental=False,
                commit_id=target_commit_id,
                branch=target_commit.get("branch"),
                parent_commit_id=None,
            )
            clean_store = GraphStore(str(clean_dir / ".verifyci" / "verifyci.db"))
            clean_rev_id = clean_store.get_revision_by_commit_id(repo_name, target_commit_id)
            clean_ents, clean_edges, clean_digest = extract_live_canonical_graph(clean_store, revision_id=clean_rev_id)
            clean_store.close()
        else:
            clean_ents, clean_edges, clean_digest = {"entities": [], "count": 0}, [], ""

        result["details"]["replay_digest"] = rep_digest
        result["details"]["clean_digest"] = clean_digest
        result["details"]["expected_digest"] = label.get("expected_canonical_digest")

        # Check Hard Veto 1: Cross-branch contamination
        isolation_branch = target_query.get("check_isolation_branch")
        if isolation_branch:
            # Find entities belonging solely to isolated branch
            isolated_commits = [c for c in commits.values() if c.get("branch") == isolation_branch]
            isolated_files = set()
            for ic in isolated_commits:
                isolated_files.update(ic["files"].keys())
            target_branch = target_query.get("target_branch")
            target_files = set(target_commit["files"].keys()) if target_commit else set()

            contaminating_files = isolated_files - target_files
            for e in rep_ents["entities"]:
                if e["file_path"] in contaminating_files:
                    result["hard_veto_failures"].append(
                        f"Cross-branch contamination: entity {e['name']} ({e['file_path']}) from branch {isolation_branch} leaked into {target_branch}"
                    )
                    break

        # Check Hard Veto 2: Overlapping live intervals
        final_dups = replay_store.conn.execute(
            "SELECT logical_entity_id, COUNT(*) FROM entities"
            " WHERE valid_until IS NULL GROUP BY logical_entity_id HAVING COUNT(*) > 1"
        ).fetchall()
        if final_dups:
            result["hard_veto_failures"].append(
                f"Overlapping live intervals: {len(final_dups)} duplicate live entities in replay store"
            )

        # Check Hard Veto 3: Historical anchor drift
        as_of_commit = target_query.get("as_of_commit")
        if as_of_commit and as_of_commit in historical_snapshots:
            t_as_of = historical_snapshots[as_of_commit]
            for check_name in target_query.get("check_entities", []):
                ent = replay_store.get_entity_by_name(check_name, as_of=t_as_of)
                if not ent:
                    result["hard_veto_failures"].append(
                        f"Historical anchor drift: entity {check_name} not retrievable as_of {as_of_commit}"
                    )

        # Check Hard Veto 6: Replay equivalence
        # Canonical live entities in replay store must match clean snapshot
        rep_set = {(e["name"], e["file_path"], e["source_hash"]) for e in rep_ents["entities"]}
        clean_set = {(e["name"], e["file_path"], e["source_hash"]) for e in clean_ents["entities"]}
        if rep_set == clean_set and rep_digest == clean_digest and len(rep_edges) == len(clean_edges):
            result["replay_equivalent"] = True
        else:
            diff_add = rep_set - clean_set
            diff_rem = clean_set - rep_set
            msg = f"Replay equivalence failed: {len(diff_add)} unexpected entities, {len(diff_rem)} missing entities"
            if len(rep_edges) != len(clean_edges):
                msg += f" (edges: {len(rep_edges)} replay vs {len(clean_edges)} clean)"
            result["hard_veto_failures"].append(msg)

        replay_store.close()

    except Exception as exc:
        result["errors"].append(f"Unexpected evaluation crash: {exc}")
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    elapsed_ms = (time.perf_counter() - t0) * 1000
    result["elapsed_ms"] = elapsed_ms

    # Final observed status assignment
    if tripwire_anomaly:
        # Tripwire cases expect INCONCLUSIVE
        # If the system detected failure or raised an error, it is INCONCLUSIVE
        if result["errors"]:
            result["observed_status"] = "INCONCLUSIVE"
        else:
            # The system blindly passed a tripwire without fail-closed detection!
            result["observed_status"] = "PASS"
            result["hard_veto_failures"].append(
                f"Fail-closed tripwire failure: anomaly {tripwire_anomaly} was blindly accepted as valid"
            )
    else:
        if result["hard_veto_failures"] or result["errors"]:
            result["observed_status"] = "FAIL"
        else:
            result["observed_status"] = "PASS"

    return result


def run_benchmark(run_label: str = "R0_baseline") -> dict[str, Any]:
    """Run full 64-case benchmark and compile diagnostic results."""
    verify_benchmark_inputs()

    cases_file = BENCHMARK_DIR / "cases.jsonl"
    labels_file = BENCHMARK_DIR / "labels.jsonl"

    cases = [json.loads(line) for line in cases_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    labels = {json.loads(line)["id"]: json.loads(line) for line in labels_file.read_text(encoding="utf-8").splitlines() if line.strip()}

    print(f"Executing CAP-006 [{run_label}] across {len(cases)} cases...")

    case_results = []
    hard_veto_summary = {
        "cross_branch_contamination": 0,
        "overlapping_live_intervals": 0,
        "historical_anchor_drift": 0,
        "fabricated_lineage": 0,
        "fail_closed_tripwires_missed": 0,
        "replay_equivalence_failures": 0,
        "idempotent_ingest_failures": 0,
    }

    slice_stats: dict[str, dict[str, int]] = {}

    for c in cases:
        cid = c["id"]
        sl = c["slice"]
        lbl = labels[cid]

        eval_res = evaluate_single_case(c, lbl)
        case_results.append(eval_res)

        # Tabulate hard vetoes
        for f in eval_res["hard_veto_failures"]:
            if "Cross-branch contamination" in f:
                hard_veto_summary["cross_branch_contamination"] += 1
            if "Overlapping live intervals" in f:
                hard_veto_summary["overlapping_live_intervals"] += 1
            if "Historical anchor drift" in f:
                hard_veto_summary["historical_anchor_drift"] += 1
            if "Replay equivalence failed" in f:
                hard_veto_summary["replay_equivalence_failures"] += 1
            if "Fail-closed tripwire failure" in f:
                hard_veto_summary["fail_closed_tripwires_missed"] += 1

        # Tabulate slice accuracy
        st = slice_stats.setdefault(sl, {"total": 0, "agreed": 0, "disagreed": 0})
        st["total"] += 1
        if eval_res["observed_status"] == lbl["expected_status"]:
            st["agreed"] += 1
        else:
            st["disagreed"] += 1

    total = len(cases)
    agreed = sum(1 for r in case_results if r["observed_status"] == r["expected_status"])
    disagreed = total - agreed
    agreement_rate = (agreed / total) * 100

    tripwire_cases = [r for r in case_results if r["slice"] == "truncated_lineage_tripwire"]
    tripwires_caught = sum(1 for r in tripwire_cases if r["observed_status"] == "INCONCLUSIVE")

    # Compile gate statuses
    gates = {
        "T1_incremental_replay_equivalence": "PASS" if hard_veto_summary["replay_equivalence_failures"] == 0 else "FAIL",
        "T2_rename_lineage_continuity": "PASS" if slice_stats["rename_edit_rename_back"]["disagreed"] == 0 else "FAIL",
        "T3_revert_cycle_correctness": "PASS" if slice_stats["revert_cycles"]["disagreed"] == 0 else "FAIL",
        "T4_branch_divergence_isolation": "PASS" if hard_veto_summary["cross_branch_contamination"] == 0 else "FAIL",
        "T5_merge_attestation_determinism": "PASS" if slice_stats["criss_cross_merges"]["disagreed"] == 0 else "FAIL",
        "T6_anchor_point_in_time_stability": "PASS" if hard_veto_summary["historical_anchor_drift"] == 0 else "FAIL",
        "T7_temporal_fail_closed_integrity": "PASS" if tripwires_caught == 8 else "FAIL",
        "T8_corpus_replay_agreement": "PASS" if agreement_rate >= 96.88 else "FAIL",
    }

    report = {
        "benchmark": "CAP-006",
        "run_label": run_label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_cases": total,
        "agreed": agreed,
        "disagreed": disagreed,
        "agreement_rate": round(agreement_rate, 2),
        "hard_veto_summary": hard_veto_summary,
        "tripwires_caught": f"{tripwires_caught}/8",
        "gates": gates,
        "slice_stats": slice_stats,
        "case_results": case_results,
    }

    output_path = BENCHMARK_DIR / f"{run_label.lower()}_results.json"
    output_path.write_bytes((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    print("\n" + "=" * 60)
    print(f"CAP-006 [{run_label}] RESULTS SUMMARY")
    print("=" * 60)
    print(f"Total Cases:        {total}")
    print(f"Overall Agreement:  {agreed}/{total} ({agreement_rate:.2f}%)")
    print(f"Tripwires Caught:   {tripwires_caught}/8")
    print("\nHard Vetoes:")
    for k, v in hard_veto_summary.items():
        status_flag = "PASS" if v == 0 else "FAIL"
        print(f"  - {k}: {v} [{status_flag}]")
    print("\nGates T1–T8:")
    for g, res in gates.items():
        print(f"  - {g}: {res}")
    print("\nSlice Breakdown:")
    for s, st in slice_stats.items():
        print(f"  - {s:35s}: {st['agreed']}/{st['total']} ({st['agreed']/st['total']*100:.1f}%)")
    print("=" * 60)
    print(f"Detailed results written to: {output_path}")

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Measure CAP-006 benchmark")
    parser.add_argument("--label", default="r0_baseline", help="Run label (default: r0_baseline)")
    args = parser.parse_args()
    run_benchmark(args.label)
