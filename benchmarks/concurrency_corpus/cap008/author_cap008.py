"""Generator script for CAP-008 Concurrency & Shared-Storage Corpus.

Generates:
- cases.jsonl (64 cases across 8 slices)
- labels.jsonl (48 PASS, 16 INCONCLUSIVE gold labels)
- oracle_manifest.jsonl (independent oracle evaluation manifest)
- CORPUS_SHA256, LABEL_SHA256, ORACLE_MANIFEST_SHA256
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

# Protocol LOCK-2 check: authoring script imports ONLY oracle.py from the benchmark dir
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import oracle  # noqa: E402


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generate_cap008_corpus() -> tuple[list[dict], list[dict], list[dict]]:
    cases: list[dict] = []
    labels: list[dict] = []
    manifest: list[dict] = []

    case_num = 1

    # =========================================================================
    # Slice 1: two_worker_read_write_contention (8 cases: cap008_c01 - c08)
    # =========================================================================
    s1_scenarios = [
        ("2w_reader_during_bulk_ingest", 10, 8),
        ("2w_reader_during_edge_batch_insert", 15, 20),
        ("2w_repeated_queries_during_linear_commits", 8, 6),
        ("2w_historical_as_of_read_during_write", 12, 10),
        ("2w_blast_radius_read_during_ingest", 14, 12),
        ("2w_reader_observing_revert_commit", 10, 8),
        ("2w_rapid_interleaved_small_commits_reads", 6, 4),
        ("2w_heavy_entity_ingest_with_hot_reader", 30, 25),
    ]
    for name, n_ent, n_edge in s1_scenarios:
        cid = f"cap008_c{case_num:02d}"
        entities = [
            {"logical_id": f"s1_ent_{cid}_{i}", "type": "FUNCTION", "name": f"fn_{i}", "file_path": f"src/mod_{cid}.py"}
            for i in range(n_ent)
        ]
        edges = [
            {"src": f"s1_ent_{cid}_{i}", "dst": f"s1_ent_{cid}_{(i+1)%n_ent}", "type": "CALLS"}
            for i in range(n_edge)
        ]
        rev_id = f"rev_{cid}_01"
        writer_action = {
            "action": "ingest_revision",
            "revision_id": rev_id,
            "repository_id": "repo_c08",
            "commit_id": f"commit_{cid}_01",
            "branch": "main",
            "entities": entities,
            "edges": edges,
        }
        reader_action = {
            "action": "query_entities_by_revision",
            "revision_id": rev_id,
        }

        case = {
            "id": cid,
            "name": name,
            "slice": "two_worker_read_write_contention",
            "worker_count": 2,
            "workers": [
                {"worker_id": "w0", "role": "writer", "actions": [writer_action]},
                {"worker_id": "w1", "role": "reader", "actions": [reader_action]},
            ],
            "initial_state": None,
            "serial_reference_order": [writer_action, reader_action],
            "is_tripwire": False,
            "concurrency_params": {"busy_timeout_ms": 5000, "wal_autocheckpoint": 1000},
            "expected_status": "PASS",
        }
        cases.append(case)
        case_num += 1

    # =========================================================================
    # Slice 2: four_worker_mixed_ingest_query (8 cases: cap008_c09 - c16)
    # =========================================================================
    s2_scenarios = [
        "4w_two_writers_two_readers_orthogonal_packages",
        "4w_three_readers_one_writer_bulk_graph",
        "4w_three_writers_one_reader_disjoint_modules",
        "4w_two_writers_alternating_commits_two_readers",
        "4w_mixed_ingest_and_ledger_append_with_readers",
        "4w_pipeline_ingest_query_anchor_verification",
        "4w_concurrent_multi_file_refactor_ingest",
        "4w_two_readers_polling_latest_while_two_writers_commit",
    ]
    for idx, name in enumerate(s2_scenarios):
        cid = f"cap008_c{case_num:02d}"
        rev_a = f"rev_{cid}_w0"
        rev_b = f"rev_{cid}_w1"
        act_w0 = {
            "action": "ingest_revision",
            "revision_id": rev_a,
            "repository_id": "repo_c08",
            "commit_id": f"commit_{cid}_a",
            "branch": "main",
            "entities": [{"logical_id": f"s2_a_{cid}_{i}", "type": "CLASS", "name": f"Cls_{i}", "file_path": "a.py"} for i in range(8)],
            "edges": [{"src": f"s2_a_{cid}_{i}", "dst": f"s2_a_{cid}_{(i+1)%8}", "type": "CALLS"} for i in range(6)],
        }
        act_w1 = {
            "action": "ingest_revision",
            "revision_id": rev_b,
            "repository_id": "repo_c08",
            "commit_id": f"commit_{cid}_b",
            "branch": "main",
            "entities": [{"logical_id": f"s2_b_{cid}_{i}", "type": "FUNCTION", "name": f"fn_{i}", "file_path": "b.py"} for i in range(8)],
            "edges": [{"src": f"s2_b_{cid}_{i}", "dst": f"s2_b_{cid}_{(i+1)%8}", "type": "CALLS"} for i in range(6)],
        }
        act_w2 = {"action": "query_latest_revision", "repository_id": "repo_c08", "branch": "main"}
        act_w3 = {"action": "query_entities_by_revision", "revision_id": rev_a}

        case = {
            "id": cid,
            "name": name,
            "slice": "four_worker_mixed_ingest_query",
            "worker_count": 4,
            "workers": [
                {"worker_id": "w0", "role": "writer", "actions": [act_w0]},
                {"worker_id": "w1", "role": "writer", "actions": [act_w1]},
                {"worker_id": "w2", "role": "reader", "actions": [act_w2]},
                {"worker_id": "w3", "role": "reader", "actions": [act_w3]},
            ],
            "initial_state": None,
            "serial_reference_order": [act_w0, act_w1, act_w2, act_w3],
            "is_tripwire": False,
            "concurrency_params": {"busy_timeout_ms": 5000, "wal_autocheckpoint": 1000},
            "expected_status": "PASS",
        }
        cases.append(case)
        case_num += 1

    # =========================================================================
    # Slice 3: eight_worker_high_contention (8 cases: cap008_c17 - c24)
    # =========================================================================
    s3_scenarios = [
        "8w_four_writers_four_readers_burst_ingest",
        "8w_six_writers_two_readers_shared_db",
        "8w_two_writers_six_readers_contention_storm",
        "8w_all_writing_distinct_revisions",
        "8w_heavy_contention_wal_checkpoint_pressure",
        "8w_concurrent_entity_lookup_and_batch_inserts",
        "8w_rapid_successive_transactions_stress",
        "8w_saturated_reader_writer_concurrency",
    ]
    for idx, name in enumerate(s3_scenarios):
        cid = f"cap008_c{case_num:02d}"
        workers = []
        serial_order = []
        for w_idx in range(8):
            wid = f"w{w_idx}"
            if w_idx < 4:
                rev_id = f"rev_{cid}_w{w_idx}"
                act = {
                    "action": "ingest_revision",
                    "revision_id": rev_id,
                    "repository_id": "repo_c08",
                    "commit_id": f"commit_{cid}_{w_idx}",
                    "branch": "main",
                    "entities": [{"logical_id": f"s3_{cid}_{w_idx}_{i}", "type": "FUNCTION", "name": f"f_{i}", "file_path": f"w{w_idx}.py"} for i in range(5)],
                    "edges": [{"src": f"s3_{cid}_{w_idx}_0", "dst": f"s3_{cid}_{w_idx}_1", "type": "CALLS"}],
                }
                workers.append({"worker_id": wid, "role": "writer", "actions": [act]})
                serial_order.append(act)
            else:
                act = {"action": "query_latest_revision", "repository_id": "repo_c08", "branch": "main"}
                workers.append({"worker_id": wid, "role": "reader", "actions": [act]})
                serial_order.append(act)

        case = {
            "id": cid,
            "name": name,
            "slice": "eight_worker_high_contention",
            "worker_count": 8,
            "workers": workers,
            "initial_state": None,
            "serial_reference_order": serial_order,
            "is_tripwire": False,
            "concurrency_params": {"busy_timeout_ms": 5000, "wal_autocheckpoint": 1000},
            "expected_status": "PASS",
        }
        cases.append(case)
        case_num += 1

    # =========================================================================
    # Slice 4: same_branch_concurrent_ingest (8 cases: cap008_c25 - c32)
    # =========================================================================
    s4_scenarios = [
        "same_branch_two_workers_linear_serialization",
        "same_branch_three_workers_ordered_ingest_commits",
        "same_branch_four_workers_successive_patches",
        "same_branch_concurrent_append_only_ingest_log",
        "same_branch_interleaved_patch_and_revert",
        "same_branch_competing_commits_latest_advancement",
        "same_branch_monotonic_lineage_no_rewind",
        "same_branch_multi_worker_shared_head_serialization",
    ]
    for idx, name in enumerate(s4_scenarios):
        cid = f"cap008_c{case_num:02d}"
        n_workers = 2 if idx < 3 else (3 if idx < 6 else 4)
        workers = []
        serial_order = []
        for w_idx in range(n_workers):
            rev_id = f"rev_{cid}_step{w_idx}"
            act = {
                "action": "ingest_revision",
                "revision_id": rev_id,
                "repository_id": "repo_c08",
                "commit_id": f"commit_{cid}_{w_idx}",
                "parent_revision_id": f"rev_{cid}_step{w_idx-1}" if w_idx > 0 else None,
                "branch": "main",
                "entities": [{"logical_id": f"s4_ent_{cid}_{w_idx}_{i}", "type": "FUNCTION", "name": f"sb_{i}", "file_path": "main.py"} for i in range(6)],
                "edges": [{"src": f"s4_ent_{cid}_{w_idx}_0", "dst": f"s4_ent_{cid}_{w_idx}_1", "type": "CALLS"}],
            }
            workers.append({"worker_id": f"w{w_idx}", "role": "writer", "actions": [act]})
            serial_order.append(act)

        case = {
            "id": cid,
            "name": name,
            "slice": "same_branch_concurrent_ingest",
            "worker_count": n_workers,
            "workers": workers,
            "initial_state": None,
            "serial_reference_order": serial_order,
            "is_tripwire": False,
            "concurrency_params": {"busy_timeout_ms": 5000, "wal_autocheckpoint": 1000},
            "expected_status": "PASS",
        }
        cases.append(case)
        case_num += 1

    # =========================================================================
    # Slice 5: different_branch_concurrent_ingest (8 cases: cap008_c33 - c40)
    # =========================================================================
    s5_scenarios = [
        ("diff_branch_two_workers_main_and_feature", ["main", "feature/auth"]),
        ("diff_branch_three_workers_orthogonal_features", ["feat/ui", "feat/api", "feat/db"]),
        ("diff_branch_four_workers_disjoint_subsystems", ["branch_a", "branch_b", "branch_c", "branch_d"]),
        ("diff_branch_feature_and_hotfix_isolation", ["feature/search", "hotfix/cve_patch"]),
        ("diff_branch_deep_history_divergence_invariance", ["alpha", "beta", "gamma"]),
        ("diff_branch_rapid_alternating_branch_commits", ["branch_x", "branch_y"]),
        ("diff_branch_multi_branch_query_isolation", ["branch_1", "branch_2", "branch_3"]),
        ("diff_branch_six_workers_disjoint_trees_strict_invariance", ["b_one", "b_two", "b_three", "b_four", "b_five", "b_six"]),
    ]
    for name, branch_list in s5_scenarios:
        cid = f"cap008_c{case_num:02d}"
        workers = []
        serial_order = []
        for w_idx, br in enumerate(branch_list):
            rev_id = f"rev_{cid}_{br.replace('/', '_')}"
            act = {
                "action": "ingest_revision",
                "revision_id": rev_id,
                "repository_id": "repo_c08",
                "commit_id": f"commit_{cid}_{w_idx}",
                "branch": br,
                "entities": [{"logical_id": f"s5_ent_{cid}_{w_idx}_{i}", "type": "FUNCTION", "name": f"f_{i}", "file_path": f"{br}.py"} for i in range(5)],
                "edges": [{"src": f"s5_ent_{cid}_{w_idx}_0", "dst": f"s5_ent_{cid}_{w_idx}_1", "type": "CALLS"}],
            }
            workers.append({"worker_id": f"w{w_idx}", "role": "writer", "actions": [act]})
            serial_order.append(act)

        case = {
            "id": cid,
            "name": name,
            "slice": "different_branch_concurrent_ingest",
            "worker_count": len(branch_list),
            "workers": workers,
            "initial_state": None,
            "serial_reference_order": serial_order,
            "is_tripwire": False,
            "concurrency_params": {"busy_timeout_ms": 5000, "wal_autocheckpoint": 1000},
            "expected_status": "PASS",
        }
        cases.append(case)
        case_num += 1

    # =========================================================================
    # Slice 6: certificate_ledger_concurrent_writes (8 cases: cap008_c41 - c48)
    # =========================================================================
    s6_scenarios = [
        ("ledger_two_workers_concurrent_event_append", 2, 4),
        ("ledger_four_workers_verification_certificates", 4, 3),
        ("ledger_eight_workers_concurrent_attestations", 8, 2),
        ("ledger_hash_continuity_under_contention", 3, 5),
        ("ledger_zero_lost_events_under_heavy_append", 4, 6),
        ("ledger_concurrent_reads_during_event_logging", 2, 4),
        ("ledger_interleaved_anchor_snapshots_and_events", 3, 4),
        ("ledger_deterministic_ancestry_serialization", 4, 3),
    ]
    for name, n_workers, evts_per_w in s6_scenarios:
        cid = f"cap008_c{case_num:02d}"
        workers = []
        serial_order = []
        for w_idx in range(n_workers):
            w_actions = []
            for e_idx in range(evts_per_w):
                evt_id = f"evt_{cid}_{w_idx}_{e_idx}"
                act = {
                    "action": "append_event",
                    "event_id": evt_id,
                    "type": "VERIFICATION_CERTIFICATE",
                    "payload": {"worker": f"w{w_idx}", "seq": e_idx, "status": "VERIFIED"},
                }
                w_actions.append(act)
                serial_order.append(act)
            workers.append({"worker_id": f"w{w_idx}", "role": "auditor", "actions": w_actions})

        case = {
            "id": cid,
            "name": name,
            "slice": "certificate_ledger_concurrent_writes",
            "worker_count": n_workers,
            "workers": workers,
            "initial_state": None,
            "serial_reference_order": serial_order,
            "is_tripwire": False,
            "concurrency_params": {"busy_timeout_ms": 5000, "wal_autocheckpoint": 1000},
            "expected_status": "PASS",
        }
        cases.append(case)
        case_num += 1

    # =========================================================================
    # Slice 7: forced_lock_timeout_exhaustion_tripwires (8 cases: cap008_c49 - c56)
    # =========================================================================
    s7_scenarios = [
        ("tripwire_exclusive_lock_held_beyond_busy_timeout", "LOCK_TIMEOUT_EXHAUSTION"),
        ("tripwire_writer_exhausts_retry_budget_on_locked_table", "RETRY_BUDGET_EXHAUSTION"),
        ("tripwire_deadlock_inducer_concurrent_exclusive_requests", "DEADLOCK_TIMEOUT"),
        ("tripwire_transaction_lock_held_blocking_readers_ro_mount", "READ_MOUNT_LOCK_TIMEOUT"),
        ("tripwire_cascading_busy_timeout_across_four_workers", "CASCADING_LOCK_TIMEOUT"),
        ("tripwire_retry_limit_exceeded_fail_closed_veto", "RETRY_LIMIT_EXCEEDED"),
        ("tripwire_exclusive_dml_lock_exhaustion_inconclusive", "DML_LOCK_TIMEOUT"),
        ("tripwire_unresolvable_lock_contention_no_partial_pass", "UNRESOLVABLE_CONTENTION"),
    ]
    for name, mechanism in s7_scenarios:
        cid = f"cap008_c{case_num:02d}"
        case = {
            "id": cid,
            "name": name,
            "slice": "forced_lock_timeout_exhaustion_tripwires",
            "worker_count": 2,
            "workers": [
                {
                    "worker_id": "w0",
                    "role": "adversary",
                    "actions": [{"action": "hold_exclusive_lock", "duration_ms": 8000}],
                },
                {
                    "worker_id": "w1",
                    "role": "writer",
                    "actions": [
                        {
                            "action": "ingest_revision",
                            "revision_id": f"rev_{cid}_fail",
                            "branch": "main",
                            "timeout_ms": 3000,
                        }
                    ],
                },
            ],
            "initial_state": None,
            "serial_reference_order": [],
            "is_tripwire": True,
            "tripwire_type": mechanism,
            "concurrency_params": {"busy_timeout_ms": 3000, "wal_autocheckpoint": 1000},
            "expected_status": "INCONCLUSIVE",
        }
        cases.append(case)
        case_num += 1

    # =========================================================================
    # Slice 8: crash_interruption_during_commit_tripwires (8 cases: cap008_c57 - c64)
    # =========================================================================
    s8_scenarios = [
        ("tripwire_worker_crashes_mid_revision_commit", "CRASH_MID_COMMIT_TRANSACTION"),
        ("tripwire_aborted_batch_insert_rollback_verification", "ABORTED_BATCH_INSERT"),
        ("tripwire_kill_during_edge_population_no_orphans", "SIGKILL_DURING_MUTATION"),
        ("tripwire_interrupted_event_append_chain_fail_closed", "INTERRUPTED_EVENT_CHAIN"),
        ("tripwire_reader_detects_uncommitted_revision_inconclusive", "UNCOMMITTED_STATE_INTERCEPTED"),
        ("tripwire_crashed_ingest_leaves_zero_partial_entities", "ROLLBACK_UNCOMMITTED_ENTITIES"),
        ("tripwire_corrupted_wal_sidecar_fail_closed", "CORRUPTED_WAL_HEADER"),
        ("tripwire_unfinalized_transaction_isolation_veto", "UNFINALIZED_TRANSACTION_VETO"),
    ]
    for name, mechanism in s8_scenarios:
        cid = f"cap008_c{case_num:02d}"
        case = {
            "id": cid,
            "name": name,
            "slice": "crash_interruption_during_commit_tripwires",
            "worker_count": 2,
            "workers": [
                {
                    "worker_id": "w0",
                    "role": "crasher",
                    "actions": [
                        {
                            "action": "abort_mid_transaction",
                            "revision_id": f"rev_{cid}_uncommitted",
                            "abort_stage": "post_entity_pre_commit",
                        }
                    ],
                },
                {
                    "worker_id": "w1",
                    "role": "reader",
                    "actions": [
                        {
                            "action": "query_entities_by_revision",
                            "revision_id": f"rev_{cid}_uncommitted",
                        }
                    ],
                },
            ],
            "initial_state": None,
            "serial_reference_order": [],
            "is_tripwire": True,
            "tripwire_type": mechanism,
            "concurrency_params": {"busy_timeout_ms": 5000, "wal_autocheckpoint": 1000},
            "expected_status": "INCONCLUSIVE",
        }
        cases.append(case)
        case_num += 1

    # Evaluate all cases through independent oracle
    for case in cases:
        verdict = oracle.evaluate_case(case)

        # Label entry
        label = {
            "id": case["id"],
            "slice": case["slice"],
            "expected_status": verdict["expected_status"],
            "expected_revisions": verdict["expected_revisions"],
            "expected_branch_states": verdict["expected_branch_states"],
            "expected_event_count": verdict["expected_event_count"],
            "expected_chain_valid": verdict["chain_continuity_valid"],
            "disjoint_invariance_holds": verdict["disjoint_invariance_holds"],
            "tripwire_mechanism": verdict["tripwire_mechanism"],
        }
        labels.append(label)

        # Manifest entry
        case_json_bytes = json.dumps(case, sort_keys=True).encode("utf-8")
        manifest_entry = {
            "id": case["id"],
            "slice": case["slice"],
            "input_hash": compute_sha256(case_json_bytes),
            "expected_status": verdict["expected_status"],
            "oracle_verdict": verdict,
            "oracle_state_hash": verdict["canonical_state_hash"],
        }
        manifest.append(manifest_entry)

    return cases, labels, manifest


def main() -> None:
    cases, labels, manifest = generate_cap008_corpus()

    cases_file = SCRIPT_DIR / "cases.jsonl"
    labels_file = SCRIPT_DIR / "labels.jsonl"
    manifest_file = SCRIPT_DIR / "oracle_manifest.jsonl"

    cases_content = "\n".join(json.dumps(c, sort_keys=True) for c in cases) + "\n"
    labels_content = "\n".join(json.dumps(lbl, sort_keys=True) for lbl in labels) + "\n"
    manifest_content = "\n".join(json.dumps(m, sort_keys=True) for m in manifest) + "\n"

    cases_file.write_text(cases_content, encoding="utf-8")
    labels_file.write_text(labels_content, encoding="utf-8")
    manifest_file.write_text(manifest_content, encoding="utf-8")

    c_hash = compute_sha256(cases_file.read_bytes())
    l_hash = compute_sha256(labels_file.read_bytes())
    m_hash = compute_sha256(manifest_file.read_bytes())

    (SCRIPT_DIR / "CORPUS_SHA256").write_text(c_hash + "\n", encoding="utf-8")
    (SCRIPT_DIR / "LABEL_SHA256").write_text(l_hash + "\n", encoding="utf-8")
    (SCRIPT_DIR / "ORACLE_MANIFEST_SHA256").write_text(m_hash + "\n", encoding="utf-8")

    pass_count = sum(1 for lbl in labels if lbl["expected_status"] == "PASS")
    incon_count = sum(1 for lbl in labels if lbl["expected_status"] == "INCONCLUSIVE")

    print("CAP-008 Corpus Generation Complete:")
    print(f"  Total Cases: {len(cases)}")
    print(f"  PASS Cases: {pass_count}")
    print(f"  INCONCLUSIVE Cases: {incon_count}")
    print(f"  CORPUS_SHA256:          {c_hash}")
    print(f"  LABEL_SHA256:           {l_hash}")
    print(f"  ORACLE_MANIFEST_SHA256: {m_hash}")


if __name__ == "__main__":
    main()
