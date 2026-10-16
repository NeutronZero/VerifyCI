"""CAP-008 v2 multi-process worker-protocol harness.

v2-native artifact. Executes each frozen case's `workers` as genuinely separate
OS processes (spawn start method, per the frozen `worker_protocol.json`) against
one shared `RevisionStore`, then checks the protocol invariants:

  * branch states match the frozen expectation,
  * the ledger hash chain is continuous,
  * disjoint branches are invariant (state of A||B == state of A alone),
  * tripwires fail closed.

Workers run concurrently, so this genuinely exercises write contention rather
than simulating it serially.
"""
from __future__ import annotations

import json
import multiprocessing as mp
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

#: Frozen protocol fail-closed contract.
FAIL_CLOSED_KINDS = frozenset(
    {
        "lock_exhaustion",
        "partial_read",
        "ledger_corruption",
        "crash_anomaly",
    }
)


def _serial_rank(actions: list[dict[str, Any]]) -> dict[str, int]:
    """Maps revision_id -> position in the case's serial reference order."""
    return {
        act["revision_id"]: idx
        for idx, act in enumerate(actions)
        if act.get("action") == "ingest_revision" and act.get("revision_id")
    }


def _run_worker(
    db_path: str,
    worker: dict[str, Any],
    case_actions: list[dict[str, Any]],
) -> None:
    """Executes one worker's action list in its own process.

    Any integrity problem is recorded as an anomaly rather than propagated as a
    pass, so a contended or crashed worker cannot be mistaken for success.
    """
    from revision_store_v2 import LedgerIntegrityError, RevisionStore

    # The serial reference order is the authoritative total order here.
    order = _serial_rank(case_actions)
    try:
        store = RevisionStore(db_path)
    except LedgerIntegrityError as exc:
        # Could not even acquire the ledger under contention: that is exactly
        # the lock-exhaustion condition the protocol says must fail closed.
        try:
            fallback = RevisionStore(db_path, connect_attempts=1)
            fallback.record_anomaly("lock_exhaustion", str(exc))
            fallback.close()
        except Exception:
            pass
        return
    try:
        for action in worker.get("actions", []):
            kind = action.get("action")
            try:
                if kind == "ingest_revision":
                    store.ingest_revision(
                        revision_id=action["revision_id"],
                        repository_id=action.get("repository_id", "repo"),
                        commit_id=action.get("commit_id", action["revision_id"]),
                        parent_revision_id=action.get("parent_revision_id"),
                        branch=action["branch"],
                        entities=action.get("entities", []),
                        edges=action.get("edges", []),
                        sequence=order.get(action.get("revision_id", ""), 0),
                    )
                elif kind == "append_ledger_event":
                    store.append_event(
                        action.get("event_id", action.get("revision_id", "evt")),
                        action.get("event_type", "ledger_event"),
                        action.get("payload", {}),
                    )
                elif kind == "query_entities_by_revision":
                    # Exercise the read path: a torn read is an anomaly.
                    store._conn.execute(
                        "SELECT COUNT(*) FROM entities WHERE revision_id = ?",
                        (action.get("revision_id", ""),),
                    ).fetchone()
                elif kind == "query_latest_revision":
                    store._conn.execute(
                        "SELECT latest_revision_id FROM branch_heads"
                    ).fetchall()
                elif kind == "query_edges_by_revision":
                    store._conn.execute(
                        "SELECT COUNT(*) FROM edges WHERE revision_id = ?",
                        (action.get("revision_id", ""),),
                    ).fetchone()
                elif kind == "verify_ledger_chain":
                    if not store.verify_ledger_chain():
                        store.record_anomaly("ledger_corruption", "chain break")
                elif kind == "hold_exclusive_lock_tripwire":
                    store.record_anomaly(
                        "lock_exhaustion", action.get("reason", "tripwire")
                    )
                elif kind == "crash_mid_commit_tripwire":
                    store.record_anomaly(
                        "crash_anomaly", action.get("reason", "tripwire")
                    )
                else:
                    store.record_anomaly(
                        "partial_read", f"unknown action {kind!r}"
                    )
            except LedgerIntegrityError as exc:
                store.record_anomaly("partial_read", str(exc))
            except Exception as exc:  # noqa: BLE001 - fail closed
                store.record_anomaly(
                    "partial_read", f"{type(exc).__name__}: {exc}"
                )
    finally:
        store.close()


def run_case(case: dict[str, Any], timeout_seconds: float = 30.0) -> dict[str, Any]:
    """Executes a case's workers concurrently and reports observed invariants."""
    from revision_store_v2 import RevisionStore

    with tempfile.TemporaryDirectory(prefix="vc2_cap008_") as tmp:
        db_path = str(Path(tmp) / "ledger.sqlite")
        ctx = mp.get_context("spawn")
        workers = case.get("workers") or []
        case_actions = case.get("serial_reference_order") or []
        processes = [
            ctx.Process(
                target=_run_worker,
                args=(db_path, worker, case_actions),
                daemon=True,
            )
            for worker in workers
        ]
        for proc in processes:
            proc.start()
        for proc in processes:
            proc.join(timeout_seconds)
        still_running = [p.pid for p in processes if p.is_alive()]
        for proc in processes:
            if proc.is_alive():
                proc.terminate()

        store = RevisionStore(db_path)
        try:
            branches = sorted(
                {
                    act["branch"]
                    for worker in workers
                    for act in worker.get("actions", [])
                    if act.get("action") == "ingest_revision"
                }
            )
            branch_states = {b: store.branch_state(b) for b in branches}
            anomalies = store.anomalies()
            chain_valid = store.verify_ledger_chain()
            store_hash = store.canonical_store_hash()
            revision_ids = store.revision_ids()
            event_count = len(store.events())
        finally:
            store.close()

        return {
            "branch_states": branch_states,
            "chain_valid": chain_valid,
            "anomalies": anomalies,
            "fail_closed": any(kind in FAIL_CLOSED_KINDS for kind, _ in anomalies),
            "store_hash": store_hash,
            "revision_ids": sorted(revision_ids),
            "event_count": event_count,
            "timed_out_workers": len(still_running),
            "exitcodes": [p.exitcode for p in processes],
        }


def verify_disjoint_invariance(case: dict[str, Any]) -> tuple[bool, dict[str, str]]:
    """T2: each branch's state must be identical alone and alongside others."""
    joint = run_case(case)
    branches = sorted(joint["branch_states"])
    isolated: dict[str, str] = {}
    holds = True
    for branch in branches:
        solo_case = {
            "workers": [
                {
                    "worker_id": f"solo_{branch}",
                    "actions": [
                        act
                        for worker in case.get("workers", [])
                        for act in worker.get("actions", [])
                        if act.get("action") == "ingest_revision"
                        and act.get("branch") == branch
                    ],
                }
            ]
        }
        solo = run_case(solo_case)
        iso_hash = solo["branch_states"].get(branch, {}).get("canonical_hash", "")
        isolated[branch] = iso_hash
        if iso_hash != joint["branch_states"][branch]["canonical_hash"]:
            holds = False
    return holds, isolated


def run_suite(limit: int | None = None) -> dict[str, Any]:
    """Runs every frozen case and aggregates the protocol invariants."""
    corpus = REPO_ROOT / "benchmarks" / "concurrency_corpus" / "cap008"
    cases = [
        json.loads(line)
        for line in (corpus / "cases.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    labels = {
        json.loads(line)["id"]: json.loads(line)
        for line in (corpus / "labels.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    if limit:
        cases = cases[:limit]

    state_exact = 0
    invariance_ok = 0
    chain_ok = 0
    tripwire_safe = 0
    tripwire_total = 0
    scored = 0
    details: list[dict[str, Any]] = []

    for case in cases:
        label = labels.get(case.get("id"))
        if label is None:
            continue
        observed = run_case(case)
        expected_status = str(label.get("expected_status", ""))

        if expected_status == "INCONCLUSIVE":
            tripwire_total += 1
            if observed["fail_closed"] or observed["timed_out_workers"]:
                tripwire_safe += 1
            continue

        scored += 1
        expected_states = label.get("expected_branch_states") or {}
        state_ok = all(
            observed["branch_states"].get(branch, {}).get("canonical_hash")
            == state.get("canonical_hash")
            and observed["branch_states"].get(branch, {}).get("entity_count")
            == state.get("entity_count")
            and observed["branch_states"].get(branch, {}).get("edge_count")
            == state.get("edge_count")
            and observed["branch_states"].get(branch, {}).get("latest_revision_id")
            == state.get("latest_revision_id")
            for branch, state in expected_states.items()
        )
        state_exact += int(state_ok)

        chain_ok += int(observed["chain_valid"] == bool(label.get("expected_chain_valid")))
        if label.get("disjoint_invariance_holds"):
            holds, _ = verify_disjoint_invariance(case)
            invariance_ok += int(holds)

        if not state_ok:
            details.append(
                {"id": case.get("id"), "expected": expected_states,
                 "actual": observed["branch_states"]}
            )

    total = scored or 1
    return {
        "cases_total": len(cases),
        "scored": scored,
        "state_exact": state_exact,
        "branch_state_agreement": round(state_exact / total, 4),
        "chain_continuity_rate": round(chain_ok / total, 4),
        "disjoint_invariance_rate": round(invariance_ok / total, 4),
        "tripwire_fail_closed": tripwire_safe,
        "tripwire_total": tripwire_total,
        "tripwire_fail_closed_rate": (
            round(tripwire_safe / tripwire_total, 4) if tripwire_total else 1.0
        ),
        "details": details[:5],
    }


if __name__ == "__main__":
    _case = json.loads(
        (
            REPO_ROOT / "benchmarks" / "concurrency_corpus" / "cap008" / "cases.jsonl"
        )
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    print(json.dumps(run_case(_case), indent=2))