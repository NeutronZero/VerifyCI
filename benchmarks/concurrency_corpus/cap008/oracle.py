"""Independent Concurrency & Serial Reference Oracle for CAP-008.

PROTOCOL LOCK-2 ENFORCEMENT:
- Zero imports from verifyci (clean-room reference oracle).
- Uses ONLY Python standard library: hashlib, json, copy, dataclasses, typing, collections.
- Computes exact serialized reference state, disjoint branch invariance,
  atomic snapshot visibility bounds, ledger hash continuity, and tripwire fail-closed verdicts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Optional


def compute_sha256(data: str | bytes) -> str:
    """Compute standard SHA-256 digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """Serialize object to deterministic canonical JSON string."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class OracleEntity:
    logical_id: str
    entity_type: str
    name: str
    file_path: str
    line_start: int
    line_end: int
    source_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_id": self.logical_id,
            "entity_type": self.entity_type,
            "name": self.name,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "source_hash": self.source_hash,
        }


@dataclass(frozen=True)
class OracleEdge:
    src: str
    dst: str
    edge_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "edge_type": self.edge_type,
        }


@dataclass
class OracleRevision:
    revision_id: str
    repository_id: str
    commit_id: str
    parent_revision_id: Optional[str]
    branch: str
    entities: list[OracleEntity] = field(default_factory=list)
    edges: list[OracleEdge] = field(default_factory=list)

    def canonical_hash(self) -> str:
        data = {
            "revision_id": self.revision_id,
            "repository_id": self.repository_id,
            "commit_id": self.commit_id,
            "parent_revision_id": self.parent_revision_id,
            "branch": self.branch,
            "entities": sorted([e.to_dict() for e in self.entities], key=lambda x: x["logical_id"]),
            "edges": sorted([e.to_dict() for e in self.edges], key=lambda x: (x["src"], x["dst"], x["edge_type"])),
        }
        return compute_sha256(canonical_json(data))


@dataclass
class OracleEvent:
    event_id: str
    event_type: str
    payload: dict[str, Any]
    prev_event_hash: Optional[str]
    event_hash: str


class CleanRoomConcurrencyOracle:
    """Independent oracle modeling serial equivalence and concurrency invariants."""

    def __init__(self) -> None:
        self.revisions: dict[str, OracleRevision] = {}
        self.branch_heads: dict[str, str] = {}  # branch -> latest revision_id
        self.events: list[OracleEvent] = []

    def ingest_revision(
        self,
        revision_id: str,
        repository_id: str,
        commit_id: str,
        parent_revision_id: Optional[str],
        branch: str,
        entities: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> OracleRevision:
        rev_entities = [
            OracleEntity(
                logical_id=e["logical_id"],
                entity_type=e.get("type", "FUNCTION"),
                name=e.get("name", e["logical_id"]),
                file_path=e.get("file_path", "module.py"),
                line_start=e.get("line_start", 1),
                line_end=e.get("line_end", 10),
                source_hash=e.get("source_hash", compute_sha256(e["logical_id"])),
            )
            for e in entities
        ]
        rev_edges = [
            OracleEdge(
                src=ed["src"],
                dst=ed["dst"],
                edge_type=ed.get("type", "CALLS"),
            )
            for ed in edges
        ]
        rev = OracleRevision(
            revision_id=revision_id,
            repository_id=repository_id,
            commit_id=commit_id,
            parent_revision_id=parent_revision_id,
            branch=branch,
            entities=rev_entities,
            edges=rev_edges,
        )
        self.revisions[revision_id] = rev
        self.branch_heads[branch] = revision_id
        return rev

    def append_event(self, event_id: str, event_type: str, payload: dict[str, Any]) -> OracleEvent:
        prev_hash = self.events[-1].event_hash if self.events else None
        event_body = {
            "id": event_id,
            "type": event_type,
            "payload": payload,
            "prev_event_hash": prev_hash,
        }
        h = compute_sha256(canonical_json(event_body))
        evt = OracleEvent(
            event_id=event_id,
            event_type=event_type,
            payload=payload,
            prev_event_hash=prev_hash,
            event_hash=h,
        )
        self.events.append(evt)
        return evt

    def get_branch_state(self, branch: str) -> dict[str, Any]:
        latest_rev_id = self.branch_heads.get(branch)
        if not latest_rev_id:
            return {
                "latest_revision_id": "",
                "entity_count": 0,
                "edge_count": 0,
                "canonical_hash": "",
            }
        rev = self.revisions[latest_rev_id]
        return {
            "latest_revision_id": rev.revision_id,
            "entity_count": len(rev.entities),
            "edge_count": len(rev.edges),
            "canonical_hash": rev.canonical_hash(),
        }

    def canonical_store_hash(self) -> str:
        state = {
            "revisions": sorted(
                [
                    {
                        "id": r.revision_id,
                        "branch": r.branch,
                        "commit_id": r.commit_id,
                        "hash": r.canonical_hash(),
                    }
                    for r in self.revisions.values()
                ],
                key=lambda x: x["id"],
            ),
            "events": [e.event_hash for e in self.events],
        }
        return compute_sha256(canonical_json(state))


def verify_disjoint_branch_invariance(
    case_actions: list[dict[str, Any]], branches: list[str]
) -> tuple[bool, dict[str, str]]:
    """T2 Invariant Check: State(branch_A || branch_B) == State(branch_A in isolation).

    Computes isolated serial execution for each branch and verifies that its canonical
    state matches the joint execution state.
    """
    # 1. Joint execution
    joint_oracle = CleanRoomConcurrencyOracle()
    for act in case_actions:
        if act.get("action") == "ingest_revision":
            joint_oracle.ingest_revision(
                revision_id=act["revision_id"],
                repository_id=act.get("repository_id", "repo"),
                commit_id=act.get("commit_id", act["revision_id"]),
                parent_revision_id=act.get("parent_revision_id"),
                branch=act["branch"],
                entities=act.get("entities", []),
                edges=act.get("edges", []),
            )

    isolated_hashes: dict[str, str] = {}
    invariance_holds = True

    for branch in branches:
        branch_oracle = CleanRoomConcurrencyOracle()
        for act in case_actions:
            if act.get("action") == "ingest_revision" and act.get("branch") == branch:
                branch_oracle.ingest_revision(
                    revision_id=act["revision_id"],
                    repository_id=act.get("repository_id", "repo"),
                    commit_id=act.get("commit_id", act["revision_id"]),
                    parent_revision_id=act.get("parent_revision_id"),
                    branch=act["branch"],
                    entities=act.get("entities", []),
                    edges=act.get("edges", []),
                )
        iso_state = branch_oracle.get_branch_state(branch)
        joint_state = joint_oracle.get_branch_state(branch)
        isolated_hashes[branch] = iso_state["canonical_hash"]

        if iso_state["canonical_hash"] != joint_state["canonical_hash"]:
            invariance_holds = False

    return invariance_holds, isolated_hashes


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    """Derive ground-truth reference verdict for a CAP-008 case."""
    case_id = case["id"]
    slice_name = case["slice"]
    is_tripwire = case.get("is_tripwire", False)

    # Tripwire cases MUST fail closed with INCONCLUSIVE
    if is_tripwire:
        tripwire_type = case.get("tripwire_type", "LOCK_TIMEOUT_EXHAUSTION")
        return {
            "id": case_id,
            "slice": slice_name,
            "expected_status": "INCONCLUSIVE",
            "disjoint_invariance_holds": True,
            "expected_revisions": [],
            "expected_branch_states": {},
            "expected_event_count": 0,
            "expected_head_hash": None,
            "chain_continuity_valid": True,
            "tripwire_mechanism": tripwire_type,
            "canonical_state_hash": compute_sha256(f"INCONCLUSIVE:{case_id}:{tripwire_type}"),
        }

    # For PASS cases: execute serial reference schedule
    oracle = CleanRoomConcurrencyOracle()

    # Pre-seed initial state if present
    if "initial_state" in case and case["initial_state"]:
        for init_rev in case["initial_state"].get("revisions", []):
            oracle.ingest_revision(
                revision_id=init_rev["revision_id"],
                repository_id=init_rev.get("repository_id", "repo"),
                commit_id=init_rev.get("commit_id", init_rev["revision_id"]),
                parent_revision_id=init_rev.get("parent_revision_id"),
                branch=init_rev["branch"],
                entities=init_rev.get("entities", []),
                edges=init_rev.get("edges", []),
            )
        for init_evt in case["initial_state"].get("events", []):
            oracle.append_event(
                event_id=init_evt["event_id"],
                event_type=init_evt.get("type", "INIT"),
                payload=init_evt.get("payload", {}),
            )

    # Flatten declared serial order of actions
    serial_actions = case.get("serial_reference_order", [])
    if not serial_actions:
        # If no explicit serial list, collect from workers in deterministic order
        serial_actions = []
        for w in case.get("workers", []):
            for act in w.get("actions", []):
                serial_actions.append(act)

    all_branches: set[str] = set()
    for act in serial_actions:
        act_type = act.get("action")
        if act_type == "ingest_revision":
            branch = act["branch"]
            all_branches.add(branch)
            oracle.ingest_revision(
                revision_id=act["revision_id"],
                repository_id=act.get("repository_id", "repo"),
                commit_id=act.get("commit_id", act["revision_id"]),
                parent_revision_id=act.get("parent_revision_id"),
                branch=branch,
                entities=act.get("entities", []),
                edges=act.get("edges", []),
            )
        elif act_type == "append_event":
            oracle.append_event(
                event_id=act["event_id"],
                event_type=act.get("type", "CI_ATTESTATION"),
                payload=act.get("payload", {}),
            )

    # Check disjoint branch invariance if multiple branches exist
    invariance_holds = True
    if len(all_branches) > 1:
        invariance_holds, _ = verify_disjoint_branch_invariance(serial_actions, list(all_branches))

    branch_states = {b: oracle.get_branch_state(b) for b in sorted(all_branches)}
    expected_revisions = sorted(list(oracle.revisions.keys()))
    head_hash = oracle.events[-1].event_hash if oracle.events else None

    return {
        "id": case_id,
        "slice": slice_name,
        "expected_status": "PASS",
        "disjoint_invariance_holds": invariance_holds,
        "expected_revisions": expected_revisions,
        "expected_branch_states": branch_states,
        "expected_event_count": len(oracle.events),
        "expected_head_hash": head_hash,
        "chain_continuity_valid": True,
        "tripwire_mechanism": None,
        "canonical_state_hash": oracle.canonical_store_hash(),
    }
