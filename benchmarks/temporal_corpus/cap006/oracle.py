"""Independent Temporal & Lineage Reference Oracle for CAP-006.

LOCK-2 COMPLIANCE NOTICE:
This module is an independent reference oracle designed to establish ground truth
for CAP-006 without circular reliance on the system under test.
It MUST NOT import any module from verifyci (storage, memory, ingestion, contracts, interface).
It uses ONLY Python standard library modules: ast, hashlib, json, dataclasses, collections.
"""
from __future__ import annotations

import ast
import hashlib
import json
from collections import deque
from dataclasses import dataclass
from typing import Any, Optional


def compute_hash(text: str | bytes) -> str:
    """Compute SHA-256 digest of utf-8 text or bytes."""
    if isinstance(text, str):
        text = text.encode("utf-8")
    return hashlib.sha256(text).hexdigest()


@dataclass(frozen=True)
class OracleEntity:
    logical_id: str
    entity_type: str  # FUNCTION, CLASS, METHOD, MODULE
    name: str
    file_path: str
    line_start: int
    line_end: int
    args: list[str]
    content_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_id": self.logical_id,
            "entity_type": self.entity_type,
            "name": self.name,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "args": self.args,
            "content_hash": self.content_hash,
        }


@dataclass(frozen=True)
class OracleEdge:
    src_id: str
    dst_id: str
    edge_type: str  # CALLS, DEFINES, IMPORTS
    callee_name: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "src_id": self.src_id,
            "dst_id": self.dst_id,
            "edge_type": self.edge_type,
            "callee_name": self.callee_name,
        }


class StandaloneAstExtractor(ast.NodeVisitor):
    """Pure-Python AST visitor extracting canonical entities and call edges."""

    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.lines = source.splitlines()
        self.entities: dict[str, OracleEntity] = {}
        self.edges: list[OracleEdge] = []
        self._scope_stack: list[str] = []

        # Add module entity
        mod_id = f"module:{file_path}"
        self.entities[mod_id] = OracleEntity(
            logical_id=mod_id,
            entity_type="MODULE",
            name=file_path,
            file_path=file_path,
            line_start=1,
            line_end=len(self.lines) if self.lines else 1,
            args=[],
            content_hash=compute_hash(source),
        )
        self._current_entity_id = mod_id

    def _get_node_source(self, node: ast.AST) -> str:
        if hasattr(ast, "get_source_segment"):
            seg = ast.get_source_segment(self.source, node)
            if seg:
                return seg
        start = getattr(node, "lineno", 1) - 1
        end = getattr(node, "end_lineno", start + 1)
        return "\n".join(self.lines[start:end])

    def visit_ClassDef(self, node: ast.ClassDef):
        class_name = node.name
        class_id = f"class:{self.file_path}:{class_name}"
        prev_parent = self._current_entity_id
        self._scope_stack.append(class_name)

        src = self._get_node_source(node)
        self.entities[class_id] = OracleEntity(
            logical_id=class_id,
            entity_type="CLASS",
            name=class_name,
            file_path=self.file_path,
            line_start=node.lineno,
            line_end=getattr(node, "end_lineno", node.lineno),
            args=[getattr(b, "id", "") for b in node.bases if hasattr(b, "id")],
            content_hash=compute_hash(src),
        )
        self.edges.append(OracleEdge(
            src_id=prev_parent,
            dst_id=class_id,
            edge_type="DEFINES",
        ))

        self._current_entity_id = class_id
        self.generic_visit(node)
        self._scope_stack.pop()
        self._current_entity_id = prev_parent

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._handle_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._handle_func(node)

    def _handle_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        func_name = node.name
        if self._scope_stack:
            qname = ".".join(self._scope_stack) + "." + func_name
            etype = "METHOD"
        else:
            qname = func_name
            etype = "FUNCTION"

        func_id = f"func:{self.file_path}:{qname}"
        prev_parent = self._current_entity_id
        self._scope_stack.append(func_name)

        args = [arg.arg for arg in node.args.args]
        src = self._get_node_source(node)
        self.entities[func_id] = OracleEntity(
            logical_id=func_id,
            entity_type=etype,
            name=qname,
            file_path=self.file_path,
            line_start=node.lineno,
            line_end=getattr(node, "end_lineno", node.lineno),
            args=args,
            content_hash=compute_hash(src),
        )
        self.edges.append(OracleEdge(
            src_id=prev_parent,
            dst_id=func_id,
            edge_type="DEFINES",
        ))

        old_parent = self._current_entity_id
        self._current_entity_id = func_id
        self.generic_visit(node)
        self._current_entity_id = old_parent
        self._scope_stack.pop()

    def visit_Call(self, node: ast.Call):
        callee_name = None
        if isinstance(node.func, ast.Name):
            callee_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callee_name = node.func.attr

        if callee_name:
            self.edges.append(OracleEdge(
                src_id=self._current_entity_id,
                dst_id=f"unresolved:{callee_name}",
                edge_type="CALLS",
                callee_name=callee_name,
            ))
        self.generic_visit(node)


def extract_file_semantics(file_path: str, source: str) -> tuple[dict[str, OracleEntity], list[OracleEdge]]:
    """Parse python source using stdlib ast and extract canonical entities/edges."""
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        # Fall back to module-only
        mod_id = f"module:{file_path}"
        e = OracleEntity(
            logical_id=mod_id,
            entity_type="MODULE",
            name=file_path,
            file_path=file_path,
            line_start=1,
            line_end=1,
            args=[],
            content_hash=compute_hash(source),
        )
        return {mod_id: e}, []

    extractor = StandaloneAstExtractor(file_path, source)
    extractor.visit(tree)
    return extractor.entities, extractor.edges


def extract_snapshot_semantics(files: dict[str, str]) -> tuple[dict[str, OracleEntity], list[OracleEdge]]:
    """Extract canonical entities and call edges from a complete file snapshot dictionary."""
    all_entities: dict[str, OracleEntity] = {}
    all_edges: list[OracleEdge] = []

    for file_path, source in sorted(files.items()):
        entities, edges = extract_file_semantics(file_path, source)
        all_entities.update(entities)
        all_edges.extend(edges)

    return all_entities, all_edges


def compute_canonical_graph_digest(entities: dict[str, OracleEntity], edges: list[OracleEdge]) -> str:
    """Compute deterministic SHA-256 digest of canonical entities and edges."""
    canonical_entities = [
        {
            "id": eid,
            "type": e.entity_type,
            "name": e.name,
            "file": e.file_path,
            "lines": [e.line_start, e.line_end],
            "args": e.args,
            "hash": e.content_hash,
        }
        for eid, e in sorted(entities.items())
    ]
    canonical_edges = [
        {
            "src": edge.src_id,
            "dst": edge.dst_id,
            "type": edge.edge_type,
            "callee": edge.callee_name,
        }
        for edge in sorted(edges, key=lambda x: (x.src_id, x.dst_id, x.edge_type, x.callee_name or ""))
    ]
    payload = json.dumps({"entities": canonical_entities, "edges": canonical_edges}, sort_keys=True)
    return compute_hash(payload)


def validate_dag(commits: list[dict[str, Any]]) -> tuple[bool, Optional[str]]:
    """Independent verification of Git commit DAG integrity.

    Checks:
    - Root existence
    - Parent reference validity
    - Cycle detection
    - Ambiguous or corrupted parent pointers
    """
    commit_map = {c["commit_id"]: c for c in commits}
    if len(commit_map) != len(commits):
        return False, "duplicate_commit_id_detected"

    adj: dict[str, list[str]] = {c["commit_id"]: [] for c in commits}
    in_degree: dict[str, int] = {c["commit_id"]: 0 for c in commits}

    for c in commits:
        cid = c["commit_id"]
        # Can have parent_id (str) or parent_ids (list)
        pids = []
        if "parent_ids" in c and c["parent_ids"]:
            pids = list(c["parent_ids"])
        elif c.get("parent_id"):
            pids = [c["parent_id"]]

        for pid in pids:
            if pid not in commit_map:
                return False, f"missing_parent_lineage:{pid}"
            if pid == cid:
                return False, f"self_cycle_detected:{cid}"
            adj[pid].append(cid)
            in_degree[cid] += 1

    # Topological sort (Kahn's algorithm) for cycle detection
    queue = deque([cid for cid, deg in in_degree.items() if deg == 0])
    visited = 0
    while queue:
        curr = queue.popleft()
        visited += 1
        for neighbor in adj[curr]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    if visited != len(commits):
        return False, "cycle_detected_in_commit_graph"

    return True, None


def compute_reachable_ancestors(commit_id: str, commit_map: dict[str, dict[str, Any]]) -> set[str]:
    """Find all ancestor commit IDs reachable from a given commit."""
    if commit_id not in commit_map:
        return set()

    reachable = set()
    stack = [commit_id]
    while stack:
        cid = stack.pop()
        if cid in reachable:
            continue
        reachable.add(cid)
        c = commit_map.get(cid)
        if not c:
            continue
        pids = []
        if "parent_ids" in c and c["parent_ids"]:
            pids = list(c["parent_ids"])
        elif c.get("parent_id"):
            pids = [c["parent_id"]]
        for pid in pids:
            if pid in commit_map and pid not in reachable:
                stack.append(pid)
    return reachable


def evaluate_oracle_case(case: dict[str, Any]) -> dict[str, Any]:
    """Independent oracle evaluation of a temporal benchmark case.

    Derives:
    1. DAG integrity verdict (tripwires trigger fail-closed INCONCLUSIVE)
    2. Reachable history
    3. Final snapshot canonical entities, edges, and digest
    4. Expected verdict (PASS / INCONCLUSIVE / FAIL)
    5. Derivation details for oracle_manifest.jsonl
    """
    case_id = case["id"]
    slice_name = case["slice"]
    commits = case["commits"]
    target_query = case["target_query"]
    tripwire_anomaly = case.get("tripwire_anomaly")

    # Step 1: Tripwire anomaly check
    if tripwire_anomaly:
        return {
            "id": case_id,
            "slice": slice_name,
            "dag_valid": False,
            "expected_status": "INCONCLUSIVE",
            "ground_truth": "fail_closed",
            "ground_truth_rationale": f"Lineage tripwire detected ({tripwire_anomaly}): temporal verifier must fail-closed with INCONCLUSIVE",
            "falsifier_class": case.get("falsifier_class"),
            "target_commit": target_query.get("target_commit"),
            "canonical_digest": None,
            "canonical_entity_count": 0,
            "canonical_edge_count": 0,
            "derivation": {
                "tripwire": tripwire_anomaly,
                "reason": "Corrupted, truncated, or disconnected history DAG triggers fail-closed safety invariant.",
            },
        }

    # Step 2: Validate DAG structure
    dag_valid, dag_error = validate_dag(commits)
    if not dag_valid:
        return {
            "id": case_id,
            "slice": slice_name,
            "dag_valid": False,
            "expected_status": "INCONCLUSIVE",
            "ground_truth": "fail_closed",
            "ground_truth_rationale": f"DAG validation failure ({dag_error}): lineage broken, fail-closed contract applies",
            "falsifier_class": case.get("falsifier_class"),
            "target_commit": target_query.get("target_commit"),
            "canonical_digest": None,
            "canonical_entity_count": 0,
            "canonical_edge_count": 0,
            "derivation": {
                "dag_error": dag_error,
                "reason": "Broken ancestry or cyclic commit structure.",
            },
        }

    commit_map = {c["commit_id"]: c for c in commits}
    target_commit_id = target_query["target_commit"]
    target_commit = commit_map.get(target_commit_id)

    if not target_commit:
        return {
            "id": case_id,
            "slice": slice_name,
            "dag_valid": False,
            "expected_status": "INCONCLUSIVE",
            "ground_truth": "fail_closed",
            "ground_truth_rationale": f"Target commit {target_commit_id} not found in commit map",
            "falsifier_class": case.get("falsifier_class"),
            "target_commit": target_commit_id,
            "canonical_digest": None,
            "canonical_entity_count": 0,
            "canonical_edge_count": 0,
            "derivation": {"error": "target_commit_missing"},
        }

    # Step 3: Compute canonical entities and edges from target snapshot files
    target_files = target_commit["files"]
    entities, edges = extract_snapshot_semantics(target_files)
    canonical_digest = compute_canonical_graph_digest(entities, edges)

    # Step 4: Branch isolation check if requested
    isolation_branch = target_query.get("check_isolation_branch")
    isolation_verified = True
    isolation_note = "n/a"
    if isolation_branch:
        # Find commits belonging exclusively to the isolated branch
        target_branch = target_query.get("target_branch")
        isolated_commits = [c for c in commits if c.get("branch") == isolation_branch]
        ancestors = compute_reachable_ancestors(target_commit_id, commit_map)
        for ic in isolated_commits:
            if ic["commit_id"] in ancestors and ic.get("branch") != target_branch:
                # Contamination!
                isolation_verified = False
                isolation_note = f"Commit {ic['commit_id']} from branch {isolation_branch} leaked into {target_branch}"
                break
        if isolation_verified:
            isolation_note = f"Branch {target_branch} is strictly isolated from {isolation_branch}"

    # Step 5: Construct oracle verdict
    status = "PASS" if isolation_verified else "FAIL"
    rationale = case.get("expected_rationale") or f"Replay equivalence verified at commit {target_commit_id}; canonical graph digest matches clean snapshot"

    return {
        "id": case_id,
        "slice": slice_name,
        "dag_valid": True,
        "expected_status": status,
        "ground_truth": "correct" if status == "PASS" else "wrong",
        "ground_truth_rationale": rationale,
        "falsifier_class": case.get("falsifier_class"),
        "target_commit": target_commit_id,
        "canonical_digest": canonical_digest,
        "canonical_entity_count": len(entities),
        "canonical_edge_count": len(edges),
        "derivation": {
            "entity_names": sorted([e.name for e in entities.values()]),
            "file_count": len(target_files),
            "ancestor_count": len(compute_reachable_ancestors(target_commit_id, commit_map)),
            "isolation_note": isolation_note,
        },
    }
