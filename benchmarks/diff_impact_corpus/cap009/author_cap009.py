#!/usr/bin/env python3
"""CAP-009 Corpus Authoring Script: End-to-End Diff-to-Impact Benchmark.

Clean-room independent authoring tool.
CRITICAL CONSTRAINT (P0-1):
This script must NOT import or invoke production parsing or seeder modules.
Ground-truth seeds and impact sets are computed purely via clean-room
specifications and independent parsing.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

CORPUS_DIR = Path(__file__).resolve().parent


def clean_room_hunk_lines(diff_text: str) -> dict[str, set[int]]:
    """Clean-room independent parser of unified diff touched line numbers.
    Does not use production diff parsing."""
    file_lines: dict[str, set[int]] = {}
    current_file: str | None = None
    old_line = 0

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            if current_file not in file_lines:
                file_lines[current_file] = set()
        elif line.startswith("--- a/"):
            old_f = line[6:].strip()
            if old_f not in file_lines:
                file_lines[old_f] = set()
            if not current_file:
                current_file = old_f
        elif line.startswith("@@"):
            # @@ -old_start,old_count +new_start,new_count @@
            parts = line.split()
            if len(parts) >= 3 and parts[1].startswith("-"):
                old_spec = parts[1][1:].split(",")[0]
                try:
                    old_line = int(old_spec)
                except ValueError:
                    old_line = 1
                if current_file:
                    file_lines[current_file].add(old_line)
        elif current_file is not None:
            if line.startswith("-"):
                file_lines[current_file].add(old_line)
                old_line += 1
            elif line.startswith("+"):
                file_lines[current_file].add(old_line)
                if old_line > 1:
                    file_lines[current_file].add(old_line - 1)
            elif not line.startswith("\\"):
                old_line += 1

    return file_lines


def clean_room_compute_seeds(
    files: list[str],
    entities: list[dict[str, Any]],
    diff_text: str,
) -> list[str]:
    """Clean-room oracle for changed entity identification."""
    touched_by_file = clean_room_hunk_lines(diff_text)
    seeds: list[str] = []

    for ent in entities:
        # Non-seedable entity types
        etype = ent.get("type", "FUNCTION")
        if etype in ("MODULE", "PARAMETER", "IMPORT", "VARIABLE"):
            continue

        epath = ent.get("file_path", "")
        # Exact or suffix match
        matching_file = None
        for f in files:
            if epath == f or epath.endswith("/" + f) or f.endswith("/" + epath):
                matching_file = f
                break

        if not matching_file:
            continue

        touched = touched_by_file.get(matching_file, set())
        # If file touched has line entries, check span overlap
        l_start = ent.get("line_start", 1)
        l_end = ent.get("line_end", l_start)
        if any(l_start <= ln <= l_end for ln in touched):
            seeds.append(ent["revision_entity_id"])

    return sorted(seeds)


def clean_room_compute_impact(
    seeds: list[str],
    graph_edges: list[list[str]],
    max_hops: int = 2,
) -> list[str]:
    """Clean-room oracle for impact set traversal (callers reachable within max_hops)."""
    # graph_edges: [[caller, callee], ...]
    predecessors: dict[str, set[str]] = {}
    for caller, callee in graph_edges:
        predecessors.setdefault(callee, set()).add(caller)

    impacted: set[str] = set()
    frontier = set(seeds)
    for _ in range(max_hops):
        next_frontier = set()
        for node in frontier:
            for pred in predecessors.get(node, set()):
                if pred not in impacted and pred not in seeds:
                    impacted.add(pred)
                    next_frontier.add(pred)
        frontier = next_frontier
        if not frontier:
            break

    return sorted(impacted)


def build_cases() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    slices = [
        "pure_insertions",
        "deletions",
        "multi_hunk",
        "renames",
        "nested_scopes",
        "decorators",
        "same_basename_collisions",
        "mixed_language",
        "adversarial_critical",
    ]
    slice_counts: dict[str, int] = {s: 25 for s in slices}
    cases: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []

    case_num = 1

    for s in slices:
        for i in range(1, 26):
            cid = f"CAP009-{case_num:03d}"
            is_critical = (s == "adversarial_critical")

            if s == "pure_insertions":
                diff = (
                    f"diff --git a/pkg/worker_{i}.py b/pkg/worker_{i}.py\n"
                    f"--- a/pkg/worker_{i}.py\n"
                    f"+++ b/pkg/worker_{i}.py\n"
                    f"@@ -10,0 +11,3 @@\n"
                    f"+    # Pure insertion at function boundary\n"
                    f"+    validate_precondition({i})\n"
                    f"+    flush_metrics()\n"
                )
                files = [f"pkg/worker_{i}.py"]
                entities = [
                    {"revision_entity_id": f"worker_{i}:init", "file_path": f"pkg/worker_{i}.py", "line_start": 1, "line_end": 8, "type": "FUNCTION"},
                    {"revision_entity_id": f"worker_{i}:process", "file_path": f"pkg/worker_{i}.py", "line_start": 9, "line_end": 20, "type": "FUNCTION"},
                ]
                edges = [[f"worker_{i}:orchestrator", f"worker_{i}:process"]]

            elif s == "deletions":
                diff = (
                    f"diff --git a/src/handler_{i}.py b/src/handler_{i}.py\n"
                    f"--- a/src/handler_{i}.py\n"
                    f"+++ b/src/handler_{i}.py\n"
                    f"@@ -15,4 +15,0 @@\n"
                    f"-    deprecated_branch({i})\n"
                    f"-    fallback_call()\n"
                    f"-    emit_audit_log()\n"
                    f"-    return None\n"
                )
                files = [f"src/handler_{i}.py"]
                entities = [
                    {"revision_entity_id": f"handler_{i}:main", "file_path": f"src/handler_{i}.py", "line_start": 10, "line_end": 25, "type": "FUNCTION"},
                    {"revision_entity_id": f"handler_{i}:cleanup", "file_path": f"src/handler_{i}.py", "line_start": 30, "line_end": 45, "type": "FUNCTION"},
                ]
                edges = [[f"handler_{i}:entrypoint", f"handler_{i}:main"]]

            elif s == "multi_hunk":
                diff = (
                    f"diff --git a/lib/pipeline_{i}.py b/lib/pipeline_{i}.py\n"
                    f"--- a/lib/pipeline_{i}.py\n"
                    f"+++ b/lib/pipeline_{i}.py\n"
                    f"@@ -5,2 +5,2 @@\n"
                    f"-    batch_size = 10\n"
                    f"+    batch_size = 20\n"
                    f"@@ -40,2 +40,2 @@\n"
                    f"-    return False\n"
                    f"+    return True\n"
                )
                files = [f"lib/pipeline_{i}.py"]
                entities = [
                    {"revision_entity_id": f"pipeline_{i}:configure", "file_path": f"lib/pipeline_{i}.py", "line_start": 3, "line_end": 12, "type": "FUNCTION"},
                    {"revision_entity_id": f"pipeline_{i}:validate", "file_path": f"lib/pipeline_{i}.py", "line_start": 35, "line_end": 48, "type": "FUNCTION"},
                ]
                edges = [
                    [f"pipeline_{i}:scheduler", f"pipeline_{i}:configure"],
                    [f"pipeline_{i}:runner", f"pipeline_{i}:validate"],
                ]

            elif s == "renames":
                diff = (
                    f"diff --git a/old_dir/service_{i}.py b/new_dir/service_{i}.py\n"
                    f"similarity index 98%\n"
                    f"rename from old_dir/service_{i}.py\n"
                    f"rename to new_dir/service_{i}.py\n"
                    f"--- a/old_dir/service_{i}.py\n"
                    f"+++ b/new_dir/service_{i}.py\n"
                    f"@@ -8,1 +8,1 @@\n"
                    f"-    version = '1.0'\n"
                    f"+    version = '2.0'\n"
                )
                files = [f"new_dir/service_{i}.py", f"old_dir/service_{i}.py"]
                entities = [
                    {"revision_entity_id": f"service_{i}:run", "file_path": f"new_dir/service_{i}.py", "line_start": 5, "line_end": 15, "type": "FUNCTION"},
                ]
                edges = [[f"service_{i}:client", f"service_{i}:run"]]

            elif s == "nested_scopes":
                diff = (
                    f"diff --git a/core/nested_{i}.py b/core/nested_{i}.py\n"
                    f"--- a/core/nested_{i}.py\n"
                    f"+++ b/core/nested_{i}.py\n"
                    f"@@ -18,2 +18,3 @@\n"
                    f"         def inner_helper():\n"
                    f"+            check_inner_invariant()\n"
                    f"             return {i}\n"
                )
                files = [f"core/nested_{i}.py"]
                entities = [
                    {"revision_entity_id": f"nested_{i}:OuterClass", "file_path": f"core/nested_{i}.py", "line_start": 5, "line_end": 35, "type": "CLASS"},
                    {"revision_entity_id": f"nested_{i}:OuterClass.method", "file_path": f"core/nested_{i}.py", "line_start": 12, "line_end": 25, "type": "METHOD"},
                ]
                edges = [[f"nested_{i}:caller", f"nested_{i}:OuterClass.method"]]

            elif s == "decorators":
                diff = (
                    f"diff --git a/web/routes_{i}.py b/web/routes_{i}.py\n"
                    f"--- a/web/routes_{i}.py\n"
                    f"+++ b/web/routes_{i}.py\n"
                    f"@@ -12,0 +13,2 @@\n"
                    f"+@rate_limit(requests=100)\n"
                    f"+@require_permission('read')\n"
                    f" def endpoint_{i}():\n"
                )
                files = [f"web/routes_{i}.py"]
                entities = [
                    {"revision_entity_id": f"routes_{i}:endpoint_{i}", "file_path": f"web/routes_{i}.py", "line_start": 12, "line_end": 22, "type": "FUNCTION"},
                ]
                edges = [[f"routes_{i}:gateway", f"routes_{i}:endpoint_{i}"]]

            elif s == "same_basename_collisions":
                # Collision: auth/client.py vs api/client.py. Only auth/client.py is touched!
                diff = (
                    f"diff --git a/auth/client_{i}.py b/auth/client_{i}.py\n"
                    f"--- a/auth/client_{i}.py\n"
                    f"+++ b/auth/client_{i}.py\n"
                    f"@@ -14,1 +14,2 @@\n"
                    f"-    timeout = 30\n"
                    f"+    timeout = 10\n"
                    f"+    ssl_context = True\n"
                )
                files = [f"auth/client_{i}.py"]
                entities = [
                    # Target entity
                    {"revision_entity_id": f"auth_client_{i}:connect", "file_path": f"auth/client_{i}.py", "line_start": 10, "line_end": 20, "type": "FUNCTION"},
                    # Collision entity with same basename
                    {"revision_entity_id": f"api_client_{i}:connect", "file_path": f"api/client_{i}.py", "line_start": 10, "line_end": 20, "type": "FUNCTION"},
                ]
                edges = [
                    [f"auth_client_{i}:login", f"auth_client_{i}:connect"],
                    [f"api_client_{i}:fetch", f"api_client_{i}:connect"],
                ]

            elif s == "mixed_language":
                diff = (
                    f"diff --git a/native/engine_{i}.rs b/native/engine_{i}.rs\n"
                    f"--- a/native/engine_{i}.rs\n"
                    f"+++ b/native/engine_{i}.rs\n"
                    f"@@ -25,2 +25,3 @@\n"
                    f" pub fn compute_hash() {{\n"
                    f"+    let salt = {i};\n"
                    f" }}\n"
                )
                files = [f"native/engine_{i}.rs"]
                entities = [
                    {"revision_entity_id": f"engine_{i}:compute_hash", "file_path": f"native/engine_{i}.rs", "line_start": 20, "line_end": 30, "type": "FUNCTION"},
                ]
                edges = [[f"engine_{i}:driver", f"engine_{i}:compute_hash"]]

            else:  # adversarial_critical
                # Severe adversarial: Rename plus same-basename collision AND path collision tricks
                diff = (
                    f"diff --git a/auth/provider_{i}.py b/security/provider_{i}.py\n"
                    f"similarity index 95%\n"
                    f"rename from auth/provider_{i}.py\n"
                    f"rename to security/provider_{i}.py\n"
                    f"--- a/auth/provider_{i}.py\n"
                    f"+++ b/security/provider_{i}.py\n"
                    f"@@ -30,2 +30,2 @@\n"
                    f"-    verify_token(token, strict=False)\n"
                    f"+    verify_token(token, strict=True)\n"
                )
                files = [f"security/provider_{i}.py", f"auth/provider_{i}.py"]
                entities = [
                    # Real target
                    {"revision_entity_id": f"security_provider_{i}:auth_token", "file_path": f"security/provider_{i}.py", "line_start": 28, "line_end": 40, "type": "FUNCTION"},
                    # Unrelated collision entity sharing filename provider_{i}.py in other subsystem
                    {"revision_entity_id": f"metrics_provider_{i}:auth_token", "file_path": f"metrics/provider_{i}.py", "line_start": 28, "line_end": 40, "type": "FUNCTION"},
                ]
                edges = [
                    [f"security_provider_{i}:guard", f"security_provider_{i}:auth_token"],
                    [f"metrics_provider_{i}:collector", f"metrics_provider_{i}:auth_token"],
                ]

            expected_seeds = clean_room_compute_seeds(files, entities, diff)
            expected_impact = clean_room_compute_impact(expected_seeds, edges)

            case_obj = {
                "case_id": cid,
                "slice": s,
                "is_critical_adversarial": is_critical,
                "diff": diff,
                "files": files,
                "entities": entities,
                "graph_edges": edges,
            }
            label_obj = {
                "case_id": cid,
                "expected_seeds": expected_seeds,
                "expected_impact": expected_impact,
                "is_critical_adversarial": is_critical,
            }

            cases.append(case_obj)
            labels.append(label_obj)
            case_num += 1

    return cases, labels, slice_counts


def write_frozen_corpus() -> None:
    cases, labels, slice_counts = build_cases()
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)

    cases_file = CORPUS_DIR / "cases.jsonl"
    labels_file = CORPUS_DIR / "labels.jsonl"

    cases_text = "\n".join(json.dumps(c, sort_keys=True) for c in cases) + "\n"
    labels_text = "\n".join(json.dumps(lbl, sort_keys=True) for lbl in labels) + "\n"

    cases_file.write_text(cases_text, encoding="utf-8")
    labels_file.write_text(labels_text, encoding="utf-8")

    c_hash = hashlib.sha256(cases_file.read_bytes()).hexdigest()
    l_hash = hashlib.sha256(labels_file.read_bytes()).hexdigest()

    (CORPUS_DIR / "CORPUS_SHA256").write_text(c_hash + "\n", encoding="utf-8")
    (CORPUS_DIR / "LABEL_SHA256").write_text(l_hash + "\n", encoding="utf-8")

    config = {
        "experiment_id": "CAP-009",
        "title": "End-to-End Diff-to-Impact Correctness Benchmark",
        "case_count": len(cases),
        "slice_counts": slice_counts,
        "corpus_sha256": c_hash,
        "label_sha256": l_hash,
        "status": "CORPUS_FROZEN",
        "freeze_rule": "Gold labels independently authored without production diffmap dependencies.",
        "gates": {
            "critical_adversarial_false_passes": 0,
            "representative_seed_precision_min": 0.95,
            "representative_seed_recall_min": 0.95,
            "representative_impact_precision_min": 0.95,
            "representative_impact_recall_min": 0.95,
        },
    }
    (CORPUS_DIR / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

    mode_protocol = f"""# CAP-009 Protocol: Diff-to-Impact Verification (FROZEN)

**Experiment ID**: CAP-009  
**Corpus SHA-256**: `{c_hash}`  
**Label SHA-256**: `{l_hash}`  
**Total Cases**: {len(cases)}  

## Slice Distribution
{json.dumps(slice_counts, indent=2)}

## Core Invariants
1. **Zero False Passes on Critical Adversarial Cases**: Basename collisions and rename mismatches must never falsely seed collision entities.
2. **>=95% Seed Precision and Recall**: Representative slices accurately map diff hunks to AST entity IDs.
3. **>=95% Impact Precision and Recall**: Downstream call-graph blast radius matches ground-truth traversal reachability.
4. **Oracle Independence (P0-1)**: Ground truth authored independently without production diffmap.
"""
    (CORPUS_DIR / "MODE_PROTOCOL.md").write_text(mode_protocol, encoding="utf-8")
    print(f"Authored CAP-009: {len(cases)} cases, c_hash={c_hash}, l_hash={l_hash}")


if __name__ == "__main__":
    write_frozen_corpus()
