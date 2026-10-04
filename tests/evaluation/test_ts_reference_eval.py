from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile

import pytest

from verifyci.contracts.edge import CPGEdgeSubtype, Edge, EdgeType
from verifyci.contracts.entity import Entity, EntityType
from verifyci.graph.builder import GraphBuilder
from verifyci.interface.commands.ingest import run_ingest
from verifyci.interface.commands.init import run_init
from verifyci.storage.graph_store import GraphStore
from verifyci.verification.diffmap import normalize_path

FIXTURE_PATH = Path("tests/fixtures/ts_reference_set_v1.json")
SRC_DIR = Path("tests/fixtures/ts_reference_src")


def check_reference_resolution(
    store: GraphStore, fixture: dict
) -> tuple[int, int, int, int]:
    """Execute the reference resolution check protocol against an ingested store.

    Note on Graph Source:
    This protocol evaluates edges from `GraphBuilder().build(entities, edges).edge_index_map()`
    rather than raw store edges. The store holds syntactic cross-file pointers, while
    `GraphBuilder._resolve_deferred` links candidate callers to target definitions during
    graph construction. Evaluating the builder graph reflects VerifyCI's actual verification
    pipeline runtime behavior where deferred cross-file calls are resolved.
    """
    ts_resolved, ts_total = 0, 0
    js_resolved, js_total = 0, 0

    rev_id = store.latest_revision_id()
    entities = store.get_entities_by_revision(rev_id)
    edges = store.get_edges_by_revision(rev_id)

    builder = GraphBuilder()
    graph = builder.build(entities, edges)
    all_edges = [payload for _, _, payload in graph.edge_index_map().values()]

    entities_by_file: dict[str, list[Entity]] = {}
    for e in entities:
        entities_by_file.setdefault(normalize_path(e.file_path), []).append(e)

    outgoing_calls: dict[str, list[Edge]] = {}
    for edge in all_edges:
        if edge.type == EdgeType.CALLS and edge.subtype in (
            CPGEdgeSubtype.CALLS_DIRECT,
            CPGEdgeSubtype.CALLS_RECURSIVE,
        ):
            outgoing_calls.setdefault(edge.src_entity_id, []).append(edge)

    entity_by_rev_id = {e.revision_entity_id: e for e in entities}

    for item in fixture["call_sites"]:
        caller_file = normalize_path(item["caller_file"])
        caller_line = item["caller_line"]
        expected_sym = item["expected_callee_symbol"]
        expected_file = normalize_path(item["expected_callee_file"])
        is_ts = item["language"] == "typescript"
        if is_ts:
            ts_total += 1
        else:
            js_total += 1

        # 1. Locate innermost non-module entity spanning caller_line
        file_entities = entities_by_file.get(caller_file, [])
        spanning = [
            e
            for e in file_entities
            if e.type != EntityType.MODULE and e.line_start <= caller_line <= e.line_end
        ]
        if not spanning:
            continue
        caller = min(spanning, key=lambda e: (e.line_end - e.line_start))

        # 2. Match outgoing resolved CALLS edges against exact (symbol, file)
        candidate_edges = outgoing_calls.get(caller.revision_entity_id, [])
        resolved = False
        for edge in candidate_edges:
            dst = entity_by_rev_id.get(edge.dst_entity_id)
            if dst and dst.name == expected_sym:
                if normalize_path(dst.file_path) == expected_file:
                    resolved = True
                    break

        if resolved:
            if is_ts:
                ts_resolved += 1
            else:
                js_resolved += 1

    return ts_resolved, ts_total, js_resolved, js_total


def test_two_tier_polyglot_quality_gate(tmp_path: Path):
    """Verify Two-Tier Quality Gate on pre-authored TS/JS reference set.

    Halt floor: >= 10% swr resolution.
    Acceptance bar: >= 70% TS (14/20) and >= 80% JS (4/5).

    Scope of Quality Gate:
    The 20/20 TS and 5/5 JS resolution proves the extractor handles clean, modern
    TypeScript/JavaScript packages with explicit relative ES6 imports (e.g. `import { x } from './y'`)
    and unique symbol targets within the same package. It does NOT claim arbitrary TypeScript
    at monorepo scale involving complex `tsconfig.json` path mappings, ambient declaration
    files (`.d.ts`), namespace merging, or third-party node_modules resolution.
    """
    assert FIXTURE_PATH.is_file(), f"Missing fixture: {FIXTURE_PATH}"
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    # Copy vendored files to tmp_path for test isolation
    for p in SRC_DIR.rglob("*"):
        if p.is_file():
            rel = p.relative_to(SRC_DIR)
            target = tmp_path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)

    db_path = run_init(str(tmp_path))
    run_ingest(str(tmp_path))

    store = GraphStore(db_path)
    try:
        ts_res, ts_tot, js_res, js_tot = check_reference_resolution(store, fixture)
    finally:
        store.close()

    assert ts_tot == 20, f"Expected 20 TS sites, got {ts_tot}"
    assert js_tot == 5, f"Expected 5 JS sites, got {js_tot}"

    ts_ratio = ts_res / ts_tot
    js_ratio = js_res / js_tot

    # Tier 1: Halt floor on SWR (>= 10%)
    assert (
        ts_ratio >= 0.10
    ), f"SWR resolution {ts_res}/{ts_tot} ({ts_ratio:.1%}) below 10% halt floor"

    # Tier 2: Acceptance bar (>= 70% TS, >= 80% JS)
    assert (
        ts_ratio >= 0.70
    ), f"TypeScript resolution {ts_res}/{ts_tot} ({ts_ratio:.1%}) below 70% acceptance bar"
    assert (
        js_ratio >= 0.80
    ), f"JavaScript resolution {js_res}/{js_tot} ({js_ratio:.1%}) below 80% acceptance bar"
