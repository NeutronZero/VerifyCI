"""Corpus Authoring Script for CAP-007: High-Node Topology & Production-Scale Retrieval.

Generates:
- cases.jsonl (64 adversarial cases, 8 slices x 8 cases)
- labels.jsonl (Oracle ground-truth labels and canonical digests)
- oracle_manifest.jsonl (Cryptographic manifest of all evaluated cases)
- CORPUS_SHA256, LABEL_SHA256, ORACLE_MANIFEST_SHA256 companion files
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import oracle  # noqa: E402


def generate_modular_case(idx: int) -> dict:
    case_id = f"SCALE-MOD-{idx:02d}"
    if idx == 8:
        # Tripwire case: missing package boundary manifest / broken boundary
        return {
            "id": case_id,
            "name": "Missing package boundary manifest in modular tree",
            "slice": "modular_package_hierarchy",
            "scenario_type": "tripwire",
            "tripwire_anomaly": "missing_package_manifest_tripwire",
            "tier": "S1",
            "graph": {"nodes": [{"id": "mod.orphan", "type": "FUNCTION", "name": "orphan"}], "edges": []},
            "queries": [{"seeds": ["mod.orphan"], "max_hops": 2}],
        }

    # Modular tree: core -> services -> controllers -> api
    nodes = []
    edges = []
    modules = ["core", "auth", "billing", "catalog", "analytics"]
    for m in modules:
        for i in range(1, 15):
            nid = f"{m}.service_{i}"
            nodes.append({"id": nid, "type": "FUNCTION", "name": f"service_{i}", "module": m})
            if i > 1:
                edges.append({"src": nid, "dst": f"{m}.service_{i-1}", "type": "CALLS"})

    # Inter-module dependencies
    for i in range(1, 10):
        edges.append({"src": f"billing.service_{i}", "dst": f"auth.service_{i}", "type": "CALLS"})
        edges.append({"src": f"catalog.service_{i}", "dst": f"core.service_{i}", "type": "CALLS"})
        edges.append({"src": f"analytics.service_{i}", "dst": f"billing.service_{i}", "type": "CALLS"})

    # Add DEPENDS_ON edges
    edges.append({"src": "billing.service_1", "dst": "external.stripe", "type": "DEPENDS_ON", "metadata": {"package": "stripe"}})
    edges.append({"src": "auth.service_1", "dst": "external.jwt", "type": "DEPENDS_ON", "metadata": {"package": "pyjwt"}})

    seed = f"billing.service_{idx}"
    return {
        "id": case_id,
        "name": f"Modular package hierarchy evaluation case {idx}",
        "slice": "modular_package_hierarchy",
        "scenario_type": "standard",
        "tier": "S1" if idx <= 4 else "S2",
        "graph": {"nodes": nodes, "edges": edges},
        "queries": [{"seeds": [seed], "max_hops": 2, "test_entities": [f"auth.service_{idx}"]}]
    }


def generate_monorepo_case(idx: int) -> dict:
    case_id = f"SCALE-MONO-{idx:02d}"
    if idx == 8:
        # Tripwire case: cross-boundary security policy violation
        return {
            "id": case_id,
            "name": "Cross-boundary security boundary violation",
            "slice": "monorepo_cross_boundary",
            "scenario_type": "tripwire",
            "tripwire_anomaly": "cross_boundary_security_tripwire",
            "tier": "S2",
            "graph": {"nodes": [{"id": "pkg_a.fn", "type": "FUNCTION", "name": "fn"}], "edges": []},
            "queries": [{"seeds": ["pkg_a.fn"], "max_hops": 2}],
        }

    nodes = []
    edges = []
    pkgs = ["shared_utils", "user_service", "order_service", "inventory_service", "payment_gateway"]
    for p in pkgs:
        for i in range(1, 16):
            nid = f"{p}.fn_{i}"
            nodes.append({"id": nid, "type": "FUNCTION", "name": f"fn_{i}", "module": p})
            if i > 1:
                edges.append({"src": nid, "dst": f"{p}.fn_{i-1}", "type": "CALLS"})
            # Calls shared utility
            edges.append({"src": nid, "dst": f"shared_utils.fn_{(i % 5) + 1}", "type": "CALLS"})

    edges.append({"src": "order_service.fn_1", "dst": "payment_gateway.fn_1", "type": "CALLS"})
    edges.append({"src": "payment_gateway.fn_1", "dst": "pkg.crypto", "type": "DEPENDS_ON", "metadata": {"package": "cryptography"}})

    seed = f"order_service.fn_{idx}"
    return {
        "id": case_id,
        "name": f"Monorepo cross-boundary dependency case {idx}",
        "slice": "monorepo_cross_boundary",
        "scenario_type": "standard",
        "tier": "S2" if idx <= 4 else "S3",
        "graph": {"nodes": nodes, "edges": edges},
        "queries": [{"seeds": [seed], "max_hops": 2, "test_entities": ["shared_utils.fn_1"]}]
    }


def generate_god_node_case(idx: int) -> dict:
    case_id = f"SCALE-GOD-{idx:02d}"
    if idx == 8:
        # Tripwire case: unbounded fan-out exhaustion
        return {
            "id": case_id,
            "name": "Unbounded fan-out resource exhaustion tripwire",
            "slice": "god_node_fanout",
            "scenario_type": "tripwire",
            "tripwire_anomaly": "unbounded_fanout_exhaustion_tripwire",
            "tier": "S4",
            "graph": {"nodes": [{"id": "hub.extreme", "type": "FUNCTION", "name": "extreme"}], "edges": []},
            "queries": [{"seeds": ["hub.extreme"], "max_hops": 2}],
        }

    nodes = [{"id": "common.logger", "type": "FUNCTION", "name": "log", "module": "common"}]
    edges = []
    # Fanout: dozens of callers calling logger.log
    fanout_count = 15 + idx * 5
    for i in range(1, fanout_count + 1):
        nid = f"client_{idx}.worker_{i}"
        nodes.append({"id": nid, "type": "FUNCTION", "name": f"worker_{i}", "module": f"client_{idx}"})
        edges.append({"src": nid, "dst": "common.logger", "type": "CALLS"})
        if i % 3 == 0:
            edges.append({"src": nid, "dst": f"client_{idx}.worker_{i-1}", "type": "CALLS"})

    return {
        "id": case_id,
        "name": f"God-node fan-in/fan-out evaluation case {idx} (fanout={fanout_count})",
        "slice": "god_node_fanout",
        "scenario_type": "standard",
        "tier": "S1" if idx <= 4 else "S2",
        "graph": {"nodes": nodes, "edges": edges},
        "queries": [{"seeds": ["common.logger"], "max_hops": 2}]
    }


def generate_deep_chain_case(idx: int) -> dict:
    case_id = f"SCALE-CHAIN-{idx:02d}"
    if idx == 8:
        # Tripwire case: unbounded depth limit
        return {
            "id": case_id,
            "name": "Unbounded recursive depth limit tripwire",
            "slice": "deep_call_chains",
            "scenario_type": "tripwire",
            "tripwire_anomaly": "unbounded_depth_limit_tripwire",
            "tier": "S4",
            "graph": {"nodes": [{"id": "chain.infinite", "type": "FUNCTION", "name": "infinite"}], "edges": []},
            "queries": [{"seeds": ["chain.infinite"], "max_hops": 999}],
        }

    chain_length = 10 + idx * 3
    nodes = []
    edges = []
    for i in range(chain_length):
        nid = f"chain_{idx}.step_{i}"
        nodes.append({"id": nid, "type": "FUNCTION", "name": f"step_{i}", "module": f"chain_{idx}"})
        if i > 0:
            edges.append({"src": f"chain_{idx}.step_{i-1}", "dst": nid, "type": "CALLS"})

    return {
        "id": case_id,
        "name": f"Transitive deep call chain case {idx} (length={chain_length})",
        "slice": "deep_call_chains",
        "scenario_type": "standard",
        "tier": "S1" if idx <= 4 else "S2",
        "graph": {"nodes": nodes, "edges": edges},
        "queries": [{"seeds": [f"chain_{idx}.step_0"], "max_hops": 3}]
    }


def generate_cycle_case(idx: int) -> dict:
    case_id = f"SCALE-CYCLE-{idx:02d}"
    if idx == 8:
        # Tripwire case: cyclic infinite traversal loop
        return {
            "id": case_id,
            "name": "Cyclic infinite traversal loop tripwire",
            "slice": "cyclic_dependencies",
            "scenario_type": "tripwire",
            "tripwire_anomaly": "cyclic_infinite_traversal_tripwire",
            "tier": "S4",
            "graph": {"nodes": [{"id": "cycle.trap", "type": "FUNCTION", "name": "trap"}], "edges": []},
            "queries": [{"seeds": ["cycle.trap"], "max_hops": 2}],
        }

    nodes = []
    edges = []
    cycle_size = 4 + idx
    for i in range(cycle_size):
        nid = f"cyclic_{idx}.node_{i}"
        nodes.append({"id": nid, "type": "FUNCTION", "name": f"node_{i}", "module": f"cyclic_{idx}"})
        nxt = f"cyclic_{idx}.node_{(i + 1) % cycle_size}"
        edges.append({"src": nid, "dst": nxt, "type": "CALLS"})
        # Add peripheral nodes attached to cycle
        p_id = f"cyclic_{idx}.periph_{i}"
        nodes.append({"id": p_id, "type": "FUNCTION", "name": f"periph_{i}", "module": f"cyclic_{idx}"})
        edges.append({"src": nid, "dst": p_id, "type": "CALLS"})

    return {
        "id": case_id,
        "name": f"Cyclic dependency graph case {idx} (cycle_size={cycle_size})",
        "slice": "cyclic_dependencies",
        "scenario_type": "standard",
        "tier": "S1" if idx <= 4 else "S2",
        "graph": {"nodes": nodes, "edges": edges},
        "queries": [{"seeds": [f"cyclic_{idx}.node_0"], "max_hops": 2}]
    }


def generate_dense_case(idx: int) -> dict:
    case_id = f"SCALE-GEN-{idx:02d}"
    if idx == 8:
        # Tripwire case: dense clique resource exhaustion
        return {
            "id": case_id,
            "name": "Dense clique resource exhaustion tripwire",
            "slice": "dense_clusters_generated",
            "scenario_type": "tripwire",
            "tripwire_anomaly": "dense_clique_resource_exhaustion_tripwire",
            "tier": "S4",
            "graph": {"nodes": [{"id": "dense.explode", "type": "FUNCTION", "name": "explode"}], "edges": []},
            "queries": [{"seeds": ["dense.explode"], "max_hops": 2}],
        }

    clique_size = 8 + idx * 2
    nodes = []
    edges = []
    for i in range(clique_size):
        nid = f"generated_proto_{idx}.field_{i}"
        nodes.append({"id": nid, "type": "FUNCTION", "name": f"field_{i}", "module": f"generated_proto_{idx}"})

    for i in range(clique_size):
        for j in range(clique_size):
            if i != j and (i + j) % 3 == 0:
                edges.append({"src": f"generated_proto_{idx}.field_{i}", "dst": f"generated_proto_{idx}.field_{j}", "type": "CALLS"})

    return {
        "id": case_id,
        "name": f"Dense generated cluster case {idx} (size={clique_size}, edges={len(edges)})",
        "slice": "dense_clusters_generated",
        "scenario_type": "standard",
        "tier": "S2" if idx <= 4 else "S3",
        "graph": {"nodes": nodes, "edges": edges},
        "queries": [{"seeds": [f"generated_proto_{idx}.field_0"], "max_hops": 2}]
    }


def generate_sparse_case(idx: int) -> dict:
    case_id = f"SCALE-SPARSE-{idx:02d}"
    if idx == 8:
        # Tripwire case: dangling unresolved entity pointer
        return {
            "id": case_id,
            "name": "Dangling unresolved entity pointer tripwire",
            "slice": "sparse_distant_targets",
            "scenario_type": "tripwire",
            "tripwire_anomaly": "dangling_unresolved_pointer_tripwire",
            "tier": "S1",
            "graph": {"nodes": [{"id": "sparse.valid", "type": "FUNCTION", "name": "valid"}], "edges": [{"src": "sparse.valid", "dst": "ghost.unresolved_999", "type": "CALLS"}]},
            "queries": [{"seeds": ["sparse.valid"], "max_hops": 2}],
        }

    length = 15 + idx * 4
    nodes = []
    edges = []
    for i in range(length):
        nid = f"sparse_tree_{idx}.elem_{i}"
        nodes.append({"id": nid, "type": "FUNCTION", "name": f"elem_{i}", "module": f"sparse_tree_{idx}"})
        if i > 0 and i % 2 == 1:
            edges.append({"src": f"sparse_tree_{idx}.elem_{i-1}", "dst": nid, "type": "CALLS"})
        elif i > 1:
            edges.append({"src": f"sparse_tree_{idx}.elem_{i-2}", "dst": nid, "type": "CALLS"})

    return {
        "id": case_id,
        "name": f"Sparse distant target case {idx} (diameter={length})",
        "slice": "sparse_distant_targets",
        "scenario_type": "standard",
        "tier": "S1" if idx <= 4 else "S2",
        "graph": {"nodes": nodes, "edges": edges},
        "queries": [{"seeds": [f"sparse_tree_{idx}.elem_0"], "max_hops": 2}]
    }


def generate_disagreement_case(idx: int) -> dict:
    case_id = f"SCALE-DISAGREE-{idx:02d}"
    if idx == 8:
        # Tripwire case: poisoned index pointer
        return {
            "id": case_id,
            "name": "Poisoned retrieval index pointer tripwire",
            "slice": "dense_sparse_disagreement",
            "scenario_type": "tripwire",
            "tripwire_anomaly": "poisoned_retrieval_pointer_tripwire",
            "tier": "S2",
            "graph": {"nodes": [{"id": "poison.seed", "type": "FUNCTION", "name": "seed"}], "edges": []},
            "queries": [{"seeds": ["poison.seed"], "max_hops": 2}],
        }

    # Lexical deception: target has name "billing_auth_processor" but is disconnected from billing
    # Structural target has completely different name "internal_calc_x" but is connected via CALLS
    nodes = [
        {"id": f"disagree_{idx}.seed_func", "type": "FUNCTION", "name": "payment_dispatch", "module": "billing"},
        {"id": f"disagree_{idx}.real_callee", "type": "FUNCTION", "name": "internal_calc_x", "module": "math"},
        {"id": f"disagree_{idx}.fake_decoy", "type": "FUNCTION", "name": "payment_dispatch_v2_fake", "module": "decoy"},
    ]
    edges = [
        {"src": f"disagree_{idx}.seed_func", "dst": f"disagree_{idx}.real_callee", "type": "CALLS"},
    ]
    for i in range(1, 10 + idx * 2):
        nodes.append({"id": f"disagree_{idx}.noise_{i}", "type": "FUNCTION", "name": f"noise_{i}", "module": "noise"})
        edges.append({"src": f"disagree_{idx}.real_callee", "dst": f"disagree_{idx}.noise_{i}", "type": "CALLS"})

    return {
        "id": case_id,
        "name": f"Dense-sparse disagreement case {idx}",
        "slice": "dense_sparse_disagreement",
        "scenario_type": "standard",
        "tier": "S1" if idx <= 4 else "S2",
        "graph": {"nodes": nodes, "edges": edges},
        "queries": [{"seeds": [f"disagree_{idx}.seed_func"], "max_hops": 2}]
    }


def author_all_cases() -> list[dict]:
    generators = [
        generate_modular_case,
        generate_monorepo_case,
        generate_god_node_case,
        generate_deep_chain_case,
        generate_cycle_case,
        generate_dense_case,
        generate_sparse_case,
        generate_disagreement_case,
    ]
    cases = []
    for gen in generators:
        for idx in range(1, 9):
            cases.append(gen(idx))
    assert len(cases) == 64
    return cases


def main():
    print("Authoring CAP-007 corpus across 64 cases...")
    cases = author_all_cases()

    cases_path = HERE / "cases.jsonl"
    labels_path = HERE / "labels.jsonl"
    manifest_path = HERE / "oracle_manifest.jsonl"

    cases_lines = [json.dumps(c, sort_keys=True) for c in cases]
    cases_content = "\n".join(cases_lines) + "\n"
    cases_path.write_bytes(cases_content.encode("utf-8"))

    print("Evaluating cases with independent exact traversal oracle...")
    labels = []
    manifests = []
    for c in cases:
        lbl, man = oracle.evaluate_oracle_case(c)
        labels.append(lbl)
        manifests.append(man)

    labels_lines = [json.dumps(lbl, sort_keys=True) for lbl in labels]
    labels_content = "\n".join(labels_lines) + "\n"
    labels_path.write_bytes(labels_content.encode("utf-8"))

    manifest_lines = [json.dumps(m, sort_keys=True) for m in manifests]
    manifest_content = "\n".join(manifest_lines) + "\n"
    manifest_path.write_bytes(manifest_content.encode("utf-8"))

    c_sha = hashlib.sha256(cases_content.encode("utf-8")).hexdigest()
    l_sha = hashlib.sha256(labels_content.encode("utf-8")).hexdigest()
    m_sha = hashlib.sha256(manifest_content.encode("utf-8")).hexdigest()

    (HERE / "CORPUS_SHA256").write_text(c_sha + "\n", encoding="utf-8")
    (HERE / "LABEL_SHA256").write_text(l_sha + "\n", encoding="utf-8")
    (HERE / "ORACLE_MANIFEST_SHA256").write_text(m_sha + "\n", encoding="utf-8")

    print("\nCAP-007 STEP 1 FREEZE COMPLETE:")
    print(f"Total Cases:     {len(cases)}")
    print(f"cases.jsonl:     {c_sha}")
    print(f"labels.jsonl:    {l_sha}")
    print(f"manifest.jsonl:  {m_sha}")


if __name__ == "__main__":
    main()
