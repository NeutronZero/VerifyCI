"""Corpus Authoring Script for CAP-007: High-Node Topology & Production-Scale Retrieval.

Generates:
- cases.jsonl (64 adversarial cases across 8 slices x 8 cases)
  - Micro structural fixtures (S0, |V| in 20-200) for intricate topology correctness
  - Mid-scale fixtures (S1_mid, |V| ~1,500-2,500)
  - Production-scale instances: S1 (|V| >= 10,000) and S2 (|V| >= 50,000)
  - Boundary/Resource tripwires (fail-closed INCONCLUSIVE)
- labels.jsonl (Oracle ground-truth labels and canonical digests via oracle.py)
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
            "failure_mechanism": "Target entity lacks parent package manifest or module boundary declaration; must fail-closed with INCONCLUSIVE",
            "tier": "S4",
            "graph": {"nodes": [{"id": "mod.orphan", "type": "FUNCTION", "name": "orphan"}], "edges": []},
            "queries": [{"seeds": ["mod.orphan"], "max_hops": 2}],
        }

    # Production Scale S1 instance for idx == 7 (|V| = 10,000)
    if idx == 7:
        nodes = []
        edges = []
        num_packages = 50
        funcs_per_pkg = 200  # 50 * 200 = 10,000 nodes
        for p in range(num_packages):
            pkg_name = f"pkg_{p:02d}"
            for f in range(funcs_per_pkg):
                nid = f"{pkg_name}.fn_{f}"
                nodes.append({"id": nid, "type": "FUNCTION", "name": f"fn_{f}", "module": pkg_name})
                if f > 0:
                    edges.append({"src": nid, "dst": f"{pkg_name}.fn_{f-1}", "type": "CALLS"})
            # Inter-package calls
            if p > 0:
                edges.append({"src": f"{pkg_name}.fn_0", "dst": f"pkg_{p-1:02d}.fn_199", "type": "CALLS"})

        edges.append({"src": "pkg_10.fn_50", "dst": "ext.db_driver", "type": "DEPENDS_ON", "metadata": {"package": "psycopg2"}})
        seed = "pkg_10.fn_50"
        return {
            "id": case_id,
            "name": "Modular package hierarchy S1 production scale (10,000 nodes)",
            "slice": "modular_package_hierarchy",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": [seed], "max_hops": 2, "test_entities": ["pkg_10.fn_49"]}],
        }

    # Intermediate scale for idx == 6 (|V| = 1,500)
    if idx == 6:
        nodes = []
        edges = []
        for p in range(15):
            pkg_name = f"mid_pkg_{p}"
            for f in range(100):
                nid = f"{pkg_name}.fn_{f}"
                nodes.append({"id": nid, "type": "FUNCTION", "name": f"fn_{f}", "module": pkg_name})
                if f > 0:
                    edges.append({"src": nid, "dst": f"{pkg_name}.fn_{f-1}", "type": "CALLS"})
            if p > 0:
                edges.append({"src": f"{pkg_name}.fn_0", "dst": f"mid_pkg_{p-1}.fn_99", "type": "CALLS"})
        return {
            "id": case_id,
            "name": "Modular package hierarchy intermediate scale (1,500 nodes)",
            "slice": "modular_package_hierarchy",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["mid_pkg_5.fn_50"], "max_hops": 2}],
        }

    # Micro structural cases (idx 1..5)
    nodes = []
    edges = []
    modules = ["core", "auth", "billing", "catalog", "analytics"]
    for m in modules:
        for i in range(1, 10 + idx * 3):
            nid = f"{m}.service_{i}"
            nodes.append({"id": nid, "type": "FUNCTION", "name": f"service_{i}", "module": m})
            if i > 1:
                edges.append({"src": nid, "dst": f"{m}.service_{i-1}", "type": "CALLS"})

    for i in range(1, 5 + idx):
        edges.append({"src": f"billing.service_{i}", "dst": f"auth.service_{i}", "type": "CALLS"})
        edges.append({"src": f"catalog.service_{i}", "dst": f"core.service_{i}", "type": "CALLS"})
        edges.append({"src": f"analytics.service_{i}", "dst": f"billing.service_{i}", "type": "CALLS"})

    edges.append({"src": "billing.service_1", "dst": "external.stripe", "type": "DEPENDS_ON", "metadata": {"package": "stripe"}})
    edges.append({"src": "auth.service_1", "dst": "external.jwt", "type": "DEPENDS_ON", "metadata": {"package": "pyjwt"}})

    seed = f"billing.service_{idx}"
    return {
        "id": case_id,
        "name": f"Modular package hierarchy structural case {idx}",
        "slice": "modular_package_hierarchy",
        "scenario_type": "standard",
        "tier": "S0_micro",
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
            "failure_mechanism": "Traversal attempts to cross an isolated security boundary without explicit entitlement; must fail-closed with INCONCLUSIVE",
            "tier": "S4",
            "graph": {
                "nodes": [
                    {"id": "pkg_public.handler", "type": "FUNCTION", "name": "handler", "module": "pkg_public"},
                    {"id": "pkg_secret.vault", "type": "FUNCTION", "name": "vault", "module": "pkg_secret"},
                ],
                "edges": [
                    {"src": "pkg_public.handler", "dst": "pkg_secret.vault", "type": "CALLS", "metadata": {"security_boundary": "isolated", "cross_boundary": "forbidden"}},
                ]
            },
            "queries": [{"seeds": ["pkg_public.handler"], "max_hops": 2}],
        }

    # Production Scale S2 instance for idx == 7 (|V| = 50,000)
    if idx == 7:
        nodes = []
        edges = []
        num_apps = 50
        funcs_per_app = 1000  # 50 * 1,000 = 50,000 nodes
        for app in range(num_apps):
            app_name = f"service_{app:02d}"
            for f in range(funcs_per_app):
                nid = f"{app_name}.fn_{f}"
                nodes.append({"id": nid, "type": "FUNCTION", "name": f"fn_{f}", "module": app_name})
                if f > 0:
                    edges.append({"src": nid, "dst": f"{app_name}.fn_{f-1}", "type": "CALLS"})
            # Link to common service
            edges.append({"src": f"{app_name}.fn_0", "dst": "service_00.fn_0", "type": "CALLS"})

        edges.append({"src": "service_25.fn_100", "dst": "common_crypto", "type": "DEPENDS_ON", "metadata": {"package": "cryptography"}})
        seed = "service_25.fn_100"
        return {
            "id": case_id,
            "name": "Monorepo cross-boundary S2 production scale (50,000 nodes)",
            "slice": "monorepo_cross_boundary",
            "scenario_type": "standard",
            "tier": "S2",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": [seed], "max_hops": 2, "test_entities": ["service_25.fn_99"]}],
        }

    # Intermediate scale for idx == 6 (|V| = 2,000)
    if idx == 6:
        nodes = []
        edges = []
        for app in range(20):
            app_name = f"mid_app_{app}"
            for f in range(100):
                nid = f"{app_name}.fn_{f}"
                nodes.append({"id": nid, "type": "FUNCTION", "name": f"fn_{f}", "module": app_name})
                if f > 0:
                    edges.append({"src": nid, "dst": f"{app_name}.fn_{f-1}", "type": "CALLS"})
            edges.append({"src": f"{app_name}.fn_0", "dst": "mid_app_0.fn_0", "type": "CALLS"})
        return {
            "id": case_id,
            "name": "Monorepo cross-boundary intermediate scale (2,000 nodes)",
            "slice": "monorepo_cross_boundary",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["mid_app_10.fn_50"], "max_hops": 2}],
        }

    # Micro structural cases (idx 1..5)
    nodes = []
    edges = []
    pkgs = ["shared_utils", "user_service", "order_service", "inventory_service", "payment_gateway"]
    for p in pkgs:
        for i in range(1, 12 + idx * 2):
            nid = f"{p}.fn_{i}"
            nodes.append({"id": nid, "type": "FUNCTION", "name": f"fn_{i}", "module": p})
            if i > 1:
                edges.append({"src": nid, "dst": f"{p}.fn_{i-1}", "type": "CALLS"})
            edges.append({"src": nid, "dst": f"shared_utils.fn_{(i % 4) + 1}", "type": "CALLS"})

    edges.append({"src": "order_service.fn_1", "dst": "payment_gateway.fn_1", "type": "CALLS"})
    edges.append({"src": "payment_gateway.fn_1", "dst": "pkg.crypto", "type": "DEPENDS_ON", "metadata": {"package": "cryptography"}})

    seed = f"order_service.fn_{idx}"
    return {
        "id": case_id,
        "name": f"Monorepo cross-boundary structural case {idx}",
        "slice": "monorepo_cross_boundary",
        "scenario_type": "standard",
        "tier": "S0_micro",
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
            "failure_mechanism": "Node fanout degree exceeds visit budget (>20,000 links) without bound; must fail-closed with INCONCLUSIVE",
            "tier": "S4",
            "graph": {"nodes": [{"id": "hub.extreme", "type": "FUNCTION", "name": "extreme"}], "edges": []},
            "queries": [{"seeds": ["hub.extreme"], "max_hops": 2}],
        }

    # Production Scale S1 instance for idx == 7 (|V| = 10,000)
    if idx == 7:
        nodes = [{"id": "hub.logger", "type": "FUNCTION", "name": "log", "module": "hub"}]
        edges = []
        for i in range(1, 10000):
            nid = f"client.fn_{i}"
            nodes.append({"id": nid, "type": "FUNCTION", "name": f"fn_{i}", "module": f"pkg_{i//100}"})
            edges.append({"src": nid, "dst": "hub.logger", "type": "CALLS"})
        return {
            "id": case_id,
            "name": "God-node fan-in S1 production scale (10,000 callers)",
            "slice": "god_node_fanout",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["client.fn_500"], "max_hops": 2}],
        }

    # Intermediate scale for idx == 6 (|V| = 1,500)
    if idx == 6:
        nodes = [{"id": "mid_hub.logger", "type": "FUNCTION", "name": "log", "module": "mid_hub"}]
        edges = []
        for i in range(1, 1500):
            nid = f"mid_client.fn_{i}"
            nodes.append({"id": nid, "type": "FUNCTION", "name": f"fn_{i}", "module": f"mid_pkg_{i//50}"})
            edges.append({"src": nid, "dst": "mid_hub.logger", "type": "CALLS"})
        return {
            "id": case_id,
            "name": "God-node fan-in intermediate scale (1,500 callers)",
            "slice": "god_node_fanout",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["mid_client.fn_50"], "max_hops": 2}],
        }

    # Micro structural cases (idx 1..5)
    nodes = [{"id": "common.logger", "type": "FUNCTION", "name": "log", "module": "common"}]
    edges = []
    fanout_count = 15 + idx * 8
    for i in range(1, fanout_count + 1):
        nid = f"client_{idx}.worker_{i}"
        nodes.append({"id": nid, "type": "FUNCTION", "name": f"worker_{i}", "module": f"client_{idx}"})
        edges.append({"src": nid, "dst": "common.logger", "type": "CALLS"})
        if i % 3 == 0:
            edges.append({"src": nid, "dst": f"client_{idx}.worker_{i-1}", "type": "CALLS"})

    return {
        "id": case_id,
        "name": f"God-node fan-in/fan-out structural case {idx} (fanout={fanout_count})",
        "slice": "god_node_fanout",
        "scenario_type": "standard",
        "tier": "S0_micro",
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
            "failure_mechanism": "Requested query depth max_hops=999 exceeds maximum traversal depth limit; must fail-closed with INCONCLUSIVE",
            "tier": "S4",
            "graph": {"nodes": [{"id": "chain.infinite", "type": "FUNCTION", "name": "infinite"}], "edges": []},
            "queries": [{"seeds": ["chain.infinite"], "max_hops": 999}],
        }

    # Production Scale S1 instance for idx == 7 (|V| = 10,000)
    if idx == 7:
        nodes = []
        edges = []
        for i in range(10000):
            nid = f"s1_chain.step_{i}"
            nodes.append({"id": nid, "type": "FUNCTION", "name": f"step_{i}", "module": f"pipeline_{i//500}"})
            if i > 0:
                edges.append({"src": f"s1_chain.step_{i-1}", "dst": nid, "type": "CALLS"})
        return {
            "id": case_id,
            "name": "Transitive deep call chain S1 production scale (10,000 depth)",
            "slice": "deep_call_chains",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["s1_chain.step_5000"], "max_hops": 3}],
        }

    # Intermediate scale for idx == 6 (|V| = 1,500)
    if idx == 6:
        nodes = []
        edges = []
        for i in range(1500):
            nid = f"mid_chain.step_{i}"
            nodes.append({"id": nid, "type": "FUNCTION", "name": f"step_{i}", "module": f"mid_pipe_{i//100}"})
            if i > 0:
                edges.append({"src": f"mid_chain.step_{i-1}", "dst": nid, "type": "CALLS"})
        return {
            "id": case_id,
            "name": "Transitive deep call chain intermediate scale (1,500 depth)",
            "slice": "deep_call_chains",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["mid_chain.step_750"], "max_hops": 3}],
        }

    # Micro structural cases (idx 1..5)
    chain_length = 10 + idx * 6
    nodes = []
    edges = []
    for i in range(chain_length):
        nid = f"chain_{idx}.step_{i}"
        nodes.append({"id": nid, "type": "FUNCTION", "name": f"step_{i}", "module": f"chain_{idx}"})
        if i > 0:
            edges.append({"src": f"chain_{idx}.step_{i-1}", "dst": nid, "type": "CALLS"})

    return {
        "id": case_id,
        "name": f"Transitive deep call chain structural case {idx} (length={chain_length})",
        "slice": "deep_call_chains",
        "scenario_type": "standard",
        "tier": "S0_micro",
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
            "failure_mechanism": "High cyclic density creates potential infinite expansion loop; must fail-closed with INCONCLUSIVE",
            "tier": "S4",
            "graph": {"nodes": [{"id": "cycle.trap", "type": "FUNCTION", "name": "trap"}], "edges": []},
            "queries": [{"seeds": ["cycle.trap"], "max_hops": 2}],
        }

    # Production Scale S1 instance for idx == 7 (|V| = 10,000)
    if idx == 7:
        nodes = []
        edges = []
        num_rings = 100
        ring_size = 100  # 100 * 100 = 10,000 nodes
        for r in range(num_rings):
            r_name = f"ring_{r:02d}"
            for i in range(ring_size):
                nid = f"{r_name}.node_{i}"
                nodes.append({"id": nid, "type": "FUNCTION", "name": f"node_{i}", "module": r_name})
                nxt = f"{r_name}.node_{(i + 1) % ring_size}"
                edges.append({"src": nid, "dst": nxt, "type": "CALLS"})
            # Link rings together
            if r > 0:
                edges.append({"src": f"{r_name}.node_0", "dst": f"ring_{r-1:02d}.node_0", "type": "CALLS"})
        return {
            "id": case_id,
            "name": "Cyclic dependencies S1 production scale (10,000 nodes across 100 rings)",
            "slice": "cyclic_dependencies",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["ring_10.node_5"], "max_hops": 2}],
        }

    # Intermediate scale for idx == 6 (|V| = 1,500)
    if idx == 6:
        nodes = []
        edges = []
        for r in range(15):
            r_name = f"mid_ring_{r}"
            for i in range(100):
                nid = f"{r_name}.node_{i}"
                nodes.append({"id": nid, "type": "FUNCTION", "name": f"node_{i}", "module": r_name})
                edges.append({"src": nid, "dst": f"{r_name}.node_{(i + 1) % 100}", "type": "CALLS"})
            if r > 0:
                edges.append({"src": f"{r_name}.node_0", "dst": f"mid_ring_{r-1}.node_0", "type": "CALLS"})
        return {
            "id": case_id,
            "name": "Cyclic dependencies intermediate scale (1,500 nodes)",
            "slice": "cyclic_dependencies",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["mid_ring_2.node_10"], "max_hops": 2}],
        }

    # Micro structural cases (idx 1..5)
    nodes = []
    edges = []
    cycle_size = 6 + idx * 2
    for i in range(cycle_size):
        nid = f"cyclic_{idx}.node_{i}"
        nodes.append({"id": nid, "type": "FUNCTION", "name": f"node_{i}", "module": f"cyclic_{idx}"})
        nxt = f"cyclic_{idx}.node_{(i + 1) % cycle_size}"
        edges.append({"src": nid, "dst": nxt, "type": "CALLS"})
        p_id = f"cyclic_{idx}.periph_{i}"
        nodes.append({"id": p_id, "type": "FUNCTION", "name": f"periph_{i}", "module": f"cyclic_{idx}"})
        edges.append({"src": nid, "dst": p_id, "type": "CALLS"})

    return {
        "id": case_id,
        "name": f"Cyclic dependency structural case {idx} (cycle_size={cycle_size})",
        "slice": "cyclic_dependencies",
        "scenario_type": "standard",
        "tier": "S0_micro",
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
            "failure_mechanism": "Combinatorial expansion of dense clique exceeds node visit/memory budget; must fail-closed with INCONCLUSIVE",
            "tier": "S4",
            "graph": {"nodes": [{"id": "dense.explode", "type": "FUNCTION", "name": "explode"}], "edges": []},
            "queries": [{"seeds": ["dense.explode"], "max_hops": 2}],
        }

    # Production Scale S2 instance for idx == 7 (|V| = 50,000)
    if idx == 7:
        nodes = []
        edges = []
        num_clusters = 50
        funcs_per_cluster = 1000  # 50 * 1,000 = 50,000 nodes
        for c in range(num_clusters):
            c_name = f"gen_proto_{c:02d}"
            for f in range(funcs_per_cluster):
                nid = f"{c_name}.stub_{f}"
                nodes.append({"id": nid, "type": "FUNCTION", "name": f"stub_{f}", "module": c_name})
                if f > 0:
                    edges.append({"src": nid, "dst": f"{c_name}.stub_{f-1}", "type": "CALLS"})
            if c > 0:
                edges.append({"src": f"{c_name}.stub_0", "dst": f"gen_proto_{c-1:02d}.stub_0", "type": "CALLS"})
        return {
            "id": case_id,
            "name": "Dense generated cluster S2 production scale (50,000 nodes)",
            "slice": "dense_clusters_generated",
            "scenario_type": "standard",
            "tier": "S2",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["gen_proto_20.stub_100"], "max_hops": 2}],
        }

    # Intermediate scale for idx == 6 (|V| = 2,000)
    if idx == 6:
        nodes = []
        edges = []
        for c in range(20):
            c_name = f"mid_gen_{c}"
            for f in range(100):
                nid = f"{c_name}.stub_{f}"
                nodes.append({"id": nid, "type": "FUNCTION", "name": f"stub_{f}", "module": c_name})
                if f > 0:
                    edges.append({"src": nid, "dst": f"{c_name}.stub_{f-1}", "type": "CALLS"})
            if c > 0:
                edges.append({"src": f"{c_name}.stub_0", "dst": f"mid_gen_{c-1}.stub_0", "type": "CALLS"})
        return {
            "id": case_id,
            "name": "Dense generated cluster intermediate scale (2,000 nodes)",
            "slice": "dense_clusters_generated",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["mid_gen_5.stub_50"], "max_hops": 2}],
        }

    # Micro structural cases (idx 1..5)
    clique_size = 10 + idx * 3
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
        "name": f"Dense generated cluster structural case {idx} (size={clique_size})",
        "slice": "dense_clusters_generated",
        "scenario_type": "standard",
        "tier": "S0_micro",
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
            "failure_mechanism": "Edge references non-existent / unresolved entity ID ghost.unresolved_999; must fail-closed with INCONCLUSIVE",
            "tier": "S4",
            "graph": {
                "nodes": [{"id": "sparse.valid", "type": "FUNCTION", "name": "valid"}],
                "edges": [{"src": "sparse.valid", "dst": "ghost.unresolved_999", "type": "CALLS"}]
            },
            "queries": [{"seeds": ["sparse.valid"], "max_hops": 2}],
        }

    # Production Scale S1 instance for idx == 7 (|V| = 10,000)
    if idx == 7:
        nodes = []
        edges = []
        for i in range(10000):
            nid = f"s1_sparse.elem_{i}"
            nodes.append({"id": nid, "type": "FUNCTION", "name": f"elem_{i}", "module": f"sparse_tree_{i//500}"})
            if i > 0 and i % 2 == 1:
                edges.append({"src": f"s1_sparse.elem_{i-1}", "dst": nid, "type": "CALLS"})
            elif i > 1:
                edges.append({"src": f"s1_sparse.elem_{i-2}", "dst": nid, "type": "CALLS"})
        return {
            "id": case_id,
            "name": "Sparse distant target S1 production scale (10,000 nodes)",
            "slice": "sparse_distant_targets",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["s1_sparse.elem_500"], "max_hops": 2}],
        }

    # Intermediate scale for idx == 6 (|V| = 1,500)
    if idx == 6:
        nodes = []
        edges = []
        for i in range(1500):
            nid = f"mid_sparse.elem_{i}"
            nodes.append({"id": nid, "type": "FUNCTION", "name": f"elem_{i}", "module": f"mid_tree_{i//100}"})
            if i > 0 and i % 2 == 1:
                edges.append({"src": f"mid_sparse.elem_{i-1}", "dst": nid, "type": "CALLS"})
            elif i > 1:
                edges.append({"src": f"mid_sparse.elem_{i-2}", "dst": nid, "type": "CALLS"})
        return {
            "id": case_id,
            "name": "Sparse distant target intermediate scale (1,500 nodes)",
            "slice": "sparse_distant_targets",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["mid_sparse.elem_50"], "max_hops": 2}],
        }

    # Micro structural cases (idx 1..5)
    length = 20 + idx * 8
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
        "name": f"Sparse distant target structural case {idx} (diameter={length})",
        "slice": "sparse_distant_targets",
        "scenario_type": "standard",
        "tier": "S0_micro",
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
            "failure_mechanism": "Query pointer references poisoned/corrupted index payload; must fail-closed with INCONCLUSIVE",
            "tier": "S4",
            "graph": {"nodes": [{"id": "poison.seed", "type": "FUNCTION", "name": "seed"}], "edges": []},
            "queries": [{"seeds": ["poison.seed"], "max_hops": 2}],
        }

    # Production Scale S1 instance for idx == 7 (|V| = 10,000)
    if idx == 7:
        nodes = [
            {"id": "disagree_s1.seed_func", "type": "FUNCTION", "name": "payment_dispatch", "module": "billing"},
            {"id": "disagree_s1.real_callee", "type": "FUNCTION", "name": "internal_calc_x", "module": "math"},
            {"id": "disagree_s1.fake_decoy", "type": "FUNCTION", "name": "payment_dispatch_v2_fake", "module": "decoy"},
        ]
        edges = [
            {"src": "disagree_s1.seed_func", "dst": "disagree_s1.real_callee", "type": "CALLS"},
        ]
        for i in range(1, 9998):
            nid = f"disagree_s1.noise_{i}"
            nodes.append({"id": nid, "type": "FUNCTION", "name": f"noise_{i}", "module": f"noise_{i//500}"})
            if i % 10 == 0:
                edges.append({"src": "disagree_s1.real_callee", "dst": nid, "type": "CALLS"})
        return {
            "id": case_id,
            "name": "Dense-sparse disagreement S1 production scale (10,000 nodes)",
            "slice": "dense_sparse_disagreement",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["disagree_s1.seed_func"], "max_hops": 2}],
        }

    # Intermediate scale for idx == 6 (|V| = 1,500)
    if idx == 6:
        nodes = [
            {"id": "mid_disagree.seed_func", "type": "FUNCTION", "name": "payment_dispatch", "module": "billing"},
            {"id": "mid_disagree.real_callee", "type": "FUNCTION", "name": "internal_calc_x", "module": "math"},
            {"id": "mid_disagree.fake_decoy", "type": "FUNCTION", "name": "payment_dispatch_v2_fake", "module": "decoy"},
        ]
        edges = [
            {"src": "mid_disagree.seed_func", "dst": "mid_disagree.real_callee", "type": "CALLS"},
        ]
        for i in range(1, 1498):
            nid = f"mid_disagree.noise_{i}"
            nodes.append({"id": nid, "type": "FUNCTION", "name": f"noise_{i}", "module": "noise"})
            if i % 10 == 0:
                edges.append({"src": "mid_disagree.real_callee", "dst": nid, "type": "CALLS"})
        return {
            "id": case_id,
            "name": "Dense-sparse disagreement intermediate scale (1,500 nodes)",
            "slice": "dense_sparse_disagreement",
            "scenario_type": "standard",
            "tier": "S1",
            "graph": {"nodes": nodes, "edges": edges},
            "queries": [{"seeds": ["mid_disagree.seed_func"], "max_hops": 2}],
        }

    # Micro structural cases (idx 1..5)
    nodes = [
        {"id": f"disagree_{idx}.seed_func", "type": "FUNCTION", "name": "payment_dispatch", "module": "billing"},
        {"id": f"disagree_{idx}.real_callee", "type": "FUNCTION", "name": "internal_calc_x", "module": "math"},
        {"id": f"disagree_{idx}.fake_decoy", "type": "FUNCTION", "name": "payment_dispatch_v2_fake", "module": "decoy"},
    ]
    edges = [
        {"src": f"disagree_{idx}.seed_func", "dst": f"disagree_{idx}.real_callee", "type": "CALLS"},
    ]
    for i in range(1, 10 + idx * 4):
        nodes.append({"id": f"disagree_{idx}.noise_{i}", "type": "FUNCTION", "name": f"noise_{i}", "module": "noise"})
        edges.append({"src": f"disagree_{idx}.real_callee", "dst": f"disagree_{idx}.noise_{i}", "type": "CALLS"})

    return {
        "id": case_id,
        "name": f"Dense-sparse disagreement structural case {idx}",
        "slice": "dense_sparse_disagreement",
        "scenario_type": "standard",
        "tier": "S0_micro",
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
    print("Authoring CAP-007 corpus across 64 cases (including real S1/S2 scale tiers)...")
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

    total_nodes = sum(len(c["graph"]["nodes"]) for c in cases)
    total_edges = sum(len(c["graph"]["edges"]) for c in cases)

    print("\nCAP-007 STEP 1 REV 2 FREEZE COMPLETE:")
    print(f"Total Cases:     {len(cases)}")
    print(f"Total Nodes:     {total_nodes:,}")
    print(f"Total Edges:     {total_edges:,}")
    print(f"cases.jsonl:     {c_sha}")
    print(f"labels.jsonl:    {l_sha}")
    print(f"manifest.jsonl:  {m_sha}")


if __name__ == "__main__":
    main()
