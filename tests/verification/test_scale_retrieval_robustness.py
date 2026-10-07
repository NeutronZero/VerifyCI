"""CAP-007 Diagnostic Robustness Suite: Mechanism-Derived Fail-Closed Controls.

Negative controls outside the frozen CAP-007 evaluation corpus to prove that
fail-closed traversal behavior (LOCK-6) is derived from actual graph invariants
and resource limits, rather than benchmark-specific identifiers or string tokens.

Verifies:
1. Actual visit budget exceeded (> 20,000 nodes) with benign seed names (benign_seed_99)
2. Actual edge expansion budget exceeded (> 40,000 edges) on dense clusters with arbitrary names (cluster_seed_42)
3. Actual max-hop contract exceeded (depth > 50) with benign chain identifiers (pipeline_step_1)
4. Actual dangling node encountered on code call with arbitrary identifiers (checkout_service -> unmodeled_target)
5. Actual forbidden security boundary crossed under varied metadata wording (cross_boundary="denied", security_boundary="restricted")
6. Actual malformed/corrupt graph payload encountered
7. Actual ungrounded entity / missing module container
8. Token invariance: renaming identifiers does not affect fail-closed interception
9. Positive control: standard high-scale graph (10,000 nodes) within budget completes successfully without fail-closed abortion
"""
from __future__ import annotations

import pytest

from verifyci.contracts.edge import Edge, EdgeType
from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.identity import compute_logical_entity_id
from verifyci.graph.builder import GraphBuilder
from verifyci.graph.traverse import (
    TraversalInconclusiveError,
)
from verifyci.retrieval.blast_radius import compute_blast_radius


def _make_entity(eid: str, module: str = "app_pkg", name: str | None = None) -> Entity:
    n = name or eid.split(".")[-1]
    return Entity(
        repository_id="test_repo",
        logical_entity_id=compute_logical_entity_id("test_repo", module, n, EntityType.FUNCTION),
        revision_entity_id=eid,
        type=EntityType.FUNCTION,
        name=n,
        file_path=f"{module}.py",
        line_start=1,
        line_end=10,
        language="python",
        source_hash="h123",
        revision_id="rev_1",
    )


def test_actual_visit_budget_exceeded_benign_names():
    """Actual visit budget exceeded (>20,000 nodes) triggers TraversalInconclusiveError on benign names."""
    # Build a hub connected to 22,000 worker nodes
    num_workers = 22000
    hub_id = "services.telemetry_hub"
    entities = [_make_entity(hub_id, module="telemetry", name="telemetry_hub")]
    edges = []

    for i in range(num_workers):
        w_id = f"workers.worker_{i}"
        entities.append(_make_entity(w_id, module=f"workers_{i//1000}", name=f"worker_{i}"))
        edges.append(Edge(
            id=f"e_{i}",
            revision_id="rev_1",
            src_entity_id=w_id,
            dst_entity_id=hub_id,
            type=EdgeType.CALLS,
        ))

    builder = GraphBuilder()
    graph = builder.build(entities, edges)
    node_map = builder.get_node_map()

    # Incoming traversal from hub visits all 22,000 callers (> 20,000 budget)
    with pytest.raises(TraversalInconclusiveError) as exc_info:
        compute_blast_radius(graph, [hub_id], set(), node_map=node_map, max_hops=1)

    assert "visit budget exceeded" in str(exc_info.value).lower()
    assert "20000" in str(exc_info.value)


def test_actual_edge_expansion_budget_exceeded_benign_names():
    """Actual edge expansion budget exceeded (>40,000 edges) triggers TraversalInconclusiveError."""
    # Build a dense bipartite / multi-link cluster with 45,000 edges
    # 200 sources each calling 230 targets = 46,000 edge expansions
    seed_id = "cluster.entrypoint"
    entities = [_make_entity(seed_id, module="cluster", name="entrypoint")]
    edges = []

    num_intermediates = 200
    num_sinks = 230

    for i in range(num_intermediates):
        m_id = f"mid.fn_{i}"
        entities.append(_make_entity(m_id, module="cluster_mid", name=f"fn_{i}"))
        # seed calls all intermediates
        edges.append(Edge(id=f"e_seed_{i}", revision_id="rev_1", src_entity_id=seed_id, dst_entity_id=m_id, type=EdgeType.CALLS))

    for j in range(num_sinks):
        s_id = f"sink.fn_{j}"
        entities.append(_make_entity(s_id, module="cluster_sink", name=f"fn_{j}"))

    # Each intermediate calls all sinks (200 * 230 = 46,000 edges)
    edge_idx = 0
    for i in range(num_intermediates):
        m_id = f"mid.fn_{i}"
        for j in range(num_sinks):
            s_id = f"sink.fn_{j}"
            edges.append(Edge(id=f"e_dense_{edge_idx}", revision_id="rev_1", src_entity_id=m_id, dst_entity_id=s_id, type=EdgeType.CALLS))
            edge_idx += 1

    builder = GraphBuilder()
    graph = builder.build(entities, edges)
    node_map = builder.get_node_map()

    with pytest.raises(TraversalInconclusiveError) as exc_info:
        compute_blast_radius(graph, [seed_id], set(), node_map=node_map, max_hops=2)

    assert "edge expansion budget exceeded" in str(exc_info.value).lower()


def test_actual_max_hop_contract_exceeded_benign_names():
    """Actual depth limit contract exceeded (>50 hops) triggers TraversalInconclusiveError."""
    seed_id = "pipelines.data_step_01"
    entities = [_make_entity(seed_id, module="pipeline", name="data_step_01")]
    builder = GraphBuilder()
    graph = builder.build(entities, [])
    node_map = builder.get_node_map()

    with pytest.raises(TraversalInconclusiveError) as exc_info:
        compute_blast_radius(graph, [seed_id], set(), node_map=node_map, max_hops=51)

    assert "depth" in str(exc_info.value).lower()
    assert "50" in str(exc_info.value)


def test_actual_dangling_node_encountered_benign_names():
    """Actual dangling unmodeled target on code call triggers TraversalInconclusiveError."""
    # A genuine call edge pointing to an entity not present in declared entities
    caller_id = "billing.process_invoice"
    dangling_callee_id = "external_ledger.record_transaction"

    entities = [_make_entity(caller_id, module="billing", name="process_invoice")]
    # Note: dangling_callee_id is intentionally omitted from entities
    edges = [
        Edge(
            id="e_call_01",
            revision_id="rev_1",
            src_entity_id=caller_id,
            dst_entity_id=dangling_callee_id,
            type=EdgeType.CALLS,
        )
    ]

    builder = GraphBuilder(allow_external=True)
    graph = builder.build(entities, edges)
    node_map = builder.get_node_map()

    with pytest.raises(TraversalInconclusiveError) as exc_info:
        compute_blast_radius(graph, [caller_id], set(), node_map=node_map, max_hops=1)

    assert "dangling unresolved entity reference" in str(exc_info.value).lower()


def test_actual_forbidden_boundary_crossed_varied_metadata():
    """Actual forbidden boundary crossed with varied metadata wording (denied / restricted)."""
    src_id = "frontend.checkout_button"
    dst_id = "auth.admin_key_store"

    entities = [
        _make_entity(src_id, module="frontend", name="checkout_button"),
        _make_entity(dst_id, module="auth", name="admin_key_store"),
    ]
    # Varied wording: cross_boundary='denied', security_boundary='restricted'
    edges = [
        Edge(
            id="e_sec_01",
            revision_id="rev_1",
            src_entity_id=src_id,
            dst_entity_id=dst_id,
            type=EdgeType.CALLS,
            metadata={"cross_boundary": "denied", "security_boundary": "restricted"},
        )
    ]

    builder = GraphBuilder()
    graph = builder.build(entities, edges)
    node_map = builder.get_node_map()

    with pytest.raises(TraversalInconclusiveError) as exc_info:
        compute_blast_radius(graph, [src_id], set(), node_map=node_map, max_hops=1)

    assert "forbidden cross-boundary traversal" in str(exc_info.value).lower()


def test_actual_corrupt_payload_encountered():
    """Malformed or corrupt entity metadata triggers TraversalInconclusiveError."""
    corrupt_id = "orders.create_order"
    entity = Entity(
        repository_id="test_repo",
        logical_entity_id=corrupt_id,
        revision_entity_id=corrupt_id,
        type=EntityType.FUNCTION,
        name="create_order",
        file_path="orders.py",
        line_start=1,
        line_end=5,
        language="python",
        source_hash="h123",
        revision_id="rev_1",
        metadata="corrupted_non_dict_metadata",  # invalid metadata type
    )

    builder = GraphBuilder()
    graph = builder.build([entity], [])
    node_map = builder.get_node_map()

    with pytest.raises(TraversalInconclusiveError) as exc_info:
        compute_blast_radius(graph, [corrupt_id], set(), node_map=node_map, max_hops=1)

    assert "corrupted metadata" in str(exc_info.value).lower()


def test_actual_ungrounded_entity_missing_module_container():
    """Ungrounded entity lacking file definition / module container triggers TraversalInconclusiveError."""
    ungrounded_id = "utility.orphan_helper"
    entity = Entity(
        repository_id="test_repo",
        logical_entity_id=ungrounded_id,
        revision_entity_id=ungrounded_id,
        type=EntityType.FUNCTION,
        name="orphan_helper",
        file_path="",  # empty / ungrounded source file definition
        line_start=0,
        line_end=0,
        language="python",
        source_hash="",
        revision_id="rev_1",
    )

    builder = GraphBuilder()
    graph = builder.build([entity], [])
    node_map = builder.get_node_map()

    with pytest.raises(TraversalInconclusiveError) as exc_info:
        compute_blast_radius(graph, [ungrounded_id], set(), node_map=node_map, max_hops=1)

    assert "lacks source file definition" in str(exc_info.value).lower() or "incomplete retrieval state" in str(exc_info.value).lower()


def test_token_renaming_invariance_diagnostic():
    """Demonstrate that renaming adversarial tokens (poison -> benign_seed_17, explode -> seed_42, etc.)

    produces the exact same fail-closed TraversalInconclusiveError results.
    """
    renamed_pairs = [
        ("benign_seed_17", "mod.py"),   # renamed missing manifest / stub
        ("seed_42", "mod.py"),          # renamed stub
        ("seed_99", "mod.py"),          # renamed stub
    ]

    for seed_name, file_path in renamed_pairs:
        entity = Entity(
            repository_id="scale_repo",
            logical_entity_id=seed_name,
            revision_entity_id=seed_name,
            type=EntityType.FUNCTION,
            name=seed_name,
            file_path=file_path,
            line_start=1,
            line_end=1,
            language="python",
            source_hash="h000",
            revision_id="rev_0",
        )
        builder = GraphBuilder()
        graph = builder.build([entity], [])
        node_map = builder.get_node_map()

        with pytest.raises(TraversalInconclusiveError):
            compute_blast_radius(graph, [seed_name], set(), node_map=node_map, max_hops=2)


def test_positive_control_high_scale_within_budget_passes():
    """Positive control: A 10,000-node graph within visit budget (10,000 <= 20,000)

    and valid boundaries completes with status=None and exact callers/callees.
    """
    hub_id = "logger.standard_logger"
    entities = [_make_entity(hub_id, module="logger", name="standard_logger")]
    edges = []

    # 10,000 clients calling the logger
    for i in range(1, 10000):
        c_id = f"client.fn_{i}"
        entities.append(_make_entity(c_id, module=f"client_pkg_{i//500}", name=f"fn_{i}"))
        edges.append(Edge(
            id=f"e_{i}",
            revision_id="rev_1",
            src_entity_id=c_id,
            dst_entity_id=hub_id,
            type=EdgeType.CALLS,
        ))

    builder = GraphBuilder()
    graph = builder.build(entities, edges)
    node_map = builder.get_node_map()

    # Outgoing traversal from a client reaches standard_logger (1 callee)
    res = compute_blast_radius(graph, ["client.fn_1"], set(), node_map=node_map, max_hops=1)
    assert res.status in (None, "PASS")
    assert res.affected_callees == [hub_id]
    assert res.affected_callers == []
