from __future__ import annotations

import pytest

from verifyci_v2.contracts.canonical import (
    CanonicalSerializationError,
    canonical_digest,
    canonical_jcs_str,
)
from verifyci_v2.ingestion.salsa_cutoff import SalsaIncrementalEngine
from verifyci_v2.interface.fastmcp_daemon import (
    IngressBudgetConfig,
    IngressLimitExceededError,
    VerifyCIFastMCPDaemon,
)


def test_rfc8785_jcs_canonicalization_and_digest_determinism() -> None:
    payload_a = {"b": [1, -0.0, 2.0], "a": "hello\nworld"}
    payload_b = {"a": "hello\nworld", "b": [1, 0, 2]}
    assert canonical_jcs_str(payload_a) == '{"a":"hello\\nworld","b":[1,0,2]}'
    assert canonical_jcs_str(payload_a) == canonical_jcs_str(payload_b)
    assert canonical_digest(payload_a) == canonical_digest(payload_b)

    with pytest.raises(CanonicalSerializationError):
        canonical_jcs_str({"bad": float("nan")})


def test_ussa_phi_nodes_and_comment_invariance() -> None:
    engine = SalsaIncrementalEngine(repo_id="test-repo")

    src_v1 = '''
def compute_discount(price: int, is_vip: bool) -> int:
    """Initial docstring."""
    discount = 0
    if is_vip:
        discount = 20
    else:
        discount = 5
    final_price = price - discount
    return final_price
'''
    plan_v1 = engine.ingest_file("src/billing.py", src_v1, language="python")
    assert plan_v1.evaluations[0].status == "NEW_FUNCTION"

    ussa = engine.get_function_ussa("src.billing.compute_discount")
    assert ussa is not None
    # Verify SSA Phi node was inserted at merge block for variable 'discount'
    merge_blocks = [b for b in ussa.basic_blocks if b.block_id.startswith("merge_")]
    assert len(merge_blocks) == 1
    assert len(merge_blocks[0].phi_nodes) == 1
    assert merge_blocks[0].phi_nodes[0].target_var.startswith("discount_")

    # Case 1: Comment and docstring change must produce an O(1) H_body cache hit
    src_v1_comment_edit = '''
# Added header comment that should not alter U-SSA H_body
def compute_discount(price: int, is_vip: bool) -> int:
    """Updated docstring with extra details."""
    discount = 0  # inline comment
    if is_vip:
        discount = 20
    else:
        discount = 5
    final_price = price - discount
    return final_price
'''
    plan_comment = engine.ingest_file("src/billing.py", src_v1_comment_edit, language="python")
    assert plan_comment.evaluations[0].status == "CACHE_HIT_BODY_IDENTICAL"
    assert plan_comment.functions_to_verify_locally == ()
    assert plan_comment.transitive_callers_to_reverify == ()


def test_salsa_early_cutoff_skips_transitive_callers_on_private_body_edit() -> None:
    engine = SalsaIncrementalEngine(repo_id="test-repo")

    engine.ingest_file(
        "src/core.py",
        """
def calc_tax(amount: int) -> int:
    rate = 10
    return amount * rate
""",
    )
    engine.ingest_file(
        "src/checkout.py",
        """
from src.core import calc_tax

def run_checkout(total: int) -> int:
    return total + calc_tax(total)
""",
    )

    # Mutate calc_tax internal implementation without changing signature, purity, or taint summary
    plan_case2 = engine.ingest_file(
        "src/core.py",
        """
def calc_tax(amount: int) -> int:
    rate = 15
    return amount * rate
""",
    )
    eval_res = plan_case2.evaluations[0]
    assert eval_res.status == "CUTOFF_INTERFACE_INVARIANT"
    assert plan_case2.functions_to_verify_locally == ("src.core.calc_tax",)
    assert plan_case2.transitive_callers_to_reverify == ()
    assert "src.checkout.run_checkout" in plan_case2.skipped_transitive_callers

    # Case 3: Mutate calc_tax interface contract (now raises ValueError) -> must propagate to caller!
    plan_case3 = engine.ingest_file(
        "src/core.py",
        """
def calc_tax(amount: int) -> int:
    if amount < 0:
        raise ValueError("negative")
    return amount * 15
""",
    )
    assert plan_case3.evaluations[0].status == "PROPAGATE_INTERFACE_CHANGED"
    assert "src.checkout.run_checkout" in plan_case3.transitive_callers_to_reverify


def test_polyglot_ffi_and_http_bridges_and_fastmcp_daemon() -> None:
    daemon = VerifyCIFastMCPDaemon(
        repo_id="polyglot-repo",
        budget=IngressBudgetConfig(max_payload_bytes=65536, rate_limit_capacity=10.0),
    )

    resp = daemon.invoke_tool(
        "vc_ingest_files",
        {
            "files": [
                {
                    "file_path": "src/util.c",
                    "language": "c",
                    "source": "int fast_crc32(int x) {\n    return x ^ 0xFF;\n}\n",
                },
                {
                    "file_path": "src/api/routes.py",
                    "language": "python",
                    "source": """
import ctypes
lib = ctypes.CDLL("./libutil.so")

@app.get("/api/v1/checksum/{item_id}")
def get_checksum(item_id: int) -> int:
    return lib.fast_crc32(item_id)
""",
                },
                {
                    "file_path": "web/client.ts",
                    "language": "typescript",
                    "source": """
export async function fetchItemChecksum(itemId: number) {
    return fetch(`/api/v1/checksum/${itemId}`);
}
""",
                },
            ]
        },
    )
    assert resp["status"] == "ok"
    assert resp["latency_ms"] < 50.0

    bridges_resp = daemon.invoke_tool("vc_polyglot_bridges", {})
    bridges = bridges_resp["data"]["bridges"]
    kinds = {b["edge_kind"] for b in bridges}
    assert "FFI_BRIDGE" in kinds
    assert "HTTP_BRIDGE" in kinds

    # Verify full-stack blast radius from C function -> Python route -> TypeScript caller
    blast_resp = daemon.invoke_tool(
        "vc_blast_radius",
        {"qualified_names": ["src.util.fast_crc32"]},
    )
    callers = blast_resp["data"]["transitive_callers"]
    assert "src.api.routes.get_checksum" in callers
    assert "web.client.fetchItemChecksum" in callers

    # Verify payload limit guard
    with pytest.raises(IngressLimitExceededError):
        daemon.invoke_tool("vc_blast_radius", {"qualified_names": ["x" * 70000]})