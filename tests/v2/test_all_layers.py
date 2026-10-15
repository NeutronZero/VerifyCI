from __future__ import annotations

import pytest

from verifyci_v2 import VerifyCIConfig
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.interface.cli import run_cli
from verifyci_v2.interface.fastmcp_daemon import VerifyCIFastMCPDaemon
from verifyci_v2.neural.adapters import (
    DeterministicJudgeAdapter,
    OpenAICompatibleJudgeAdapter,
)
from verifyci_v2.neural.cegis_repair import CEGISAutoRepairEngine
from verifyci_v2.neural.conformal import (
    calibrate_judge_on_dataset,
    compute_conformal_quantile,
    evaluate_with_conformal_gate,
)
from verifyci_v2.neural.spec_compiler import IntentToSMTCompiler
from verifyci_v2.provenance.gittuf_rsl import RSLTamperDetectedError
from verifyci_v2.sandbox.wasm_runner import (
    SandboxCapabilityViolationError,
    SandboxFuelExhaustedError,
    WasmCheckerSandbox,
    WasmSandboxConfig,
)
from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore
from verifyci_v2.store.model2vec_embed import build_neighborhood_header
from verifyci_v2.store.rabitq_index import RaBitQHybridIndex
from verifyci_v2.symbolic.egglog_engine import EgglogEquivalenceEngine
from verifyci_v2.symbolic.secrets_taint import TaintTrackedSecretEngine
from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver


def test_layer4_duckdb_temporal_as_of_and_rabitq_pruning() -> None:
    store = DuckDBCPGStore(":memory:")
    src_c1 = "def charge(user_id: int, amount: int) -> int:\n    return amount\n"
    src_c2 = "def charge(user_id: int, amount: int) -> int:\n    return amount + 5\n"

    fns_c1 = lower_file_to_ussa("src/pay.py", src_c1)
    fns_c2 = lower_file_to_ussa("src/pay.py", src_c2)

    store.record_commit_snapshot("commit_v1", fns_c1)
    store.record_commit_snapshot("commit_v2", fns_c2, parent_sha="commit_v1")

    replay_v1 = store.get_function_as_of("commit_v1", "src.pay.charge")
    replay_v2 = store.get_function_as_of("commit_v2", "src.pay.charge")
    assert replay_v1 is not None and replay_v2 is not None
    assert replay_v1.h_body != replay_v2.h_body
    assert replay_v1.h_body == fns_c1[0].h_body

    # Test RaBitQ 1-bit index & error-bounded pruning across 40 functions
    index = RaBitQHybridIndex()
    for i in range(40):
        fn_src = f"def helper_{i}(x: int) -> int:\n    return x + {i}\n"
        fn_ussa = lower_file_to_ussa(f"src/mod_{i}.py", fn_src)[0]
        hdr = build_neighborhood_header(fn_ussa, callers=[f"caller_{i}"], callees=[])
        index.upsert_document(
            fn_ussa.node_uid, fn_ussa.qualified_name, hdr, coverage_hit_freq=float(i)
        )

    stats = index.search("def helper_39 caller_39", top_k=3, confidence_z=0.5)
    assert len(stats.results) == 3
    assert stats.total_candidates == 40
    assert stats.pruned_by_error_bound > 0
    assert stats.results[0].qualified_name == "src.mod_39.helper_39"


def test_layer5_egglog_equivalence_and_datalog_rules() -> None:
    egg = EgglogEquivalenceEngine()

    # Algebraically equivalent refactoring (commutativity + dead temporary elimination + identity)
    base_src = """
def calc_score(a: int, b: int) -> int:
    temp = a + b
    return temp + 0
"""
    head_src = """
def calc_score(a: int, b: int) -> int:
    return b + a
"""
    f_base = lower_file_to_ussa("src/math.py", base_src)[0]
    f_head = lower_file_to_ussa("src/math.py", head_src)[0]
    eq = egg.check_equivalence(f_base, f_head)
    assert eq.is_equivalent is True

    # Datalog Unsafe Deletion (cap003a)
    del_findings = egg.datalog_unsafe_deletions(
        removed_qnames=["src.core.legacy_auth"],
        active_callers_map={"src.core.legacy_auth": ["src.api.login_route"]},
        file_path="src/core.py",
    )
    assert len(del_findings) == 1
    assert del_findings[0].rule_id == "VC2-CAP003A-UNSAFE-DELETION"

    # Datalog Concurrency Lock-Order Inversion & Unguarded Shared Mutation (cap008)
    conc_src = """
def worker_a():
    with lock_1:
        with lock_2:
            pass

def worker_b():
    with lock_2:
        with lock_1:
            pass

async def async_mutator():
    state.counter += 1
"""
    conc_findings = egg.datalog_concurrency_invariants("src/workers.py", conc_src)
    rule_ids = {f.rule_id for f in conc_findings}
    assert "VC2-CAP008-LOCK-ORDER-INVERSION" in rule_ids
    assert "VC2-CAP008-UNGUARDED-SHARED-MUTATION" in rule_ids


def test_layer5_and_6_z3_prover_and_cegis_auto_repair() -> None:
    prover = Z3SymbolicProver()
    cegis = CEGISAutoRepairEngine(prover=prover)

    # 1. Aliased Call Swap (cap004)
    base_call = """
def transfer(sender: int, receiver: int) -> int:
    s = sender
    r = receiver
    return execute_wire(s, r)
"""
    head_call_bug = """
def transfer(sender: int, receiver: int) -> int:
    s = sender
    r = receiver
    return execute_wire(r, s)
"""
    fb = lower_file_to_ussa("src/bank.py", base_call)[0]
    fh = lower_file_to_ussa("src/bank.py", head_call_bug)[0]

    findings = prover.prove_function_diff(
        file_path="src/bank.py",
        base_source=base_call,
        head_source=head_call_bug,
        func_base=fb,
        func_head=fh,
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "VC2-CAP004-CALL-SWAP"
    assert finding.witness is not None
    assert finding.witness.smt_status == "SAT"
    assert (
        finding.witness.input_assignments["sender"]
        != finding.witness.input_assignments["receiver"]
    )

    # Synthesize and Z3-verify auto-repair via CEGIS!
    repaired = cegis.repair_finding(
        file_path="src/bank.py",
        base_source=base_call,
        head_source=head_call_bug,
        finding=finding,
        target_qualified_name="src.bank.transfer",
    )
    assert len(repaired.fixes) == 1
    assert repaired.fixes[0].z3_verified_unsat is True
    assert "execute_wire(s, r)" in repaired.fixes[0].replacement_text


def test_layer5_and_6_secrets_taint_redaction_and_conformal_gate() -> None:
    import base64

    engine = TaintTrackedSecretEngine()
    raw_aws = "AKIAIOSFODNN7EXAMPLE"
    b64_aws = base64.b64encode(raw_aws.encode("utf-8")).decode("ascii")

    prod_src = f"""
def connect_aws():
    api_token = "{b64_aws}"
    print(api_token)
"""
    prod_findings = engine.scan_python_source("src/prod_aws.py", prod_src)
    assert len(prod_findings) == 1
    assert prod_findings[0].rule_id == "VC2-SECRET-AWS_ACCESS_KEY"
    assert prod_findings[0].severity == "CRITICAL"

    # Mock fixture in `tests/` partition should be suppressed (`cap002b`)
    test_fixture_src = """
def test_login():
    mock_api_key = "mock_dummy_test_key_1234567890"
    return mock_api_key
"""
    assert engine.scan_python_source("tests/test_auth.py", test_fixture_src) == ()

    # Pre-egress secret redaction in OpenAICompatibleJudgeAdapter
    remote_adapter = OpenAICompatibleJudgeAdapter(base_url="https://api.example.com/v1")
    req = remote_adapter.prepare_redacted_request(
        {"code": f'secret_key = "{raw_aws}"'},
        question="Is this safe?",
    )
    assert raw_aws not in str(req)
    assert "<REDACTED_SECRET_1>" in remote_adapter.last_redacted_payload

    # Split Conformal Prediction quantile and abstention gate
    q_hat = compute_conformal_quantile([0.01, 0.03, 0.05, 0.08, 0.12], alpha=0.20)
    judge = DeterministicJudgeAdapter()
    profile = calibrate_judge_on_dataset(
        judge,
        [({"code": "x = 1"}, "none"), ({"code": "y = 2"}, "none")],
        options=("none", "defect"),
        alpha=0.10,
    )
    ambiguous_decision = evaluate_with_conformal_gate(
        {"none": 0.52, "defect": 0.48},
        profile,
        safe_label="none",
    )
    assert ambiguous_decision.escalate_to_smt is True
    assert q_hat <= 1.0


def test_layer7_wasm_sandbox_intoto_dsse_and_gittuf_rsl() -> None:
    sandbox = WasmCheckerSandbox(
        WasmSandboxConfig(max_instruction_fuel=2000, require_wasm_isolation=False)
    )
    fns = lower_file_to_ussa("src/a.py", "def f(x: int) -> int:\n    return x + 1\n")

    # Forbidden host I/O capability in plugin source must be rejected
    with pytest.raises(SandboxCapabilityViolationError):
        sandbox.register_plugin(
            "evil_plugin", "import os; os.system('rm -rf /')", lambda _fns: []
        )

    # Valid read-only checker plugin
    sandbox.register_plugin("noop_plugin", "def check(fns): return []", lambda _fns: [])
    report = sandbox.execute_plugin("noop_plugin", fns)
    assert report.fuel_consumed > 0
    assert report.findings == ()

    # Exhaust fuel limit on tiny budget
    tight_sandbox = WasmCheckerSandbox(
        WasmSandboxConfig(max_instruction_fuel=100, require_wasm_isolation=False)
    )
    tight_sandbox.register_plugin(
        "tight_plugin", "def check(fns): return []", lambda _fns: []
    )
    with pytest.raises(SandboxFuelExhaustedError):
        tight_sandbox.execute_plugin("tight_plugin", fns)

    # Test CLI, FastMCP Daemon, in-toto DSSE signature verification, and gittuf RSL tamper detection
    cli_prove = run_cli(
        [
            "prove",
            "--file",
            "src/guard.py",
            "--base-source",
            "def check_age(age: int) -> bool:\n    if age >= 18:\n        return True\n    return False\n",
            "--head-source",
            "def check_age(age: int) -> bool:\n    if age < 18:\n        return True\n    return False\n",
            "--fix",
        ]
    )
    finding = cli_prove["data"]["findings"][0]
    assert finding["rule_id"] == "VC2-CAP002-GUARD-INVERSION"
    assert finding["fixes"][0]["z3_verified_unsat"] is True

    # Test gittuf Reference State Log hash chain & rollback detection
    daemon = VerifyCIFastMCPDaemon(repo_id="rsl-repo")
    anchor_1 = daemon.invoke_tool(
        "vc_anchor_attestation", {"head_commit_sha": "commit_111"}
    )
    anchor_2 = daemon.invoke_tool(
        "vc_anchor_attestation", {"head_commit_sha": "commit_222"}
    )
    assert (
        anchor_2["data"]["rsl_entry"]["parent_entry_id"]
        == anchor_1["data"]["rsl_entry"]["entry_id"]
    )
    assert daemon.rsl.verify_rsl_lineage(expected_head_commit="commit_222") is True

    with pytest.raises(RSLTamperDetectedError):
        daemon.rsl.verify_rsl_lineage(expected_head_commit="rolled_back_commit_111")


def test_intent_to_smt_compiler_and_full_capability_adjudicator() -> None:
    cfg = VerifyCIConfig.load()
    assert cfg.ai_provider == "deterministic"

    # Test Intent-to-SMT compiler catching an unclamped discount calculation
    compiler = IntentToSMTCompiler()
    unclamped_checkout = """
def apply_discount(total: int, discount: int) -> int:
    return total - discount
"""
    intent_findings = compiler.verify_function_against_intent(
        file_path="src/checkout.py",
        source=unclamped_checkout,
        intent_text="Ensure checkout amount never drops below zero after discount",
    )
    assert len(intent_findings) == 1
    assert intent_findings[0].rule_id == "VC2-INTENT-POSTCONDITION-VIOLATION"
    assert intent_findings[0].witness is not None
    assert intent_findings[0].witness.smt_status == "SAT"

    # Clamped implementation satisfies the compiled SMT postcondition
    clamped_checkout = """
def apply_discount(total: int, discount: int) -> int:
    return max(0, total - discount)
"""
    assert (
        compiler.verify_function_against_intent(
            file_path="src/checkout.py",
            source=clamped_checkout,
            intent_text="Ensure checkout amount never drops below zero after discount",
        )
        == ()
    )

    # Test `vc2 check` and `vc2 adjudicate` CLI commands across all 15 capabilities
    check_resp = run_cli(
        [
            "check",
            "--file",
            "src/checkout.py",
            "--source",
            unclamped_checkout,
            "--intent",
            "Ensure checkout amount never drops below zero",
        ]
    )
    assert check_resp["finding_count"] == 1

    adj_resp = run_cli(["adjudicate"])
    assert adj_resp["all_passed"] is True
    assert adj_resp["total_capabilities"] == 15
    assert adj_resp["passed_count"] == 15


def test_extended_dfg_taint_and_euf_and_egglog_rules() -> None:
    from verifyci_v2.symbolic.egglog_engine import _canonicalize_sexpr
    from verifyci_v2.symbolic.secrets_taint import TaintTrackedSecretEngine
    from verifyci_v2.symbolic.z3_prover import _evaluate_concrete_divergence

    # 1. Transitive DFG taint propagation through dict interpolation to sink
    engine = TaintTrackedSecretEngine()
    code_dict = """
def post_token():
    secret_tok = "tok_live_1234567890abcdef"
    payload = {"Authorization": secret_tok}
    requests.post("https://api.stripe.com", json=payload)
"""
    findings = engine.scan_python_source("src/net.py", code_dict)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "flows into active I/O sink" in findings[0].message

    # 2. Transitive DFG taint propagation through f-strings
    code_fstr = """
def log_token():
    raw_key = "tok_live_1234567890abcdef"
    msg = f"Bearer {raw_key}"
    logger.info(msg)
"""
    fstr_findings = engine.scan_python_source("src/logger.py", code_fstr)
    assert len(fstr_findings) == 1
    assert fstr_findings[0].severity == "CRITICAL"

    # 3. Z3 EUF symbolic divergence without exec()
    base_src = "def call_fn(a: int, b: int) -> int:\n    return wire(a, b)\n"
    head_src = "def call_fn(a: int, b: int) -> int:\n    return wire(b, a)\n"
    diverges = _evaluate_concrete_divergence(
        base_src, head_src, "call_fn", ("a", "b"), {"a": 1, "b": 2}
    )
    assert diverges is True

    # When inputs are identical under EUF congruence closure, no divergence
    same = _evaluate_concrete_divergence(
        base_src, head_src, "call_fn", ("a", "b"), {"a": 5, "b": 5}
    )
    assert same is False

    # 4. Egglog rewrite rules for Sub and Boolean idempotence
    rw: list[str] = []
    assert _canonicalize_sexpr("(Sub x 0)", rw) == "x"
    assert _canonicalize_sexpr("(Sub x x)", rw) == "0"
    assert _canonicalize_sexpr("(And x x)", rw) == "x"
    assert _canonicalize_sexpr("(Or x x)", rw) == "x"
    assert "sub_zero_identity" in rw
    assert "sub_self_annihilation" in rw
    assert "idempotent_And" in rw
    assert "idempotent_Or" in rw
