from __future__ import annotations

import base64
from pathlib import Path
import tomllib
from typing import Any
import pytest


from verifyci_v2.contracts.ai_protocol import GenerativeSynthesizerProtocol
from verifyci_v2.contracts.attestation import (
    DSSEEnvelope,
    InTotoVerificationPredicate,
)
from verifyci_v2.contracts.ssa_ir import CPGEdge
from verifyci_v2.ingestion.salsa_cutoff import SalsaIncrementalEngine
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.ingestion.stack_graphs import StackGraphStitcher
from verifyci_v2.neural.adapters import (
    DeterministicJudgeAdapter,
    OpenAICompatibleJudgeAdapter,
)
from verifyci_v2.neural.cegis_repair import CEGISAutoRepairEngine
from verifyci_v2.neural.conformal import (
    calibrate_judge_on_dataset,
    evaluate_with_conformal_gate,
)
from verifyci_v2.provenance.dsse_intoto import InTotoDSSESigner
from verifyci_v2.provenance.gittuf_rsl import GittufRSLLedger, RSLTamperDetectedError
from verifyci_v2.sandbox.wasm_runner import (
    SandboxCapabilityViolationError,
    SandboxFuelExhaustedError,
    WasmCheckerSandbox,
    WasmSandboxConfig,
)
from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore
from verifyci_v2.store.rabitq_index import RaBitQHybridIndex
from verifyci_v2.symbolic.egglog_engine import EgglogEquivalenceEngine
from verifyci_v2.symbolic.z3_prover import (
    Z3SymbolicProver,
    _evaluate_concrete_divergence,
    _z3_mod,
)


def test_p0_1_egglog_float_inconclusive_and_honest_verdict() -> None:
    egg = EgglogEquivalenceEngine()

    # Case A: Integer refactoring emits HEURISTIC_EQUIVALENT_CANDIDATE (never PROVEN_EQUIVALENT)
    base_int = "def add(a: int, b: int) -> int:\n    return a + b\n"
    head_int = "def add(a: int, b: int) -> int:\n    return b + a\n"
    f_b_int = lower_file_to_ussa("src/calc.py", base_int)[0]
    f_h_int = lower_file_to_ussa("src/calc.py", head_int)[0]
    res_int = egg.check_equivalence(f_b_int, f_h_int)
    assert res_int.is_equivalent is True
    assert res_int.verdict == "HEURISTIC_EQUIVALENT_CANDIDATE"

    # Case B: Floating point types or literals return is_equivalent=False and INCONCLUSIVE
    base_flt = "def calc(x: float) -> float:\n    return x + 1.5\n"
    head_flt = "def calc(x: float) -> float:\n    return 1.5 + x\n"
    f_b_flt = lower_file_to_ussa("src/calc.py", base_flt)[0]
    f_h_flt = lower_file_to_ussa("src/calc.py", head_flt)[0]
    res_flt = egg.check_equivalence(f_b_flt, f_h_flt)
    assert res_flt.is_equivalent is False
    assert res_flt.verdict == "INCONCLUSIVE"


def test_p0_2_z3_generates_real_distinct_counterexamples() -> None:
    prover = Z3SymbolicProver()

    # Case A: Call swap with parameters (sender, receiver) produces distinct witness without {10, 25}
    base_wire = """
def transfer(sender: int, receiver: int) -> int:
    return wire(sender, receiver)
"""
    head_wire = """
def transfer(sender: int, receiver: int) -> int:
    return wire(receiver, sender)
"""
    f_b = lower_file_to_ussa("src/bank.py", base_wire)[0]
    f_h = lower_file_to_ussa("src/bank.py", head_wire)[0]
    findings = prover.prove_function_diff(
        file_path="src/bank.py",
        base_source=base_wire,
        head_source=head_wire,
        func_base=f_b,
        func_head=f_h,
    )
    assert len(findings) == 1
    w = findings[0].witness
    assert w is not None
    if _z3_mod is not None:
        assert w.smt_status == "SAT"
        s_val = w.input_assignments["sender"]
        r_val = w.input_assignments["receiver"]
        assert s_val != r_val
        # Must not be hardcoded {10, 25}
        assert not (s_val == 10 and r_val == 25)
    else:
        assert w.smt_status == "SOLVER_UNAVAILABLE"
        assert w.input_assignments == {}

    # Case B: Guarded function where x > 100 must produce witness with x > 100 and concrete divergence
    base_guard = """
def guarded_wire(x: int, a: int, b: int) -> tuple[int, int]:
    if x > 100:
        return wire(a, b)
    return wire(0, 0)
"""
    head_guard = """
def guarded_wire(x: int, a: int, b: int) -> tuple[int, int]:
    if x > 100:
        return wire(b, a)
    return wire(0, 0)
"""
    f_bg = lower_file_to_ussa("src/guard.py", base_guard)[0]
    f_hg = lower_file_to_ussa("src/guard.py", head_guard)[0]
    findings_g = prover.prove_function_diff(
        file_path="src/guard.py",
        base_source=base_guard,
        head_source=head_guard,
        func_base=f_bg,
        func_head=f_hg,
    )
    assert len(findings_g) == 1
    wg = findings_g[0].witness
    assert wg is not None
    if _z3_mod is not None:
        assert wg.smt_status == "SAT"
        assert wg.input_assignments["x"] > 100
        assert wg.input_assignments["a"] != wg.input_assignments["b"]
        diverges = _evaluate_concrete_divergence(
            base_guard, head_guard, "guarded_wire", f_bg.parameters, wg.input_assignments
        )
        assert diverges is True


def test_p0_3_cegis_rejects_unverified_or_timed_out_repairs() -> None:
    prover = Z3SymbolicProver()

    base_src = """
def process(a: int, b: int) -> int:
    return wire(a, b)
"""
    head_bug = """
def process(a: int, b: int) -> int:
    return wire(b, a)
"""
    fb = lower_file_to_ussa("src/proc.py", base_src)[0]
    fh = lower_file_to_ussa("src/proc.py", head_bug)[0]
    finding = prover.prove_function_diff(
        file_path="src/proc.py",
        base_source=base_src,
        head_source=head_bug,
        func_base=fb,
        func_head=fh,
    )[0]

    # Case A: Synthesizer proposes patch deleting body or adding loop -> rejected
    class BadSynthesizer(GenerativeSynthesizerProtocol):
        def synthesize_patch(self, **kwargs: Any) -> str:
            # Trivial body deletion
            return "def process(a: int, b: int) -> int:\n    return 0\n"

    cegis_bad = CEGISAutoRepairEngine(synthesizer=BadSynthesizer(), prover=prover)
    repaired_bad = cegis_bad.repair_finding(
        file_path="src/proc.py",
        base_source=base_src,
        head_source=head_bug,
        finding=finding,
        target_qualified_name="src.proc.process",
    )
    assert repaired_bad.fixes == ()

    # Case B: Loop introduction -> rejected
    class LoopSynthesizer(GenerativeSynthesizerProtocol):
        def synthesize_patch(self, **kwargs: Any) -> str:
            return "def process(a: int, b: int) -> int:\n    for _ in range(1):\n        return wire(a, b)\n"

    cegis_loop = CEGISAutoRepairEngine(synthesizer=LoopSynthesizer(), prover=prover)
    repaired_loop = cegis_loop.repair_finding(
        file_path="src/proc.py",
        base_source=base_src,
        head_source=head_bug,
        finding=finding,
        target_qualified_name="src.proc.process",
    )
    assert repaired_loop.fixes == ()

    # Case C: Force timeout (timeout_ms=0 / 1) -> must not emit z3_verified_unsat=True
    timeout_prover = Z3SymbolicProver(timeout_ms=1)
    # Monkeypatch solve to simulate timeout
    def timeout_mock(*args: Any, **kwargs: Any) -> tuple[bool, str]:
        return False, "UNKNOWN"

    timeout_prover.prove_equivalence = timeout_mock  # type: ignore[assignment]
    cegis_timeout = CEGISAutoRepairEngine(prover=timeout_prover)
    repaired_to = cegis_timeout.repair_finding(
        file_path="src/proc.py",
        base_source=base_src,
        head_source=head_bug,
        finding=finding,
        target_qualified_name="src.proc.process",
    )
    assert repaired_to.fixes == ()


def test_p0_conformal_small_sample_fails_closed() -> None:
    judge = DeterministicJudgeAdapter()
    small_dataset = [({"code": "x = 1"}, "none")] * 2

    # Calibrating on n=2 (< 30) must produce is_calibrated = False
    profile = calibrate_judge_on_dataset(
        judge,
        small_dataset,
        options=("none", "defect"),
        alpha=0.02,
    )
    assert profile.is_calibrated is False

    # evaluate_with_conformal_gate must fail closed: always abstains and escalates
    decision = evaluate_with_conformal_gate(
        {"none": 0.99, "defect": 0.01},
        profile,
        safe_label="none",
    )
    assert decision.abstained is True
    assert decision.escalate_to_smt is True


def test_p1_grammar_validator_reports_honest_mode() -> None:
    judge_det = DeterministicJudgeAdapter()
    att_det = judge_det.attestation()
    assert att_det.validation_mode == "post_hoc_schema"

    judgment_det = judge_det.judge_boolean({"code": "a = 1"}, "Is this safe?")
    assert judgment_det.validation_mode == "post_hoc_schema"

    judge_remote = OpenAICompatibleJudgeAdapter()
    att_remote = judge_remote.attestation()
    assert att_remote.validation_mode == "post_hoc_schema"


def test_p0_stack_graphs_no_unrelated_short_symbol_collision() -> None:
    stitcher = StackGraphStitcher()
    stitcher.upsert_file("src/a.py", "def helper() -> int:\n    return 42\n")
    stitcher.upsert_file("src/b.py", "def caller() -> int:\n    return helper()\n")

    # In src/b.py, helper is not imported from src.a. Must resolve to ()
    resolved = stitcher.resolve_symbol("helper", from_module="src.b", import_map={})
    assert resolved == ()


def test_p0_salsa_semantic_body_change_invalidates_value_callers() -> None:
    engine = SalsaIncrementalEngine()
    engine.ingest_file(
        "src/tax.py",
        "def calc_tax(amount: int) -> int:\n    rate = 10\n    return amount * rate\n",
    )
    engine.ingest_file(
        "src/checkout.py",
        "from src.tax import calc_tax\ndef run_checkout(total: int) -> int:\n    return calc_tax(total)\n",
    )

    # Mutate calc_tax body while preserving interface (signature, taint, exceptions)
    plan = engine.ingest_file(
        "src/tax.py",
        "def calc_tax(amount: int) -> int:\n    rate = 15\n    return amount * rate\n",
    )
    assert any(e.status == "CUTOFF_INTERFACE_INVARIANT" for e in plan.evaluations)
    # Structural cutoff: run_checkout not in type_and_taint
    assert "src.checkout.run_checkout" not in plan.type_and_taint_callers_to_reverify
    # Semantic invalidation: run_checkout IS in semantic_value callers
    assert "src.checkout.run_checkout" in plan.semantic_value_callers_to_reverify


def test_p1_store_temporal_edge_isolation_and_explicit_backend() -> None:
    store = DuckDBCPGStore(backend="sqlite")
    assert store.active_backend == "sqlite"

    edge_ab = CPGEdge("e1", "node_a", "node_b", "CALLS")
    edge_ac = CPGEdge("e2", "node_a", "node_c", "CALLS")

    store.record_commit_snapshot("commit_v1", (), edges=[edge_ab])
    store.record_commit_snapshot("commit_v2", (), edges=[edge_ac])

    v1_edges = store.get_edges_as_of("commit_v1")
    v2_edges = store.get_edges_as_of("commit_v2")

    assert len(v1_edges) == 1
    assert v1_edges[0].dst_node_uid == "node_b"

    assert len(v2_edges) == 1
    assert v2_edges[0].dst_node_uid == "node_c"

    # Requesting missing duckdb backend raises RuntimeError if duckdb is not installed
    try:
        import duckdb  # noqa: F401
    except ImportError:
        with pytest.raises(RuntimeError):
            DuckDBCPGStore(backend="duckdb")


def test_p1_pyproject_discovers_all_test_suites() -> None:
    pyproject_path = Path("pyproject.toml")
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)
    testpaths = data.get("tool", {}).get("pytest", {}).get("ini_options", {}).get("testpaths", [])
    assert "tests" in testpaths or "tests/v2" in testpaths


def test_p0_4_wasm_sandbox_rejects_unconfined_python_by_default() -> None:
    sandbox = WasmCheckerSandbox(WasmSandboxConfig(require_wasm_isolation=True))

    # Case A: Python callable with require_wasm_isolation=True raises SandboxCapabilityViolationError
    with pytest.raises(SandboxCapabilityViolationError):
        sandbox.register_plugin("py_plugin", "def check(fns): return []", lambda _fns: [])

    # Case B: Real WAT module with infinite loop traps with SandboxFuelExhaustedError
    wat_infinite = '(module (func (export "run") (loop br 0)))'
    sandbox.register_plugin("infinite_wat", wat_infinite)
    with pytest.raises(SandboxFuelExhaustedError):
        sandbox.execute_plugin("infinite_wat", ())


def test_p0_5_ed25519_asymmetric_dsse_and_git_ref_persistence(tmp_path: Path) -> None:
    # Case A: InTotoDSSESigner() without explicit key raises TypeError
    with pytest.raises(TypeError):
        InTotoDSSESigner()  # type: ignore[call-arg]

    signer, pubkey = InTotoDSSESigner.generate_ephemeral()
    pred = InTotoVerificationPredicate(
        repo_id="test-repo",
        base_commit_sha="commit_000",
        head_commit_sha="commit_abc",
        ussa_merkle_root="root_123",
        gittuf_rsl_entry_hash="rsl_genesis",
        ai_provider="deterministic",
        conformal_profile_hash=None,
        findings=(),
    )
    env = signer.sign_predicate(pred)

    # Verifier with only public key verifies envelope
    verifier_signer, _ = InTotoDSSESigner.generate_ephemeral()
    assert verifier_signer.verify_envelope(env, public_key=pubkey) is True

    # Tampering with 1 byte of payload fails verification
    raw_payload = base64.b64decode(env.payload)
    tampered_payload = bytearray(raw_payload)
    tampered_payload[0] ^= 0xFF
    tampered_env = DSSEEnvelope(
        payloadType=env.payloadType,
        payload=base64.b64encode(tampered_payload).decode("ascii"),
        signatures=env.signatures,
    )
    assert verifier_signer.verify_envelope(tampered_env, public_key=pubkey) is False

    # Case B: GittufRSLLedger persistence across process restarts
    git_dir = tmp_path / ".git"
    git_dir.mkdir(parents=True, exist_ok=True)

    ledger_1 = GittufRSLLedger(repo_path=tmp_path)
    e1 = ledger_1.append_reference_entry(
        ref_name="refs/heads/main",
        target_commit_sha="commit_111",
        ussa_merkle_root="root_1",
        dsse_envelope=env,
    )
    e2 = ledger_1.append_reference_entry(
        ref_name="refs/heads/main",
        target_commit_sha="commit_222",
        ussa_merkle_root="root_2",
        dsse_envelope=env,
    )
    assert e2.parent_entry_id == e1.entry_id

    # Restart: create new instance with same repo_path
    ledger_2 = GittufRSLLedger(repo_path=tmp_path)
    assert len(ledger_2._rsl_chain) == 2
    assert ledger_2.verify_rsl_lineage(expected_head_commit="commit_222") is True
    with pytest.raises(RSLTamperDetectedError):
        ledger_2.verify_rsl_lineage(expected_head_commit="commit_111")


def test_p1_retrieval_reports_scan_mode_and_memory_bytes() -> None:
    index = RaBitQHybridIndex(retain_exact_vectors=True)
    index.upsert_document("uid1", "mod.fn1", "def fn1(): pass")
    stats = index.search("fn1", top_k=1)

    assert stats.scan_mode == "linear_bitwise_scan"
    assert stats.quantized_bytes > 0
    assert stats.exact_float_bytes > 0

    index_no_exact = RaBitQHybridIndex(retain_exact_vectors=False)
    index_no_exact.upsert_document("uid2", "mod.fn2", "def fn2(): pass")
    stats_no_exact = index_no_exact.search("fn2", top_k=1)
    assert stats_no_exact.exact_float_bytes == 0
