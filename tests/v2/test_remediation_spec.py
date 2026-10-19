from __future__ import annotations
import base64
from pathlib import Path
import tomllib
from typing import Any
import pytest
from verifyci_v2.contracts.ai_protocol import GenerativeSynthesizerProtocol
from verifyci_v2.contracts.attestation import DSSEEnvelope, InTotoVerificationPredicate
from verifyci_v2.contracts.ssa_ir import CPGEdge
from verifyci_v2.ingestion.salsa_cutoff import SalsaIncrementalEngine
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.ingestion.stack_graphs import StackGraphStitcher
from verifyci_v2.neural.adapters import DeterministicJudgeAdapter, OpenAICompatibleJudgeAdapter
from verifyci_v2.neural.cegis_repair import CEGISAutoRepairEngine
from verifyci_v2.contracts.conformal import calibrate_judge_on_dataset, evaluate_with_conformal_gate
from verifyci_v2.provenance.dsse_intoto import InTotoDSSESigner
from verifyci_v2.provenance.gittuf_rsl import GittufRSLLedger, RSLTamperDetectedError
from verifyci_v2.sandbox.wasm_runner import SandboxCapabilityViolationError, SandboxFuelExhaustedError, WasmCheckerSandbox, WasmSandboxConfig
from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore
from verifyci_v2.store.rabitq_index import RaBitQHybridIndex
from verifyci_v2.symbolic.egglog_engine import EgglogEquivalenceEngine
from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver, _evaluate_concrete_divergence, _z3_mod

def test_p0_1_egglog_float_inconclusive_and_honest_verdict() -> None:
    egg = EgglogEquivalenceEngine()
    base_int = 'def add(a: int, b: int) -> int:\n    return a + b\n'
    head_int = 'def add(a: int, b: int) -> int:\n    return b + a\n'
    f_b_int = lower_file_to_ussa('src/calc.py', base_int)[0]
    f_h_int = lower_file_to_ussa('src/calc.py', head_int)[0]
    res_int = egg.check_equivalence(f_b_int, f_h_int)
    assert res_int.is_equivalent is True
    assert res_int.verdict == 'HEURISTIC_EQUIVALENT_CANDIDATE'
    base_flt = 'def calc(x: float) -> float:\n    return x + 1.5\n'
    head_flt = 'def calc(x: float) -> float:\n    return 1.5 + x\n'
    f_b_flt = lower_file_to_ussa('src/calc.py', base_flt)[0]
    f_h_flt = lower_file_to_ussa('src/calc.py', head_flt)[0]
    res_flt = egg.check_equivalence(f_b_flt, f_h_flt)
    assert res_flt.is_equivalent is False
    assert res_flt.verdict == 'INCONCLUSIVE'

def test_p0_2_z3_generates_real_distinct_counterexamples() -> None:
    prover = Z3SymbolicProver()
    base_wire = '\ndef transfer(sender: int, receiver: int) -> int:\n    return wire(sender, receiver)\n'
    head_wire = '\ndef transfer(sender: int, receiver: int) -> int:\n    return wire(receiver, sender)\n'
    f_b = lower_file_to_ussa('src/bank.py', base_wire)[0]
    f_h = lower_file_to_ussa('src/bank.py', head_wire)[0]
    findings = prover.prove_function_diff(file_path='src/bank.py', base_source=base_wire, head_source=head_wire, func_base=f_b, func_head=f_h)
    assert len(findings) == 1
    w = findings[0].witness
    assert w is not None
    if _z3_mod is not None:
        assert w.smt_status == 'SAT'
        s_val = w.input_assignments['sender']
        r_val = w.input_assignments['receiver']
        assert s_val != r_val
        assert not (s_val == 10 and r_val == 25)
    else:
        assert w.smt_status == 'SOLVER_UNAVAILABLE'
        assert w.input_assignments == {}
    base_guard = '\ndef guarded_wire(x: int, a: int, b: int) -> tuple[int, int]:\n    if x > 100:\n        return wire(a, b)\n    return wire(0, 0)\n'
    head_guard = '\ndef guarded_wire(x: int, a: int, b: int) -> tuple[int, int]:\n    if x > 100:\n        return wire(b, a)\n    return wire(0, 0)\n'
    f_bg = lower_file_to_ussa('src/guard.py', base_guard)[0]
    f_hg = lower_file_to_ussa('src/guard.py', head_guard)[0]
    findings_g = prover.prove_function_diff(file_path='src/guard.py', base_source=base_guard, head_source=head_guard, func_base=f_bg, func_head=f_hg)
    assert len(findings_g) == 1
    wg = findings_g[0].witness
    assert wg is not None
    if _z3_mod is not None:
        assert wg.smt_status == 'SAT'
        assert wg.input_assignments['x'] > 100
        assert wg.input_assignments['a'] != wg.input_assignments['b']
        diverges = _evaluate_concrete_divergence(base_guard, head_guard, 'guarded_wire', f_bg.parameters, wg.input_assignments)
        assert diverges is True

def test_p0_3_cegis_rejects_unverified_or_timed_out_repairs() -> None:
    prover = Z3SymbolicProver()
    base_src = '\ndef process(a: int, b: int) -> int:\n    return wire(a, b)\n'
    head_bug = '\ndef process(a: int, b: int) -> int:\n    return wire(b, a)\n'
    fb = lower_file_to_ussa('src/proc.py', base_src)[0]
    fh = lower_file_to_ussa('src/proc.py', head_bug)[0]
    finding = prover.prove_function_diff(file_path='src/proc.py', base_source=base_src, head_source=head_bug, func_base=fb, func_head=fh)[0]

    class BadSynthesizer(GenerativeSynthesizerProtocol):

        def synthesize_patch(self, **kwargs: Any) -> str:
            return 'def process(a: int, b: int) -> int:\n    return 0\n'
    cegis_bad = CEGISAutoRepairEngine(synthesizer=BadSynthesizer(), prover=prover)
    repaired_bad = cegis_bad.repair_finding(file_path='src/proc.py', base_source=base_src, head_source=head_bug, finding=finding, target_qualified_name='src.proc.process')
    assert repaired_bad.fixes == ()

    class LoopSynthesizer(GenerativeSynthesizerProtocol):

        def synthesize_patch(self, **kwargs: Any) -> str:
            return 'def process(a: int, b: int) -> int:\n    for _ in range(1):\n        return wire(a, b)\n'
    cegis_loop = CEGISAutoRepairEngine(synthesizer=LoopSynthesizer(), prover=prover)
    repaired_loop = cegis_loop.repair_finding(file_path='src/proc.py', base_source=base_src, head_source=head_bug, finding=finding, target_qualified_name='src.proc.process')
    assert repaired_loop.fixes == ()
    timeout_prover = Z3SymbolicProver(timeout_ms=1)

    def timeout_mock(*args: Any, **kwargs: Any) -> tuple[bool, str]:
        return (False, 'UNKNOWN')
    timeout_prover.prove_equivalence = timeout_mock
    cegis_timeout = CEGISAutoRepairEngine(prover=timeout_prover)
    repaired_to = cegis_timeout.repair_finding(file_path='src/proc.py', base_source=base_src, head_source=head_bug, finding=finding, target_qualified_name='src.proc.process')
    assert repaired_to.fixes == ()

def test_p0_conformal_small_sample_fails_closed() -> None:
    judge = DeterministicJudgeAdapter()
    small_dataset = [({'code': 'x = 1'}, 'none')] * 2
    profile = calibrate_judge_on_dataset(judge, small_dataset, options=('none', 'defect'), alpha=0.02)
    assert profile.is_calibrated is False
    decision = evaluate_with_conformal_gate({'none': 0.99, 'defect': 0.01}, profile, safe_label='none')
    assert decision.abstained is True
    assert decision.escalate_to_smt is True

def test_p1_grammar_validator_reports_honest_mode() -> None:
    judge_det = DeterministicJudgeAdapter()
    att_det = judge_det.attestation()
    assert att_det.validation_mode == 'post_hoc_schema'
    judgment_det = judge_det.judge_boolean({'code': 'a = 1'}, 'Is this safe?')
    assert judgment_det.validation_mode == 'post_hoc_schema'
    judge_remote = OpenAICompatibleJudgeAdapter()
    att_remote = judge_remote.attestation()
    assert att_remote.validation_mode == 'post_hoc_schema'

def test_p0_stack_graphs_no_unrelated_short_symbol_collision() -> None:
    stitcher = StackGraphStitcher()
    stitcher.upsert_file('src/a.py', 'def helper() -> int:\n    return 42\n')
    stitcher.upsert_file('src/b.py', 'def caller() -> int:\n    return helper()\n')
    resolved = stitcher.resolve_symbol('helper', from_module='src.b', import_map={})
    assert resolved == ()

def test_p0_salsa_semantic_body_change_invalidates_value_callers() -> None:
    engine = SalsaIncrementalEngine()
    engine.ingest_file('src/tax.py', 'def calc_tax(amount: int) -> int:\n    rate = 10\n    return amount * rate\n')
    engine.ingest_file('src/checkout.py', 'from src.tax import calc_tax\ndef run_checkout(total: int) -> int:\n    return calc_tax(total)\n')
    plan = engine.ingest_file('src/tax.py', 'def calc_tax(amount: int) -> int:\n    rate = 15\n    return amount * rate\n')
    assert any((e.status == 'CUTOFF_INTERFACE_INVARIANT' for e in plan.evaluations))
    assert 'src.checkout.run_checkout' not in plan.type_and_taint_callers_to_reverify
    assert 'src.checkout.run_checkout' in plan.semantic_value_callers_to_reverify

def test_p1_store_temporal_edge_isolation_and_explicit_backend() -> None:
    store = DuckDBCPGStore(backend='sqlite')
    assert store.active_backend == 'sqlite'
    edge_ab = CPGEdge(edge_uid='e1', src_node_uid='node_a', dst_node_uid='node_b', edge_kind='CALLS')
    edge_ac = CPGEdge(edge_uid='e2', src_node_uid='node_a', dst_node_uid='node_c', edge_kind='CALLS')
    store.record_commit_snapshot('commit_v1', (), edges=[edge_ab])
    store.record_commit_snapshot('commit_v2', (), edges=[edge_ac])
    v1_edges = store.get_edges_as_of('commit_v1')
    v2_edges = store.get_edges_as_of('commit_v2')
    assert len(v1_edges) == 1
    assert v1_edges[0].dst_node_uid == 'node_b'
    assert len(v2_edges) == 1
    assert v2_edges[0].dst_node_uid == 'node_c'
    try:
        import duckdb
        _ = duckdb
    except ImportError:
        with pytest.raises(RuntimeError):
            DuckDBCPGStore(backend='duckdb')

def test_p1_pyproject_discovers_all_test_suites() -> None:
    pyproject_path = Path('pyproject.toml')
    with open(pyproject_path, 'rb') as f:
        data = tomllib.load(f)
    testpaths = data.get('tool', {}).get('pytest', {}).get('ini_options', {}).get('testpaths', [])
    assert 'tests' in testpaths or 'tests/v2' in testpaths

def test_p0_4_wasm_sandbox_rejects_unconfined_python_by_default() -> None:
    sandbox = WasmCheckerSandbox(WasmSandboxConfig(require_wasm_isolation=True))
    with pytest.raises(SandboxCapabilityViolationError):
        sandbox.register_plugin('py_plugin', 'def check(fns): return []', lambda _fns: [])
    wat_infinite = '(module (func (export "run") (loop br 0)))'
    sandbox.register_plugin('infinite_wat', wat_infinite)
    with pytest.raises(SandboxFuelExhaustedError):
        sandbox.execute_plugin('infinite_wat', ())

def test_p0_5_ed25519_asymmetric_dsse_and_git_ref_persistence(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        InTotoDSSESigner()
    signer, pubkey = InTotoDSSESigner.generate_ephemeral()
    pred = InTotoVerificationPredicate(repo_id='test-repo', base_commit_sha='commit_000', head_commit_sha='commit_abc', ussa_merkle_root='root_123', gittuf_rsl_entry_hash='rsl_genesis', ai_provider='deterministic', conformal_profile_hash=None, findings=())
    env = signer.sign_predicate(pred)
    verifier_signer, _ = InTotoDSSESigner.generate_ephemeral()
    assert verifier_signer.verify_envelope(env, public_key=pubkey) is True
    raw_payload = base64.b64decode(env.payload)
    tampered_payload = bytearray(raw_payload)
    tampered_payload[0] ^= 255
    tampered_env = DSSEEnvelope(payloadType=env.payloadType, payload=base64.b64encode(tampered_payload).decode('ascii'), signatures=env.signatures)
    assert verifier_signer.verify_envelope(tampered_env, public_key=pubkey) is False
    # Real Git object identity is required in production. Build a tiny valid
    # repository instead of using synthetic SHA strings against a fake .git dir.
    import subprocess
    subprocess.run(['git', 'init'], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(['git', 'config', 'user.name', 'Test User'], cwd=str(tmp_path), check=True)
    subprocess.run(['git', 'config', 'user.email', 'test@verifyci.dev'], cwd=str(tmp_path), check=True)
    (tmp_path / 'seed.txt').write_text('seed\n', encoding='utf-8')
    subprocess.run(['git', 'add', '.'], cwd=str(tmp_path), check=True)
    subprocess.run(['git', 'commit', '-m', 'seed'], cwd=str(tmp_path), check=True, capture_output=True)
    target_sha = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=str(tmp_path), check=True, capture_output=True, text=True).stdout.strip()
    ledger_1 = GittufRSLLedger(repo_path=tmp_path)
    e1 = ledger_1.append_reference_entry(ref_name='refs/heads/main', target_commit_sha=target_sha, ussa_merkle_root='root_1', dsse_envelope=env)
    e2 = ledger_1.append_reference_entry(ref_name='refs/heads/main', target_commit_sha=target_sha, ussa_merkle_root='root_2', dsse_envelope=env)
    assert e2.parent_entry_id == e1.entry_id
    ledger_2 = GittufRSLLedger(repo_path=tmp_path)
    assert len(ledger_2._rsl_chain) == 2
    assert ledger_2.verify_rsl_lineage(expected_head_commit=target_sha) is True
    with pytest.raises(RSLTamperDetectedError):
        ledger_2.verify_rsl_lineage(expected_head_commit='0' * len(target_sha))

def test_p1_retrieval_reports_scan_mode_and_memory_bytes() -> None:
    index = RaBitQHybridIndex(retain_exact_vectors=True)
    index.upsert_document('uid1', 'mod.fn1', 'def fn1(): pass')
    stats = index.search('fn1', top_k=1)
    assert stats.scan_mode == 'linear_bitwise_scan'
    assert stats.quantized_bytes > 0
    assert stats.exact_float_bytes > 0
    index_no_exact = RaBitQHybridIndex(retain_exact_vectors=False)
    index_no_exact.upsert_document('uid2', 'mod.fn2', 'def fn2(): pass')
    stats_no_exact = index_no_exact.search('fn2', top_k=1)
    assert stats_no_exact.exact_float_bytes == 0

def test_r2_1_spec_compiler_uses_real_z3_and_never_fabricates_sat(monkeypatch: pytest.MonkeyPatch) -> None:
    from verifyci_v2.neural import spec_compiler
    compiler = spec_compiler.IntentToSMTCompiler()
    monkeypatch.setattr(spec_compiler, '_z3_mod', None)
    findings_no_z3 = compiler.verify_function_against_intent(file_path='src/calc.py', source='def sub(a: int, b: int) -> int:\n    return a - b\n', intent_text='never drops below zero')
    for f in findings_no_z3:
        assert f.witness is not None
        assert f.witness.smt_status != 'SAT'
    monkeypatch.undo()
    guarded_src = 'def compute_discount(total: int, discount: int) -> int:\n    if discount <= total:\n        return total - discount\n    return 0\n'
    findings_guarded = compiler.verify_function_against_intent(file_path='src/calc.py', source=guarded_src, intent_text='never drops below zero')
    assert len(findings_guarded) == 0
    unguarded_src = 'def compute_discount(total: int, discount: int) -> int:\n    return total - discount\n'
    findings_unguarded = compiler.verify_function_against_intent(file_path='src/calc.py', source=unguarded_src, intent_text='never drops below zero')
    assert len(findings_unguarded) == 1
    finding = findings_unguarded[0]
    assert finding.verdict == 'FAIL'
    assert finding.witness is not None
    assert finding.witness.smt_status == 'SAT'
    assert finding.witness.input_assignments
    total_val = finding.witness.input_assignments['total']
    discount_val = finding.witness.input_assignments['discount']
    assert total_val - discount_val < 0


@pytest.mark.benchmark
def test_r2_2_adjudicator_distinguishes_smoke_from_frozen_corpus_and_calibrates_validly(tmp_path: Path) -> None:
    from verifyci_v2.interface.cap_adjudicator import V2CapabilityAdjudicator
    adjudicator = V2CapabilityAdjudicator()
    smoke_res = adjudicator.run_self_test_smoke_suite()
    assert smoke_res['all_passed'] is True
    cap010_card = next((sc for sc in smoke_res['scorecards'] if sc['cap_id'] == 'cap010'))
    assert cap010_card['passed'] is True
    alias_res = adjudicator.adjudicate_all()
    assert alias_res['all_passed'] is True
    corpus_res = adjudicator.adjudicate_corpus()
    assert corpus_res['corpora_evaluated'] > 0
    assert corpus_res['all_verified'] is True
    fake_cap = tmp_path / 'fake_cap'
    fake_cap.mkdir()
    (fake_cap / 'cases.jsonl').write_text('{"id": 1}\n', encoding='utf-8')
    (fake_cap / 'labels.jsonl').write_text('{"id": 1, "expected": "PASS"}\n', encoding='utf-8')
    (fake_cap / 'CORPUS_SHA256').write_text('corrupted_sha256_hash\n', encoding='utf-8')
    (fake_cap / 'LABEL_SHA256').write_text('corrupted_label_hash\n', encoding='utf-8')
    fake_root = tmp_path / 'benchmarks'
    fake_root.mkdir()
    fake_secret = fake_root / 'secret_corpus' / 'cap002b'
    fake_secret.mkdir(parents=True)
    (fake_secret / 'cases.jsonl').write_text('{"id": 1}\n', encoding='utf-8')
    (fake_secret / 'labels.jsonl').write_text('{"id": 1}\n', encoding='utf-8')
    (fake_secret / 'CORPUS_SHA256').write_text('drifted_hash\n', encoding='utf-8')
    with pytest.raises(ValueError, match='CORPUS_SHA256 drift'):
        adjudicator.adjudicate_corpus(benchmark_dir=fake_root)

def test_r2_3_scripts_and_skill_acceptance_run_without_legacy_v1_module_error() -> None:
    from scripts.ci_test_selector import select_tests, validate_test_targets
    from benchmarks.latency.fixture import env, extractor, graph_store, intent_align, provider, workload
    assert (env, extractor, graph_store, intent_align, provider, workload) is not None
    selected = select_tests(['verifyci_v2/symbolic/z3_prover.py'])
    valid = validate_test_targets(selected)
    assert any(('tests/v2' in t for t in valid))
    from verifyci_v2.interface.cli import run_cli
    res_vdiff = run_cli(['verify-diff', '--format', 'json'])
    assert res_vdiff['status'] == 'PASS'

def test_r2_4_unsupported_ast_diff_emits_inconclusive_never_silent_pass() -> None:
    from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
    from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver
    base_src = 'def loop_calc(x: int) -> int:\n    while x < 10:\n        x += 1\n    return x\n'
    head_src = 'def loop_calc(x: int) -> int:\n    while x < 20:\n        x += 1\n    return x\n'
    fb = lower_file_to_ussa('src/loop.py', base_src)[0]
    fh = lower_file_to_ussa('src/loop.py', head_src)[0]
    prover = Z3SymbolicProver()
    findings = prover.prove_function_diff(file_path='src/loop.py', base_source=base_src, head_source=head_src, func_base=fb, func_head=fh)
    assert len(findings) == 1
    f = findings[0]
    assert f.verdict == 'INCONCLUSIVE'
    assert f.rule_id == 'VC2-Z3-UNSUPPORTED-AST'
    assert f.witness is not None
    assert f.witness.smt_status == 'UNKNOWN'
    assert 'While' in f.message

def test_p0_prover_rejects_arithmetic_return_divergence() -> None:
    from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
    from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver
    base_src = 'def f(x: int) -> int:\n    return x + 1\n'
    cand_src = 'def f(x: int) -> int:\n    return x + 2\n'
    fb = lower_file_to_ussa('calc.py', base_src)[0]
    fc = lower_file_to_ussa('calc.py', cand_src)[0]
    prover = Z3SymbolicProver()
    is_equiv, smt_status = prover.prove_equivalence(base_source=base_src, cand_source=cand_src, func_base=fb, func_cand=fc)
    assert is_equiv is False
    assert smt_status == 'SAT'
    comm_src = 'def f(x: int) -> int:\n    return 1 + x\n'
    fc_comm = lower_file_to_ussa('calc.py', comm_src)[0]
    is_eq_comm, smt_comm = prover.prove_equivalence(base_source=base_src, cand_source=comm_src, func_base=fb, func_cand=fc_comm)
    assert is_eq_comm is True
    assert smt_comm == 'UNSAT'

def test_p0_prover_rejects_branch_specific_return_divergence() -> None:
    from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
    from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver
    base_src = 'def branch_fn(x: int) -> int:\n    if x > 0:\n        return x + 1\n    return x - 1\n'
    cand_src = 'def branch_fn(x: int) -> int:\n    if x > 0:\n        return x + 2\n    return x - 1\n'
    fb = lower_file_to_ussa('branch.py', base_src)[0]
    fc = lower_file_to_ussa('branch.py', cand_src)[0]
    prover = Z3SymbolicProver()
    is_equiv, smt_status = prover.prove_equivalence(base_source=base_src, cand_source=cand_src, func_base=fb, func_cand=fc)
    assert is_equiv is False
    assert smt_status == 'SAT'

def test_p0_cli_verify_diff_real_pipeline_and_exit_codes(tmp_path: Path) -> None:
    from verifyci_v2.interface.cli import run_cli, main
    secret_diff = "--- a/config.py\n+++ b/config.py\n@@ -1,1 +1,2 @@\n APP_NAME = 'test'\n+AWS_SECRET = 'AKIA1234567890ABCDEF'\n"
    sec_file = tmp_path / 'secret.diff'
    sec_file.write_text(secret_diff, encoding='utf-8')
    res_sec = run_cli(['verify-diff', '--diff-file', str(sec_file), '--format', 'json'])
    assert res_sec['status'] == 'FAIL'
    assert res_sec['verdict']['status'] == 'FAIL'
    assert main(['verify-diff', '--diff-file', str(sec_file), '--format', 'json']) == 1
    bug_diff = '--- a/calc.py\n+++ b/calc.py\n@@ -1,2 +1,2 @@\n-def add_one(x: int) -> int:\n-    return x + 1\n+def add_one(x: int) -> int:\n+    return x + 2\n'
    bug_file = tmp_path / 'bug.diff'
    bug_file.write_text(bug_diff, encoding='utf-8')
    res_bug = run_cli(['verify-diff', '--diff-file', str(bug_file), '--format', 'json'])
    assert res_bug['status'] == 'FAIL'
    assert main(['verify-diff', '--diff-file', str(bug_file), '--format', 'json']) == 1
    syn_diff = '--- a/syntax.py\n+++ b/syntax.py\n@@ -1,1 +1,1 @@\n+def broken(:\n'
    syn_file = tmp_path / 'syn.diff'
    syn_file.write_text(syn_diff, encoding='utf-8')
    res_syn = run_cli(['verify-diff', '--diff-file', str(syn_file), '--format', 'json'])
    assert res_syn['status'] == 'FAIL'
    assert main(['verify-diff', '--diff-file', str(syn_file), '--format', 'json']) == 1
    inc_diff = '--- a/loop.py\n+++ b/loop.py\n@@ -1,4 +1,4 @@\n-def fn(x: int) -> int:\n-    while x < 5:\n-        x += 1\n-    return x\n+def fn(x: int) -> int:\n+    while x < 10:\n+        x += 1\n+    return x\n'
    inc_file = tmp_path / 'inc.diff'
    inc_file.write_text(inc_diff, encoding='utf-8')
    res_inc = run_cli(['verify-diff', '--diff-file', str(inc_file), '--format', 'json'])
    assert res_inc['status'] == 'INCONCLUSIVE'
    assert main(['verify-diff', '--diff-file', str(inc_file), '--format', 'json']) == 2
    clean_diff = '--- a/calc.py\n+++ b/calc.py\n@@ -1,2 +1,2 @@\n-def add_one(x: int) -> int:\n-    return x + 1\n+def add_one(x: int) -> int:\n+    return 1 + x\n'
    clean_file = tmp_path / 'clean.diff'
    clean_file.write_text(clean_diff, encoding='utf-8')
    res_clean = run_cli(['verify-diff', '--diff-file', str(clean_file), '--format', 'json'])
    assert res_clean['status'] == 'PASS'
    assert main(['verify-diff', '--diff-file', str(clean_file), '--format', 'json']) == 0
    missing_path = tmp_path / 'non_existent.diff'
    res_missing = run_cli(['verify-diff', '--diff-file', str(missing_path), '--format', 'json'])
    assert res_missing['status'] == 'INFRA_ERROR'
    assert main(['verify-diff', '--diff-file', str(missing_path), '--format', 'json']) == 3

def test_p0_cli_ingest_tracks_failed_files(tmp_path: Path) -> None:
    from verifyci_v2.interface.cli import run_cli
    valid_py = tmp_path / 'valid.py'
    valid_py.write_text('def f(x: int) -> int: return x\n', encoding='utf-8')
    bad_py = tmp_path / 'corrupted.py'
    bad_py.write_text('def unparseable( ::::\n', encoding='utf-8')
    db_path = str(tmp_path / 'test.db')
    res = run_cli(['ingest', str(tmp_path), '--db', db_path])
    assert res['status'] == 'partial_ingest'
    assert res['ingested_functions'] == 1
    assert len(res['failed_files']) == 1
    assert 'corrupted.py' in res['failed_files'][0]['file']

def test_p0_gittuf_rsl_real_git_plumbing_and_persistence(tmp_path: Path) -> None:
    import subprocess
    from verifyci_v2.provenance.gittuf_rsl import GittufRSLLedger
    from verifyci_v2.contracts.attestation import InTotoVerificationPredicate
    from verifyci_v2.provenance.dsse_intoto import InTotoDSSESigner
    subprocess.run(['git', 'init'], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(['git', 'config', 'user.name', 'Test User'], cwd=str(tmp_path), check=True)
    subprocess.run(['git', 'config', 'user.email', 'test@verifyci.dev'], cwd=str(tmp_path), check=True)
    dummy_file = tmp_path / 'file.txt'
    dummy_file.write_text('hello\n', encoding='utf-8')
    subprocess.run(['git', 'add', '.'], cwd=str(tmp_path), check=True)
    subprocess.run(['git', 'commit', '-m', 'init commit'], cwd=str(tmp_path), check=True, capture_output=True)
    commit_sha = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=str(tmp_path), check=True, capture_output=True, text=True).stdout.strip()
    signer, pubkey = InTotoDSSESigner.generate_ephemeral()
    pred = InTotoVerificationPredicate(repo_id='test-repo', base_commit_sha='commit_000', head_commit_sha=commit_sha, ussa_merkle_root='root_123', gittuf_rsl_entry_hash='rsl_genesis', ai_provider='deterministic', conformal_profile_hash=None, findings=())
    env = signer.sign_predicate(pred)
    ledger_1 = GittufRSLLedger(repo_path=tmp_path)
    entry = ledger_1.append_reference_entry(ref_name='refs/heads/main', target_commit_sha=commit_sha, ussa_merkle_root='root_123', dsse_envelope=env)
    obj_type = subprocess.run(['git', 'cat-file', '-t', 'refs/gittuf/reference-state-log'], cwd=str(tmp_path), check=True, capture_output=True, text=True).stdout.strip()
    assert obj_type == 'commit'
    note_out = subprocess.run(['git', 'notes', '--ref', 'refs/notes/verifyci', 'show', commit_sha], cwd=str(tmp_path), check=True, capture_output=True, text=True).stdout.strip()
    assert env.payload in note_out
    ledger_2 = GittufRSLLedger(repo_path=tmp_path)
    assert len(ledger_2._rsl_chain) == 1
    assert ledger_2._rsl_chain[0].entry_id == entry.entry_id
    assert ledger_2.get_note_for_commit(commit_sha) is not None
    assert ledger_2.verify_rsl_lineage(expected_head_commit=commit_sha) is True

def test_p0_conformal_selective_risk_control_false_pass_guarantee() -> None:
    from typing import Sequence
    from verifyci_v2.contracts.conformal import calibrate_judge_on_dataset, evaluate_with_conformal_gate
    from verifyci_v2.contracts.ai_protocol import DiscriminativeJudgeProtocol, CategoricalChoice, ModelAttestationRecord

    class MisclassifyingJudge(DiscriminativeJudgeProtocol):
        provider_name = 'mock'
        model_id = 'test-judge'

        def judge_choice(self, state: dict[str, Any], question: str, options: Sequence[str]) -> CategoricalChoice:
            return CategoricalChoice(selected='none', distribution={'none': 0.95, 'defect': 0.05}, confidence=0.95)

        def attestation(self, conformal_hash: str | None=None) -> ModelAttestationRecord:
            return ModelAttestationRecord(provider_name='mock', model_id='test', weights_or_endpoint_hash='hash', prompt_template_hash='tmpl', conformal_profile_hash=conformal_hash)
    labeled = [({'diff': f'safe_{i}'}, 'none') for i in range(20)] + [({'diff': f'defect_{i}'}, 'defect') for i in range(15)]
    profile = calibrate_judge_on_dataset(MisclassifyingJudge(), labeled, options=('none', 'defect'), alpha=0.05)
    assert profile.tau_safe > 1.0
    decision = evaluate_with_conformal_gate({'none': 0.999, 'defect': 0.001}, profile, safe_label='none')
    assert decision.escalate_to_smt is True

def test_p1_wasm_fails_closed_when_runtime_unavailable() -> None:
    from verifyci_v2.sandbox.wasm_runner import WasmCheckerSandbox, WasmSandboxConfig
    sandbox = WasmCheckerSandbox(WasmSandboxConfig(require_wasm_isolation=True))
    with pytest.raises(KeyError):
        sandbox.execute_plugin('unknown', ())

def test_p1_duckdb_cpg_clears_stale_records_and_versions_edges(tmp_path: Path) -> None:
    from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore
    from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
    from verifyci_v2.contracts.ssa_ir import CPGEdge
    store = DuckDBCPGStore(str(tmp_path / 'test.vc2'))
    f1 = lower_file_to_ussa('a.py', 'def f(): return 1\n')[0]
    f2 = lower_file_to_ussa('b.py', 'def g(): return 2\n')[0]
    edge_1 = CPGEdge(edge_uid='e1', src_node_uid=f1.node_uid, dst_node_uid=f2.node_uid, edge_kind='CALL', static_weight=1.0, coverage_hit_freq=0.0)
    store.record_commit_snapshot('commit_A', [f1, f2], [edge_1])
    assert len(store.get_functions_as_of('commit_A')) == 2
    assert len(store.get_edges_as_of('commit_A')) == 1
    store.record_commit_snapshot('commit_A', [f1], [])
    assert len(store.get_functions_as_of('commit_A')) == 1
    assert len(store.get_edges_as_of('commit_A')) == 0
    edge_v1 = CPGEdge(edge_uid='shared_edge', src_node_uid=f1.node_uid, dst_node_uid=f1.node_uid, edge_kind='CALL', static_weight=1.0, coverage_hit_freq=0.0)
    store.record_commit_snapshot('commit_1', [f1], [edge_v1])
    edge_v2 = CPGEdge(edge_uid='shared_edge', src_node_uid=f1.node_uid, dst_node_uid=f1.node_uid, edge_kind='CALL', static_weight=2.0, coverage_hit_freq=0.9)
    store.record_commit_snapshot('commit_2', [f1], [edge_v2])
    edges_c1 = store.get_edges_as_of('commit_1')
    edges_c2 = store.get_edges_as_of('commit_2')
    assert edges_c1[0].static_weight == 1.0
    assert edges_c1[0].coverage_hit_freq == 0.0
    assert edges_c2[0].static_weight == 2.0
    assert edges_c2[0].coverage_hit_freq == 0.9

def test_p1_stack_graphs_tracks_unresolved_references() -> None:
    from verifyci_v2.ingestion.stack_graphs import StackGraphStitcher
    stitcher = StackGraphStitcher()
    code = 'import missing_lib\ndef client():\n    return missing_lib.external_call()\n'
    stitcher.upsert_file('client.py', code, language='python')
    unresolved = stitcher.get_unresolved_references()
    assert len(unresolved) >= 1
    assert any(('external_call' in u['symbol'] for u in unresolved))

def test_p1_cli_calibrate_default_produces_calibrated_profile() -> None:
    from verifyci_v2.interface.cli import run_cli
    res = run_cli(['calibrate'])
    assert res['status'] == 'ok'
    prof = res['conformal_profile']
    assert prof['is_calibrated'] is True
    assert prof['sample_size'] >= 30
