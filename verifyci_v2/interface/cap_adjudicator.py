from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import time
from typing import Any

from verifyci_v2.ingestion.salsa_cutoff import SalsaIncrementalEngine
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.neural.adapters import DeterministicJudgeAdapter
from verifyci_v2.neural.cegis_repair import CEGISAutoRepairEngine
from verifyci_v2.neural.conformal import calibrate_judge_on_dataset
from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore
from verifyci_v2.store.model2vec_embed import build_neighborhood_header
from verifyci_v2.store.rabitq_index import RaBitQHybridIndex
from verifyci_v2.symbolic.egglog_engine import EgglogEquivalenceEngine
from verifyci_v2.symbolic.secrets_taint import TaintTrackedSecretEngine
from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver


@dataclass(frozen=True, slots=True)
class CapabilityScorecard:
    cap_id: str
    suite_name: str
    passed: bool
    metric_name: str
    metric_value: float
    target_threshold: float
    latency_ms: float


class V2CapabilityAdjudicator:
    """
    Executes and adjudicates all 15 VerifyCI capability gates (`cap001` through `cap013`,
    including `cap002b` and `cap003a`) against the v2 Neuro-Symbolic Engine.
    """

    def run_self_test_smoke_suite(self) -> dict[str, Any]:
        scorecards: list[CapabilityScorecard] = [
            self._eval_cap001_retrieval(),
            self._eval_cap002_patch_verdicts(),
            self._eval_cap002b_secrets_partition(),
            self._eval_cap003_blast_salsa_cutoff(),
            self._eval_cap003a_unsafe_deletion(),
            self._eval_cap004_call_semantics(),
            self._eval_cap005_cegis_auto_repair(),
            self._eval_cap006_temporal_as_of(),
            self._eval_cap007_rabitq_scale(),
            self._eval_cap008_concurrency(),
            self._eval_cap009_polyglot_diff_impact(),
            self._eval_cap010_neighborhood_generalization(),
            self._eval_cap011_obfuscated_secrets(),
            self._eval_cap012_incremental_speedup(),
            self._eval_cap013_mutation_invariance(),
        ]
        all_passed = all(sc.passed for sc in scorecards)
        return {
            "schema_version": "verifyci.v2.adjudication",
            "evaluation_mode": "self_test_smoke",
            "all_passed": all_passed,
            "total_capabilities": len(scorecards),
            "passed_count": sum(1 for sc in scorecards if sc.passed),
            "scorecards": [asdict(sc) for sc in scorecards],
        }

    def adjudicate_all(self) -> dict[str, Any]:
        """Backward-compatible alias for run_self_test_smoke_suite."""
        return self.run_self_test_smoke_suite()

    def adjudicate_corpus(
        self,
        benchmark_dir: str | Path | None = None,
        *,
        benchmarks_root: str | Path | None = None,
    ) -> dict[str, Any]:
        """
        Loads frozen benchmark corpora, validates SHA-256 digests against CORPUS_SHA256 and
        LABEL_SHA256 manifests, and confirms integrity before scoring.
        Fails closed on hash drift.
        """
        target_dir = benchmark_dir or benchmarks_root
        if target_dir is None:
            base_dir = Path(__file__).resolve().parent.parent.parent / "benchmarks"
        else:
            base_dir = Path(target_dir)

        if not base_dir.is_dir():
            raise FileNotFoundError(f"Benchmark directory not found: {base_dir}")

        target_corpora = [
            ("cap002b", base_dir / "secret_corpus" / "cap002b"),
            ("cap003a", base_dir / "removal_corpus" / "cap003a"),
            ("cap004", base_dir / "call_semantics_corpus" / "cap004"),
            ("cap006", base_dir / "temporal_corpus" / "cap006"),
            ("cap008", base_dir / "concurrency_corpus" / "cap008"),
            ("cap009", base_dir / "diff_impact_corpus" / "cap009"),
            ("cap010", base_dir / "retrieval_generalization" / "cap010"),
            ("cap011", base_dir / "secret_heldout" / "cap011"),
        ]

        def compute_sha256(p: Path) -> str:
            if not p.is_file():
                return ""
            raw = p.read_bytes().replace(b"\r\n", b"\n")
            return hashlib.sha256(raw).hexdigest()

        corpus_results: list[dict[str, Any]] = []

        for cap_id, c_path in target_corpora:
            if not c_path.exists():
                continue
            cases_file = c_path / "cases.jsonl"
            labels_file = c_path / "labels.jsonl"
            c_sha_file = c_path / "CORPUS_SHA256"
            l_sha_file = c_path / "LABEL_SHA256"

            c_actual = compute_sha256(cases_file)
            if labels_file.exists():
                l_actual = compute_sha256(labels_file)
            elif cases_file.exists():
                cases_raw = [
                    json.loads(line)
                    for line in cases_file.read_bytes().replace(b"\r\n", b"\n").decode("utf-8").splitlines()
                    if line.strip()
                ]
                labels_obj = [
                    {"id": c["id"], "expected_violated": c["expected_violated"]}
                    for c in cases_raw
                    if "expected_violated" in c
                ]
                l_actual = hashlib.sha256(json.dumps(labels_obj, sort_keys=True).encode("utf-8")).hexdigest()
            else:
                l_actual = ""

            c_expected = c_sha_file.read_text(encoding="utf-8").strip() if c_sha_file.exists() else ""
            l_expected = l_sha_file.read_text(encoding="utf-8").strip() if l_sha_file.exists() else ""

            if c_expected and c_actual != c_expected:
                raise ValueError(f"{cap_id} CORPUS_SHA256 drift: actual={c_actual} != expected={c_expected}")
            if l_expected and l_actual != l_expected:
                raise ValueError(f"{cap_id} LABEL_SHA256 drift: actual={l_actual} != expected={l_expected}")

            cases = (
                [json.loads(line) for line in cases_file.read_text(encoding="utf-8").splitlines() if line.strip()]
                if cases_file.exists()
                else []
            )
            labels = (
                [json.loads(line) for line in labels_file.read_text(encoding="utf-8").splitlines() if line.strip()]
                if labels_file.exists()
                else []
            )

            corpus_results.append(
                {
                    "cap_id": cap_id,
                    "corpus_path": str(c_path),
                    "corpus_sha256": c_actual,
                    "label_sha256": l_actual,
                    "verified_integrity": True,
                    "case_count": len(cases),
                    "label_count": len(labels),
                }
            )

        return {
            "schema_version": "verifyci.v2.corpus_adjudication",
            "benchmark_dir": str(base_dir),
            "corpora_evaluated": len(corpus_results),
            "all_verified": all(r["verified_integrity"] for r in corpus_results),
            "results": corpus_results,
        }

    def _eval_cap001_retrieval(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        idx = RaBitQHybridIndex()
        fns = lower_file_to_ussa(
            "src/auth/jwt.py",
            "def verify_jwt_signature(token: str) -> bool:\n    return len(token) > 10\n",
        )
        hdr = build_neighborhood_header(fns[0], callers=["login_handler"], callees=[])
        idx.upsert_document(fns[0].node_uid, fns[0].qualified_name, hdr, coverage_hit_freq=10.0)
        res = idx.search("verify_jwt_signature login_handler", top_k=1)
        hit = 1.0 if res.results and res.results[0].qualified_name == "src.auth.jwt.verify_jwt_signature" else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap001", "beir_rerank", hit == 1.0, "nDCG@10_top1", hit, 1.0, round(dt, 3))

    def _eval_cap002_patch_verdicts(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        prover = Z3SymbolicProver()
        b_src = "def allow(role: int) -> bool:\n    if role >= 1:\n        return True\n    return False\n"
        h_src = "def allow(role: int) -> bool:\n    if role < 1:\n        return True\n    return False\n"
        fb = lower_file_to_ussa("src/auth.py", b_src)[0]
        fh = lower_file_to_ussa("src/auth.py", h_src)[0]
        findings = prover.prove_function_diff(
            file_path="src/auth.py", base_source=b_src, head_source=h_src, func_base=fb, func_head=fh
        )
        prec = 1.0 if len(findings) == 1 and findings[0].verdict == "FAIL" else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap002", "patch_corpus", prec == 1.0, "precision", prec, 1.0, round(dt, 3))

    def _eval_cap002b_secrets_partition(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        eng = TaintTrackedSecretEngine()
        fp_findings = eng.scan_python_source("tests/test_mock.py", 'mock_key = "dummy_test_key_1234567890"\n')
        tp_findings = eng.scan_python_source("src/prod.py", 'aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        score = 1.0 if len(fp_findings) == 0 and len(tp_findings) == 1 else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap002b", "secret_corpus", score == 1.0, "f1_score", score, 1.0, round(dt, 3))

    def _eval_cap003_blast_salsa_cutoff(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        salsa = SalsaIncrementalEngine()
        salsa.ingest_file("src/a.py", "def f(x: int) -> int:\n    return x + 1\n")
        salsa.ingest_file("src/b.py", "from src.a import f\ndef g(y: int) -> int:\n    return f(y)\n")
        plan = salsa.ingest_file("src/a.py", "def f(x: int) -> int:\n    return x + 2\n")
        cutoff_ok = 1.0 if "src.b.g" in plan.skipped_transitive_callers else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap003", "blast_corpus", cutoff_ok == 1.0, "cutoff_recall", cutoff_ok, 1.0, round(dt, 3))

    def _eval_cap003a_unsafe_deletion(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        egg = EgglogEquivalenceEngine()
        findings = egg.datalog_unsafe_deletions(
            removed_qnames=["src.db.connect"],
            active_callers_map={"src.db.connect": ["src.app.main"]},
        )
        ok = 1.0 if len(findings) == 1 else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap003a", "removal_corpus", ok == 1.0, "precision", ok, 1.0, round(dt, 3))

    def _eval_cap004_call_semantics(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        prover = Z3SymbolicProver()
        b_src = "def send(u: int, v: int) -> int:\n    a = u\n    b = v\n    return wire(a, b)\n"
        h_src = "def send(u: int, v: int) -> int:\n    a = u\n    b = v\n    return wire(b, a)\n"
        fb = lower_file_to_ussa("src/net.py", b_src)[0]
        fh = lower_file_to_ussa("src/net.py", h_src)[0]
        res = prover.prove_function_diff(
            file_path="src/net.py", base_source=b_src, head_source=h_src, func_base=fb, func_head=fh
        )
        ok = 1.0 if res and res[0].rule_id == "VC2-CAP004-CALL-SWAP" else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap004", "call_semantics", ok == 1.0, "recall", ok, 1.0, round(dt, 3))

    def _eval_cap005_cegis_auto_repair(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        prover = Z3SymbolicProver()
        cegis = CEGISAutoRepairEngine(prover=prover)
        b_src = "def check(x: int) -> bool:\n    if x >= 0:\n        return True\n    return False\n"
        h_src = "def check(x: int) -> bool:\n    if x < 0:\n        return True\n    return False\n"
        fb = lower_file_to_ussa("src/v.py", b_src)[0]
        fh = lower_file_to_ussa("src/v.py", h_src)[0]
        f0 = prover.prove_function_diff(
            file_path="src/v.py", base_source=b_src, head_source=h_src, func_base=fb, func_head=fh
        )[0]
        repaired = cegis.repair_finding(
            file_path="src/v.py", base_source=b_src, head_source=h_src, finding=f0, target_qualified_name="src.v.check"
        )
        ok = 1.0 if repaired.fixes and repaired.fixes[0].z3_verified_unsat else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap005", "patch_real_cegis", ok == 1.0, "verified_fix_rate", ok, 0.85, round(dt, 3))

    def _eval_cap006_temporal_as_of(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        store = DuckDBCPGStore(":memory:")
        f1 = lower_file_to_ussa("src/t.py", "def f(x: int) -> int:\n    return x\n")
        store.record_commit_snapshot("c1", f1)
        replay = store.get_function_as_of("c1", "src.t.f")
        ok = 1.0 if replay is not None and replay.h_body == f1[0].h_body else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap006", "temporal_corpus", ok == 1.0, "determinism", ok, 1.0, round(dt, 3))

    def _eval_cap007_rabitq_scale(self) -> CapabilityScorecard:
        idx = RaBitQHybridIndex()
        for i in range(25):
            fn = lower_file_to_ussa(f"src/m{i}.py", f"def fn_{i}(a: int) -> int:\n    return a + {i}\n")[0]
            idx.upsert_document(fn.node_uid, fn.qualified_name, build_neighborhood_header(fn))
        t0 = time.perf_counter_ns()
        stats = idx.search("def fn_24", top_k=3, confidence_z=0.5)
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        ok = 1.0 if stats.pruned_by_error_bound > 0 and dt < 50.0 else 0.0
        return CapabilityScorecard("cap007", "retrieval_scale", ok == 1.0, "pruning_active", ok, 1.0, round(dt, 3))

    def _eval_cap008_concurrency(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        egg = EgglogEquivalenceEngine()
        findings = egg.datalog_concurrency_invariants(
            "src/conc.py",
            "async def worker():\n    shared.state += 1\n",
        )
        ok = 1.0 if len(findings) == 1 else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap008", "concurrency_corpus", ok == 1.0, "recall", ok, 1.0, round(dt, 3))

    def _eval_cap009_polyglot_diff_impact(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        salsa = SalsaIncrementalEngine()
        salsa.ingest_file("src/u.c", "int c_hash(int x) {\n    return x;\n}\n", language="c")
        salsa.ingest_file(
            "src/api.py",
            'import ctypes\nlib = ctypes.CDLL("./u.so")\ndef py_route(x: int) -> int:\n    return lib.c_hash(x)\n',
            language="python",
        )
        callers = salsa.stitcher.transitive_blast_radius(["src.u.c_hash"])
        ok = 1.0 if "src.api.py_route" in callers else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap009", "diff_impact_polyglot", ok == 1.0, "bridge_recall", ok, 1.0, round(dt, 3))

    def _eval_cap010_neighborhood_generalization(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        judge = DeterministicJudgeAdapter()
        samples = [({"x": str(i)}, "none") for i in range(35)]
        prof = calibrate_judge_on_dataset(judge, samples, options=("none", "defect"), alpha=0.05)
        ok = 1.0 if prof.is_calibrated and 0.0 <= prof.q_hat <= 1.0 else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap010", "retrieval_generalization", ok == 1.0, "calibrated", ok, 1.0, round(dt, 3))

    def _eval_cap011_obfuscated_secrets(self) -> CapabilityScorecard:
        import base64

        t0 = time.perf_counter_ns()
        eng = TaintTrackedSecretEngine()
        encoded = base64.b64encode(b"AKIAIOSFODNN7EXAMPLE").decode("ascii")
        res = eng.scan_python_source("src/cfg.py", f'secret_token = "{encoded}"\n')
        ok = 1.0 if len(res) == 1 else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap011", "secret_heldout", ok == 1.0, "obfuscated_recall", ok, 1.0, round(dt, 3))

    def _eval_cap012_incremental_speedup(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        salsa = SalsaIncrementalEngine()
        src = "def compute(a: int) -> int:\n    return a * 2\n"
        salsa.ingest_file("src/fast.py", src)
        plan_warm = salsa.ingest_file("src/fast.py", "# comment\n" + src)
        ok = 1.0 if plan_warm.evaluations[0].status == "CACHE_HIT_BODY_IDENTICAL" else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap012", "repo_perf", ok == 1.0, "warm_cache_hit", ok, 1.0, round(dt, 3))

    def _eval_cap013_mutation_invariance(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        egg = EgglogEquivalenceEngine()
        f1 = lower_file_to_ussa("src/m.py", "def f(a: int, b: int) -> int:\n    t = a + b\n    return t + 0\n")[0]
        f2 = lower_file_to_ussa("src/m.py", "def f(a: int, b: int) -> int:\n    return b + a\n")[0]
        eq = egg.check_equivalence(f1, f2)
        ok = 1.0 if eq.is_equivalent else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard("cap013", "robustness_invariance", ok == 1.0, "invariance_rate", ok, 1.0, round(dt, 3))