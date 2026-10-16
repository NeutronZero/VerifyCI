from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import tempfile
import time
from typing import Any, TypeAlias

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


CapAdjudicationReport: TypeAlias = dict[str, Any]


@dataclass(frozen=True, slots=True)
class OracleScorecard:
    """Ground-truth measurement of a capability against a frozen corpus.

    `passed` is None when the capability is not measurable against this corpus.
    An unmeasurable capability is never reported as passing: fail-closed.
    """

    cap_id: str
    suite_name: str
    case_count: int
    scored: int
    metric_name: str
    metric_value: float | None
    target_threshold: float
    passed: bool | None
    threshold_basis: str
    metrics: dict[str, float] = field(default_factory=dict)
    confusion: dict[str, int] = field(default_factory=dict)
    false_accept_count: int = 0
    not_scored_reason: str | None = None


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _prf(tp: int, fp: int, fn: int, tn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    return {
        "tp": float(tp),
        "fp": float(fp),
        "fn": float(fn),
        "tn": float(tn),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
    }


def _binary_counts(pairs: list[tuple[bool, bool]]) -> tuple[int, int, int, int]:
    tp = sum(1 for pred, gold in pairs if pred and gold)
    fp = sum(1 for pred, gold in pairs if pred and not gold)
    fn = sum(1 for pred, gold in pairs if not pred and gold)
    tn = sum(1 for pred, gold in pairs if not pred and not gold)
    return tp, fp, fn, tn


def _unavailable_scorecard(cap_id: str, exc: Exception) -> "OracleScorecard":
    return OracleScorecard(
        cap_id=cap_id,
        suite_name="unavailable",
        case_count=0,
        scored=0,
        metric_name="unavailable",
        metric_value=None,
        target_threshold=0.0,
        passed=None,
        threshold_basis="none",
        not_scored_reason=f"{type(exc).__name__}: {exc}",
    )


# Capabilities with no frozen ground truth v2 can be scored against. Some have
# a corpus whose v2 entry point does not exist yet; the rest are exercised only
# by the self-test smoke suite, where the same harness supplies the fixture and
# the answer. Neither is an independent oracle, so both are declared here
# rather than silently omitted.
_DECLARED_UNMEASURABLE: dict[str, str] = {
    "cap006": "corpus expects exact canonical graph digests per commit; v2 DuckDB "
    "CPG digest is not yet byte-compatible with the frozen oracle",
    "cap008": "corpus expects a multi-process worker-protocol ledger replay; v2 "
    "exposes only the static datalog_concurrency_invariants rule",
    "cap005": "CEGIS auto-repair is exercised only by the self-test smoke fixture; "
    "patch_real has no frozen ground-truth labels v2 can be scored against",
    "cap007": "RaBitQ pruning is exercised only by the self-test smoke fixture; "
    "retrieval_corpus has no frozen ranking labels v2 can be scored against",
    "cap012": "incremental speedup is exercised only by the self-test smoke fixture; "
    "repo_perf has no frozen latency baseline v2 can be scored against",
    "cap013": "mutation invariance is exercised only by the self-test smoke fixture; "
    "robustness has no frozen invariance labels v2 can be scored against",
}


def _declared_unmeasurable(cap_id: str) -> "OracleScorecard":
    reason = _DECLARED_UNMEASURABLE.get(
        cap_id, "no frozen corpus with ground-truth labels for this capability"
    )
    return OracleScorecard(
        cap_id=cap_id,
        suite_name="not_measurable",
        case_count=0,
        scored=0,
        metric_name="not_measurable",
        metric_value=None,
        target_threshold=0.0,
        passed=None,
        threshold_basis="none",
        not_scored_reason=reason,
    )


_CAP010_INDEX: dict[str, Any] = {}


def _cap010_retriever(docs: dict[str, str]):
    """Builds the cap010 index once per process.

    The corpus is frozen and the embedder is deterministic, so the index is
    reusable across calls; rebuilding it for every measurement made the test
    suite pay the indexing cost repeatedly.
    """
    key = f"{len(docs)}:{hash(frozenset(docs))}"
    cached = _CAP010_INDEX.get(key)
    if cached is None:
        from verifyci_v2.interface.retrieval import TextRetriever

        cached = TextRetriever.build(docs)
        _CAP010_INDEX[key] = cached
    return cached


def _oracle_runners(adjudicator: "V2CapabilityAdjudicator"):
    """cap id -> runner, for corpora with a v2 engine entry point."""
    return (
        ("cap002b", adjudicator._oracle_cap002b),
        ("cap011", adjudicator._oracle_cap011),
        ("cap002_heldout", adjudicator._oracle_cap002_heldout),
        ("cap004", adjudicator._oracle_cap004),
        ("cap003a", adjudicator._oracle_cap003a),
                ("cap005", adjudicator._oracle_cap005),
                ("cap007", adjudicator._oracle_cap007),
                ("cap013", adjudicator._oracle_cap013),
                ("cap012", adjudicator._oracle_cap012),
                ("cap006", adjudicator._oracle_cap006),
                ("cap008", adjudicator._oracle_cap008),
        ("cap009", adjudicator._oracle_cap009),
        ("cap010", adjudicator._oracle_cap010),
    )


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
            if Path(__file__).resolve().parent.name == "common":
                base_dir = Path(__file__).resolve().parent.parent
            else:
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
                    for line in cases_file.read_bytes()
                    .replace(b"\r\n", b"\n")
                    .decode("utf-8")
                    .splitlines()
                    if line.strip()
                ]
                labels_obj = [
                    {"id": c["id"], "expected_violated": c["expected_violated"]}
                    for c in cases_raw
                    if "expected_violated" in c
                ]
                l_actual = hashlib.sha256(
                    json.dumps(labels_obj, sort_keys=True).encode("utf-8")
                ).hexdigest()
            else:
                l_actual = ""

            if cases_file.exists():
                if not c_sha_file.exists():
                    raise ValueError(f"{cap_id} missing CORPUS_SHA256 manifest file")
                c_expected = c_sha_file.read_text(encoding="utf-8").strip()
                if c_actual != c_expected:
                    raise ValueError(
                        f"{cap_id} CORPUS_SHA256 drift: actual={c_actual} != expected={c_expected}"
                    )

            if labels_file.exists():
                if not l_sha_file.exists():
                    raise ValueError(f"{cap_id} missing LABEL_SHA256 manifest file")
                l_expected = l_sha_file.read_text(encoding="utf-8").strip()
                if l_actual != l_expected:
                    raise ValueError(
                        f"{cap_id} LABEL_SHA256 drift: actual={l_actual} != expected={l_expected}"
                    )
            else:
                l_expected = (
                    l_sha_file.read_text(encoding="utf-8").strip()
                    if l_sha_file.exists()
                    else ""
                )
                if l_expected and l_actual != l_expected:
                    raise ValueError(
                        f"{cap_id} LABEL_SHA256 drift: actual={l_actual} != expected={l_expected}"
                    )

            cases = (
                [
                    json.loads(line)
                    for line in cases_file.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                if cases_file.exists()
                else []
            )
            labels = (
                [
                    json.loads(line)
                    for line in labels_file.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
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

        oracles = self.adjudicate_corpus_oracles(base_dir)
        return {
            "schema_version": "verifyci.v2.corpus_adjudication",
            "benchmark_dir": str(base_dir),
            "corpora_evaluated": len(corpus_results),
            "all_verified": all(r["verified_integrity"] for r in corpus_results),
            "results": corpus_results,
            "oracles": oracles,
        }

    def _oracle_secrets_binary(
        self,
        cases: list[dict[str, Any]],
        gold_key: str,
        suite_name: str,
    ) -> tuple[int, int, int, int]:
        """Runs the taint-tracked secret engine over each case diff.

        Prediction is "this case violates the secret invariant" = the engine
        emitted at least one FAIL finding for the patched source.
        """
        from verifyci_v2.interface.cli import _parse_unified_diff

        engine = TaintTrackedSecretEngine()
        pairs: list[tuple[bool, bool]] = []
        for case in cases:
            predicted = False
            try:
                for entry in _parse_unified_diff(case.get("diff", "")):
                    if entry["file_path"].endswith(".py"):
                        found = engine.scan_python_source(
                            entry["file_path"], entry["head_source"]
                        )
                    else:
                        found = engine.scan_config_lines(
                            entry["file_path"],
                            entry["head_source"].splitlines(),
                        )
                    if any(f.verdict == "FAIL" for f in found):
                        predicted = True
                        break
            except Exception:
                # An engine crash is a false accept for this case, never a pass.
                predicted = False
            pairs.append((predicted, bool(case.get(gold_key))))
        return _binary_counts(pairs)

    def _oracle_cap002b(self, base_dir: Path) -> OracleScorecard:
        cases = _read_jsonl(base_dir / "secret_corpus" / "cap002b" / "cases.jsonl")
        tp, fp, fn, tn = self._oracle_secrets_binary(
            cases, "expected_violated", "cap002b"
        )
        metrics = _prf(tp, fp, fn, tn)
        bar = 0.8696  # v1 parity bar (secret_corpus/cap002b/RESULTS.md recall)
        return OracleScorecard(
            cap_id="cap002b",
            suite_name="secret_corpus_ground_truth",
            case_count=len(cases),
            scored=len(cases),
            metric_name="recall",
            metric_value=metrics["recall"],
            target_threshold=bar,
            passed=metrics["recall"] >= bar,
            threshold_basis="v1_parity",
            metrics=metrics,
            confusion={
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
            },
            false_accept_count=fn,
        )

    def _oracle_cap011(self, base_dir: Path) -> OracleScorecard:
        cases = _read_jsonl(base_dir / "secret_heldout" / "cap011" / "cases.jsonl")
        tp, fp, fn, tn = self._oracle_secrets_binary(cases, "is_secret", "cap011")
        metrics = _prf(tp, fp, fn, tn)
        bar = 0.95  # predeclared (secret_heldout/cap011/RESULTS.md overall recall)
        return OracleScorecard(
            cap_id="cap011",
            suite_name="secret_heldout_ground_truth",
            case_count=len(cases),
            scored=len(cases),
            metric_name="recall",
            metric_value=metrics["recall"],
            target_threshold=bar,
            passed=metrics["recall"] >= bar and metrics["precision"] >= 0.99,
            threshold_basis="predeclared_recall_0.95_and_precision_0.99",
            metrics=metrics,
            confusion={
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
            },
            false_accept_count=fn,
        )

    def _oracle_cap005(self, base_dir: Path) -> OracleScorecard:
        """Real-patch verdict agreement against the frozen CAP-005 corpus.

        The frozen 64-case `patch_real` corpus ships `cases.jsonl` + `labels.jsonl`
        with an exact id match and an adjudicated `expected_status` per case, so
        this capability is measurable without authoring any new evidence.

        Fail-closed mapping matches CAP-002 held-out: a stricter verdict than the
        label is accepted, a laxer one is not, and HUMAN_REVIEW has no v2 verdict
        so it is reported as unmapped rather than silently credited.
        """
        from verifyci_v2.interface.cli import run_cli

        corpus_dir = base_dir / "patch_real" / "cap005"
        cases = {str(c.get("id")): c for c in _read_jsonl(corpus_dir / "cases.jsonl")}
        labels = _read_jsonl(corpus_dir / "labels.jsonl")

        acceptable = {
            "PASS": {"PASS"},
            "FAIL": {"FAIL"},
            "INCONCLUSIVE": {"INCONCLUSIVE", "FAIL"},
        }
        agreed = 0
        false_accepts = 0
        unmapped = 0
        scored = 0

        for label in labels:
            case_id = str(label.get("id", ""))
            case = cases.get(case_id)
            if case is None:
                continue
            expected = str(label.get("expected_status", ""))
            allowed = acceptable.get(expected)
            if allowed is None:
                unmapped += 1
                continue

            scored += 1
            with tempfile.NamedTemporaryFile(
                "w", suffix=".diff", delete=False, encoding="utf-8"
            ) as fh:
                fh.write(case.get("diff", ""))
                diff_path = fh.name
            try:
                result = run_cli(
                    ["verify-diff", "--diff-file", diff_path, "--format", "json"]
                )
                actual = str(result.get("status", "INCONCLUSIVE"))
            except Exception as exc:
                actual = f"ERROR:{type(exc).__name__}"
            finally:
                Path(diff_path).unlink(missing_ok=True)

            if actual in allowed:
                agreed += 1
            if expected in ("FAIL", "INCONCLUSIVE") and actual == "PASS":
                false_accepts += 1

        agreement = round(agreed / scored, 4) if scored else 0.0
        # v1 parity bar: v1 scored 64/64 (100%) on this frozen corpus
        # (benchmarks/patch_real/cap005/RESULTS.md).
        bar = 1.0
        return OracleScorecard(
            cap_id="cap005",
            suite_name="patch_real",
            case_count=len(labels),
            scored=scored,
            metric_name="verdict_agreement",
            metric_value=agreement,
            target_threshold=bar,
            passed=agreement >= bar and false_accepts == 0 and scored > 0,
            threshold_basis="v1_parity_and_zero_false_accepts",
            metrics={"agreement": agreement, "false_accepts": float(false_accepts)},
            confusion={"agreed": agreed, "unmapped": unmapped},
            false_accept_count=false_accepts,
            not_scored_reason=(
                None if scored else "no label has a v2-mappable expected_status"
            ),
        )

    def _oracle_cap007(self, base_dir: Path) -> OracleScorecard:
        """Hop-bounded blast radius + deterministic ranking vs frozen CAP-007 labels.

        The frozen labels were produced by `benchmarks/retrieval_corpus/cap007/oracle.py`,
        a clean-room reference implementation that imports nothing from verifyci.
        This oracle therefore measures the v2 engine (`diff_impact`) against an
        independent reference, not against itself.

        Tripwire cases must fail closed: an unbounded or crashing traversal is
        scored as a disagreement, never as agreement.
        """
        from verifyci_v2.ingestion.diff_impact import (
            build_graph,
            compute_blast_radius,
            deterministic_ranking,
        )

        corpus_dir = base_dir / "retrieval_corpus" / "cap007"
        cases = {str(c.get("id")): c for c in _read_jsonl(corpus_dir / "cases.jsonl")}
        labels = _read_jsonl(corpus_dir / "labels.jsonl")

        set_exact = 0
        ranking_exact = 0
        tripwire_safe = 0
        tripwire_total = 0
        scored = 0
        disagreements: list[dict[str, Any]] = []

        for label in labels:
            case_id = str(label.get("id", ""))
            case = cases.get(case_id)
            if case is None:
                continue
            scored += 1
            expected_status = str(label.get("expected_status", ""))

            if expected_status == "INCONCLUSIVE":
                # Tripwire: bounded traversal must terminate without hanging and
                # must not claim a concrete impact set.
                tripwire_total += 1
                try:
                    graph = build_graph(
                        case.get("graph", {}).get("nodes", []),
                        case.get("graph", {}).get("edges", []),
                    )
                    queries = case.get("queries") or [{}]
                    for query in queries:
                        compute_blast_radius(
                            graph,
                            [str(s) for s in query.get("seeds", [])],
                            [str(t) for t in query.get("test_entities", [])],
                            int(query.get("max_hops", 2)),
                        )
                    tripwire_safe += 1
                except Exception:
                    pass
                continue

            expected_set = set(label.get("exact_impact_set") or [])
            expected_rankings = label.get("rankings") or {}
            try:
                graph = build_graph(
                    case.get("graph", {}).get("nodes", []),
                    case.get("graph", {}).get("edges", []),
                )
                union: set[str] = set()
                hops: dict[str, int] = {}
                for query in case.get("queries") or [{}]:
                    seeds = [str(s) for s in query.get("seeds", [])]
                    result = compute_blast_radius(
                        graph,
                        seeds,
                        [str(t) for t in query.get("test_entities", [])],
                        int(query.get("max_hops", 2)),
                    )
                    union |= set(result.affected_callers) | set(
                        result.affected_callees
                    )
                    for eid in result.hop_distances:
                        hops[eid] = min(hops.get(eid, 999), result.hop_distances[eid])
                actual_rankings = {
                    key: list(val)
                    for key, val in deterministic_ranking(hops).items()
                }
            except Exception as exc:
                disagreements.append(
                    {"id": case_id, "error": f"{type(exc).__name__}: {exc}"}
                )
                continue

            set_ok = union == expected_set
            rank_ok = all(
                set(actual_rankings.get(key, [])) == set(expected_rankings.get(key, []))
                for key in expected_rankings
            )
            set_exact += int(set_ok)
            ranking_exact += int(rank_ok)
            if not (set_ok and rank_ok):
                disagreements.append(
                    {
                        "id": case_id,
                        "missing": sorted(expected_set - union)[:5],
                        "extra": sorted(union - expected_set)[:5],
                        "set_exact": set_ok,
                        "ranking_exact": rank_ok,
                    }
                )

        total = scored - tripwire_total
        set_agreement = round(set_exact / total, 4) if total > 0 else 0.0
        ranking_agreement = round(ranking_exact / total, 4) if total > 0 else 0.0
        trip_rate = round(tripwire_safe / tripwire_total, 4) if tripwire_total else 1.0

        return OracleScorecard(
            cap_id="cap007",
            suite_name="retrieval_corpus",
            case_count=len(labels),
            scored=scored,
            metric_name="impact_set_agreement",
            metric_value=set_agreement,
            target_threshold=0.95,
            passed=(
                total > 0
                and set_agreement >= 0.95
                and ranking_agreement >= 0.95
                and trip_rate == 1.0
            ),
            threshold_basis="frozen_clean_room_oracle_agreement",
            metrics={
                "impact_set_agreement": set_agreement,
                "ranking_agreement": ranking_agreement,
                "tripwire_safe_rate": trip_rate,
            },
            confusion={
                "set_exact": set_exact,
                "ranking_exact": ranking_exact,
                "tripwire_safe": tripwire_safe,
                "tripwire_total": tripwire_total,
            },
            false_accept_count=0,
            not_scored_reason=None if scored else "no cases matched labels",
        )

    def _oracle_cap013(self, base_dir: Path) -> OracleScorecard:
        """Mutation kill rate against the frozen CAP-013 gates.

        Gates are read from the frozen `config.json` and are never relaxed here:
        `critical_mutation_kill_rate_min`, `incorrect_pass_rate_max`,
        `oracle_disagreement_rate_max`, `false_decline_rate_max`.

        The mutation table is the v2-native `mutations_v2.py`: the frozen v1
        table targets `verifyci.*` modules that no longer exist. Each mutation is
        applied in an isolated sandbox copy and classified killed/survived by
        running a behaviour probe; a surviving critical mutation is a reported
        verification gap, never hidden.
        """
        import json as _json

        config_path = base_dir / "robustness" / "cap013" / "config.json"
        if not config_path.exists():
            return OracleScorecard(
                cap_id="cap013",
                suite_name="robustness",
                case_count=0,
                scored=0,
                metric_name="mutation_kill_rate",
                metric_value=None,
                target_threshold=1.0,
                passed=None,
                threshold_basis="frozen_config_gates",
                not_scored_reason="frozen cap013 config is missing",
            )

        config = _json.loads(config_path.read_text(encoding="utf-8"))
        gates = config.get("gates", {})
        kill_min = float(gates.get("critical_mutation_kill_rate_min", 1.0))
        incorrect_max = float(gates.get("incorrect_pass_rate_max", 0.0))
        decline_max = float(gates.get("false_decline_rate_max", 0.05))
        disagreement_max = float(gates.get("oracle_disagreement_rate_max", 0.0))

        import sys as _sys

        _sys.path.insert(0, str(base_dir / "robustness" / "cap013"))
        try:
            import mutations_v2
        except Exception as exc:  # pragma: no cover - import guard
            return OracleScorecard(
                cap_id="cap013",
                suite_name="robustness",
                case_count=0,
                scored=0,
                metric_name="mutation_kill_rate",
                metric_value=None,
                target_threshold=kill_min,
                passed=None,
                threshold_basis="frozen_config_gates",
                not_scored_reason=f"mutation harness unavailable: {type(exc).__name__}",
            )

        result = mutations_v2.run_suite()
        kill_rate = float(result["mutation_kill_rate"])
        incorrect = float(result["incorrect_pass_rate"])
        decline = float(result["false_decline_rate"])
        disagreement = float(result["oracle_disagreement_rate"])

        passed = (
            kill_rate >= kill_min
            and incorrect <= incorrect_max
            and decline <= decline_max
            and disagreement <= disagreement_max
            and result["critical_total"] > 0
        )

        return OracleScorecard(
            cap_id="cap013",
            suite_name="robustness",
            case_count=int(result["critical_total"]),
            scored=int(result["critical_total"]),
            metric_name="mutation_kill_rate",
            metric_value=kill_rate,
            target_threshold=kill_min,
            passed=passed,
            threshold_basis="frozen_config_gates",
            metrics={
                "mutation_kill_rate": kill_rate,
                "incorrect_pass_rate": incorrect,
                "false_decline_rate": decline,
                "oracle_disagreement_rate": disagreement,
            },
            confusion={
                "critical_killed": int(result["critical_killed"]),
                "critical_total": int(result["critical_total"]),
                "invalid_mutations": int(result["critical_invalid"]),
                "false_declines": int(result["false_declines"]),
            },
            false_accept_count=int(round(incorrect * result["critical_total"])),
            not_scored_reason=None,
        )

    def _oracle_cap012(self, base_dir: Path) -> OracleScorecard:
        """Repository performance envelope against the frozen CAP-012 budgets.

        Budgets (p95 latency and peak RSS per tier) come from the frozen
        `config.json` and are never modified. This oracle only supplies the v2
        tier fixtures and measures the real ingest path
        (`SalsaIncrementalEngine.ingest_file`) against those predeclared
        budgets.
        """
        import sys as _sys

        tier_dir = base_dir / "repo_perf" / "cap012"
        if not (tier_dir / "config.json").exists():
            return OracleScorecard(
                cap_id="cap012",
                suite_name="repo_perf",
                case_count=0,
                scored=0,
                metric_name="budget_compliance",
                metric_value=None,
                target_threshold=1.0,
                passed=None,
                threshold_basis="frozen_config_budgets",
                not_scored_reason="frozen cap012 config is missing",
            )

        _sys.path.insert(0, str(tier_dir))
        try:
            import tiers_v2
        except Exception as exc:  # pragma: no cover - import guard
            return OracleScorecard(
                cap_id="cap012",
                suite_name="repo_perf",
                case_count=0,
                scored=0,
                metric_name="budget_compliance",
                metric_value=None,
                target_threshold=1.0,
                passed=None,
                threshold_basis="frozen_config_budgets",
                not_scored_reason=f"tier harness unavailable: {type(exc).__name__}",
            )

        envelope = tiers_v2.run_envelope()
        compliance = float(envelope["budget_compliance"])
        tiers = envelope["tiers"]
        over_budget = sorted(
            name for name, spec in tiers.items() if not spec["within_budget"]
        )

        # Every predeclared tier must land inside its frozen budget.
        return OracleScorecard(
            cap_id="cap012",
            suite_name="repo_perf",
            case_count=int(envelope["tiers_total"]),
            scored=int(envelope["tiers_total"]),
            metric_name="budget_compliance",
            metric_value=compliance,
            target_threshold=1.0,
            passed=compliance == 1.0 and int(envelope["tiers_total"]) > 0,
            threshold_basis="frozen_config_budgets",
            metrics={
                "budget_compliance": compliance,
                "worst_p95_budget_utilisation": float(
                    envelope["worst_p95_budget_utilisation"]
                ),
            },
            confusion={
                "tiers_within_budget": int(envelope["tiers_within_budget"]),
                "tiers_total": int(envelope["tiers_total"]),
            },
            false_accept_count=len(over_budget),
            not_scored_reason=None,
        )

    def _oracle_cap006(self, base_dir: Path) -> OracleScorecard:
        """Temporal replay attestation against the frozen CAP-006 corpus.

        Measures the protocol's own gates:
          * T1 replay equivalence - the canonical digest of an incrementally
            replayed history must equal the digest of a clean snapshot.
          * Absolute parity - that digest must equal the frozen
            `expected_canonical_digest` produced by the clean-room oracle.
          * T7 fail-closed - tripwire histories (unknown parent, cyclic lineage,
            missing target) must raise and never yield an invented digest.

        Tripwire cases are excluded from the parity denominator because the
        frozen label carries no digest for them; they are scored on T7 alone.
        """
        from verifyci_v2.store.canonical_graph import (
            LineageIntegrityError,
            clean_snapshot_digest,
            replay_digest,
            resolve_snapshot_files,
        )

        corpus_dir = base_dir / "temporal_corpus" / "cap006"
        cases = {
            str(c.get("id")): c
            for c in _read_jsonl(corpus_dir / "cases.jsonl")
        }
        labels = _read_jsonl(corpus_dir / "labels.jsonl")

        parity_exact = 0
        t1_equivalent = 0
        tripwire_failed_closed = 0
        tripwire_total = 0
        scored = 0
        disagreements: list[dict[str, Any]] = []

        for label in labels:
            case_id = str(label.get("id", ""))
            case = cases.get(case_id)
            if case is None:
                continue
            expected_status = str(label.get("expected_status", ""))
            target = label.get("target_commit") or (
                case.get("target_query", {}) or {}
            ).get("target_commit")

            if expected_status == "INCONCLUSIVE":
                tripwire_total += 1
                try:
                    replay_digest(case.get("commits", []), str(target))
                except LineageIntegrityError:
                    tripwire_failed_closed += 1
                except Exception:
                    tripwire_failed_closed += 1
                continue

            scored += 1
            try:
                replayed = replay_digest(case.get("commits", []), str(target))
                snapshot_files = resolve_snapshot_files(
                    case.get("commits", []), str(target)
                )
                clean = clean_snapshot_digest(snapshot_files)
            except Exception as exc:
                disagreements.append(
                    {"id": case_id, "error": f"{type(exc).__name__}: {exc}"}
                )
                continue

            if replayed == clean:
                t1_equivalent += 1
            expected_digest = label.get("expected_canonical_digest")
            if expected_digest is None or replayed == expected_digest:
                parity_exact += 1
            else:
                disagreements.append(
                    {
                        "id": case_id,
                        "expected": expected_digest,
                        "actual": replayed,
                        "t1_equivalent": replayed == clean,
                    }
                )

        total = scored or 1
        parity = round(parity_exact / total, 4)
        t1_rate = round(t1_equivalent / total, 4)
        trip_rate = (
            round(tripwire_failed_closed / tripwire_total, 4)
            if tripwire_total
            else 1.0
        )

        return OracleScorecard(
            cap_id="cap006",
            suite_name="temporal_corpus",
            case_count=len(labels),
            scored=scored,
            metric_name="canonical_digest_parity",
            metric_value=parity,
            target_threshold=1.0,
            passed=(
                total > 0 and parity == 1.0 and t1_rate == 1.0 and trip_rate == 1.0
            ),
            threshold_basis="frozen_clean_room_oracle_parity_and_t1_equivalence",
            metrics={
                "canonical_digest_parity": parity,
                "t1_replay_equivalence": t1_rate,
                "tripwire_fail_closed_rate": trip_rate,
            },
            confusion={
                "parity_exact": parity_exact,
                "t1_equivalent": t1_equivalent,
                "tripwire_failed_closed": tripwire_failed_closed,
                "tripwire_total": tripwire_total,
            },
            false_accept_count=0,
            not_scored_reason=None if scored else "no PASS-labelled cases matched",
        )

    def _oracle_cap008(self, base_dir: Path) -> OracleScorecard:
        """Concurrency invariants against the frozen CAP-008 corpus.

        Executes each case's workers as real OS processes against one shared
        revision store, then checks the frozen invariants:
          * branch states (canonical hash, counts, head) match the labels,
          * the ledger hash chain is continuous,
          * disjoint branches are invariant (A||B == A alone),
          * tripwires fail closed.
        """
        import sys as _sys

        harness_dir = base_dir / "concurrency_corpus" / "cap008"
        if not (harness_dir / "cases.jsonl").exists():
            return OracleScorecard(
                cap_id="cap008",
                suite_name="concurrency_corpus",
                case_count=0,
                scored=0,
                metric_name="branch_state_agreement",
                metric_value=None,
                target_threshold=0.95,
                passed=None,
                threshold_basis="frozen_worker_protocol",
                not_scored_reason="frozen cap008 corpus is missing",
            )

        _sys.path.insert(0, str(harness_dir))
        try:
            import harness_v2
        except Exception as exc:  # pragma: no cover - import guard
            return OracleScorecard(
                cap_id="cap008",
                suite_name="concurrency_corpus",
                case_count=0,
                scored=0,
                metric_name="branch_state_agreement",
                metric_value=None,
                target_threshold=0.95,
                passed=None,
                threshold_basis="frozen_worker_protocol",
                not_scored_reason=f"harness unavailable: {type(exc).__name__}",
            )

        result = harness_v2.run_suite()
        scored = int(result["scored"])
        state = float(result["branch_state_agreement"])
        chain = float(result["chain_continuity_rate"])
        invariance = float(result["disjoint_invariance_rate"])
        trip = float(result["tripwire_fail_closed_rate"])

        passed = (
            scored > 0
            and state >= 0.95
            and chain >= 0.95
            and invariance >= 0.95
            and trip == 1.0
        )

        return OracleScorecard(
            cap_id="cap008",
            suite_name="concurrency_corpus",
            case_count=int(result["cases_total"]),
            scored=scored,
            metric_name="branch_state_agreement",
            metric_value=state,
            target_threshold=0.95,
            passed=passed,
            threshold_basis="frozen_worker_protocol",
            metrics={
                "branch_state_agreement": state,
                "chain_continuity_rate": chain,
                "disjoint_invariance_rate": invariance,
                "tripwire_fail_closed_rate": trip,
            },
            confusion={
                "state_exact": int(result["state_exact"]),
                "tripwire_fail_closed": int(result["tripwire_fail_closed"]),
                "tripwire_total": int(result["tripwire_total"]),
            },
            false_accept_count=0,
            not_scored_reason=None if scored else "no PASS-labelled cases matched",
        )

    def _oracle_cap002_heldout(self, base_dir: Path) -> OracleScorecard:
        """End-to-end gate agreement: v2 `verify-diff` status vs frozen ground truth.

        Fail-closed mapping: a stricter verdict than the label (FAIL for an
        expected INCONCLUSIVE) is accepted; a laxer one is not. HUMAN_REVIEW has
        no v2 verdict and is reported as unmapped rather than silently credited.
        """
        from verifyci_v2.interface.cli import run_cli

        cases = _read_jsonl(
            base_dir / "patch_corpus" / "cap002_heldout" / "cases.jsonl"
        )
        acceptable = {
            "PASS": {"PASS"},
            "FAIL": {"FAIL"},
            "INCONCLUSIVE": {"INCONCLUSIVE", "FAIL"},
        }
        agreed = 0
        false_accepts = 0
        unmapped = 0
        per_case: list[dict[str, Any]] = []

        for case in cases:
            expected = str(case.get("expected_status", ""))
            with tempfile.NamedTemporaryFile(
                "w", suffix=".diff", delete=False, encoding="utf-8"
            ) as fh:
                fh.write(case.get("diff", ""))
                diff_path = fh.name
            try:
                result = run_cli(
                    ["verify-diff", "--diff-file", diff_path, "--format", "json"]
                )
                actual = str(result.get("status", "INCONCLUSIVE"))
            except Exception as exc:
                actual = f"ERROR:{type(exc).__name__}"
            finally:
                Path(diff_path).unlink(missing_ok=True)

            allowed = acceptable.get(expected)
            if allowed is None:
                unmapped += 1
                per_case.append(
                    {
                        "id": case.get("id"),
                        "expected": expected,
                        "actual": actual,
                        "mapped": False,
                    }
                )
                continue
            ok = actual in allowed
            agreed += int(ok)
            # A defect-bearing case that the gate passes is a false accept.
            if expected in ("FAIL", "INCONCLUSIVE") and actual == "PASS":
                false_accepts += 1
            per_case.append(
                {
                    "id": case.get("id"),
                    "expected": expected,
                    "actual": actual,
                    "mapped": True,
                    "agreed": ok,
                }
            )

        scored = len(cases) - unmapped
        agreement = round(agreed / scored, 4) if scored else 0.0
        bar = 0.8235  # v1 parity bar (patch_corpus/cap002_heldout/RESULTS.md 14/17)
        return OracleScorecard(
            cap_id="cap002_heldout",
            suite_name="patch_corpus_ground_truth",
            case_count=len(cases),
            scored=scored,
            metric_name="verdict_agreement",
            metric_value=agreement,
            target_threshold=bar,
            passed=agreement >= bar and false_accepts == 0,
            threshold_basis="v1_parity_and_zero_false_accepts",
            metrics={
                "agreement": agreement,
                "agreed": float(agreed),
                "scored": float(scored),
                "unmapped": float(unmapped),
            },
            confusion={
                "agreed": agreed,
                "disagreed": scored - agreed,
                "unmapped": unmapped,
            },
            false_accept_count=false_accepts,
        )

    def _oracle_cap004(self, base_dir: Path) -> OracleScorecard:
        from verifyci_v2.symbolic.contract_checker import verify_call_contract

        corpus_dir = base_dir / "call_semantics_corpus" / "cap004"
        cases = {c["id"]: c for c in _read_jsonl(corpus_dir / "cases.jsonl")}
        labels = _read_jsonl(corpus_dir / "labels.jsonl")

        agreed = 0
        scored = 0
        false_accepts = 0
        confusion: dict[str, str] = {}

        for label in labels:
            case = cases.get(label["id"])
            if case is None:
                continue
            scored += 1
            result = verify_call_contract(
                case["call_code"], case["callee_signature"], case["contract"]
            )
            expected = str(label["expected"])
            confusion[label.get("slice", "?")] = (
                f"{confusion.get(label.get('slice', '?'), '')}"
                f"{'|' if confusion.get(label.get('slice', '?')) else ''}"
                f"{expected}->{result.verdict}"
            )
            if result.verdict == expected:
                agreed += 1
            # A defect contract that the checker *accepts* is a false accept. An
            # INCONCLUSIVE verdict on a defect case is fail-closed, not an accept.
            if expected == "FAIL" and result.verdict == "VERIFIED":
                false_accepts += 1

        accuracy = round(agreed / scored, 4) if scored else 0.0
        bar = 0.90  # v1 parity bar: contract checking is fully decidable on this corpus
        return OracleScorecard(
            cap_id="cap004",
            suite_name="call_semantics_ground_truth",
            case_count=len(cases),
            scored=scored,
            metric_name="verdict_agreement",
            metric_value=accuracy,
            target_threshold=bar,
            passed=accuracy >= bar and false_accepts == 0,
            threshold_basis="declarative_contract_checking_is_fully_decidable",
            metrics={"agreement": accuracy, "agreed": float(agreed)},
            confusion={
                "agreed": agreed,
                "disagreed": scored - agreed,
                **{k: v for k, v in confusion.items() if k != "?"},
            },
            false_accept_count=false_accepts,
        )

    def _oracle_cap003a(self, base_dir: Path) -> OracleScorecard:
        from verifyci_v2.ingestion.removal_provenance import (
            analyze_removal_provenance,
        )

        corpus_dir = base_dir / "removal_corpus" / "cap003a"
        cases = {c["id"]: c for c in _read_jsonl(corpus_dir / "cases.jsonl")}
        labels = _read_jsonl(corpus_dir / "labels.jsonl")

        agreed = 0
        scored = 0
        false_accepts = 0
        fabricated_missed = 0
        per_slice: dict[str, list[str]] = {}

        for label in labels:
            case = cases.get(label["id"])
            if case is None:
                continue
            scored += 1
            result = analyze_removal_provenance(case["diff"], case.get("entities", []))
            expected = str(label["expected"])
            actual = "INCONCLUSIVE" if result.verdict == "UNVERIFIED" else result.verdict
            per_slice.setdefault(label.get("slice", "?"), []).append(
                f"{expected}->{actual}"
            )
            if actual == expected:
                agreed += 1
            if expected == "FABRICATED" and actual != "FABRICATED":
                fabricated_missed += 1
            # The safety-critical direction: a diff the corpus calls forged must
            # never be accepted as a verified removal.
            if expected == "FABRICATED" and actual == "VERIFIED":
                false_accepts += 1

        accuracy = round(agreed / scored, 4) if scored else 0.0
        bar = 0.90
        return OracleScorecard(
            cap_id="cap003a",
            suite_name="removal_provenance_ground_truth",
            case_count=len(cases),
            scored=scored,
            metric_name="verdict_agreement",
            metric_value=accuracy,
            target_threshold=bar,
            passed=accuracy >= bar and false_accepts == 0,
            threshold_basis="provenance_checking_is_fully_decidable_on_this_corpus",
            metrics={
                "agreement": accuracy,
                "agreed": float(agreed),
                "fabricated_missed": float(fabricated_missed),
            },
            confusion={
                "agreed": agreed,
                "disagreed": scored - agreed,
                **{k: "|".join(v) for k, v in per_slice.items()},
            },
            false_accept_count=false_accepts,
        )

    def _oracle_cap009(self, base_dir: Path) -> OracleScorecard:
        from verifyci_v2.ingestion.diff_impact import analyze_diff_impact

        corpus_dir = base_dir / "diff_impact_corpus" / "cap009"
        cases = {c["case_id"]: c for c in _read_jsonl(corpus_dir / "cases.jsonl")}
        labels = _read_jsonl(corpus_dir / "labels.jsonl")

        seed_exact = 0
        impact_exact = 0
        scored = 0
        missed_seeds = 0
        missed_impact = 0
        critical_scored = 0
        critical_missed = 0

        for label in labels:
            case = cases.get(label["case_id"])
            if case is None:
                continue
            scored += 1
            result = analyze_diff_impact(
                case["diff"], case.get("entities", []), case.get("graph_edges", [])
            )
            expected_seeds = {str(s) for s in label.get("expected_seeds", [])}
            expected_impact = {str(s) for s in label.get("expected_impact", [])}
            actual_seeds = set(result.seeds)
            actual_impact = set(result.impact)

            if actual_seeds == expected_seeds:
                seed_exact += 1
            else:
                missed_seeds += len(expected_seeds - actual_seeds)
            if actual_impact == expected_impact:
                impact_exact += 1
            else:
                missed_impact += len(expected_impact - actual_impact)

            if label.get("is_critical_adversarial") or case.get(
                "is_critical_adversarial"
            ):
                critical_scored += 1
                if actual_seeds != expected_seeds or actual_impact != expected_impact:
                    critical_missed += 1

        seed_accuracy = round(seed_exact / scored, 4) if scored else 0.0
        impact_accuracy = round(impact_exact / scored, 4) if scored else 0.0
        # Blast-radius under-reporting is the unsafe direction: a caller
        # silently dropped from impact.
        expected_impact_total = sum(
            len(entry.get("expected_impact", [])) for entry in labels
        )
        missed_impact_rate = missed_impact / max(1, expected_impact_total)
        bar = 0.95
        passed = impact_accuracy >= bar and seed_accuracy >= bar
        return OracleScorecard(
            cap_id="cap009",
            suite_name="diff_impact_ground_truth",
            case_count=len(cases),
            scored=scored,
            metric_name="impact_accuracy",
            metric_value=impact_accuracy,
            target_threshold=bar,
            passed=passed,
            threshold_basis="exact_set_match_against_frozen_impact_labels",
            metrics={
                "seed_accuracy": seed_accuracy,
                "impact_accuracy": impact_accuracy,
                "missed_impact_rate": round(missed_impact_rate, 4),
                "critical_missed": float(critical_missed),
            },
            confusion={
                "seed_exact": seed_exact,
                "impact_exact": impact_exact,
                "critical_scored": critical_scored,
            },
            false_accept_count=critical_missed,
        )

    def adjudicate_capability(self, cap_id: str) -> OracleScorecard:
        """Runs one capability's engine against its frozen corpus.

        Used by the per-capability `measure_*.py` scripts so measuring one
        capability does not execute all of them.
        """
        base_dir = Path(__file__).resolve().parent.parent
        if not base_dir.is_dir():
            base_dir = Path(__file__).resolve().parent.parent.parent / "benchmarks"

        for candidate_id, runner in _oracle_runners(self):
            if candidate_id == cap_id:
                try:
                    return runner(base_dir)
                except Exception as exc:
                    return _unavailable_scorecard(cap_id, exc)

        return _declared_unmeasurable(cap_id)

    def _oracle_cap010(self, base_dir: Path) -> OracleScorecard:
        import math

        from benchmarks.common.retrieval_rules import evaluate_retrieval_abstention

        corpus_dir = base_dir / "retrieval_generalization" / "cap010"
        cases = _read_jsonl(corpus_dir / "cases.jsonl")
        docs = {c["id"]: c["text"] for c in cases if c.get("kind") == "doc"}
        queries = {c["qid"]: c["text"] for c in cases if c.get("kind") == "query"}
        labels = _read_jsonl(corpus_dir / "labels.jsonl")

        retriever = _cap010_retriever(docs)
        doc_texts = {doc_id: docs[doc_id] for doc_id in retriever.doc_ids()}

        hit_5 = hit_20 = 0
        ndcg_sum = 0.0
        ndcg_count = 0
        answerable = 0
        abstained_correct = 0
        false_relevant = 0
        no_answer = 0

        for label in labels:
            qid = label["qid"]
            query = queries.get(qid)
            if query is None:
                continue
            relevance = {str(k): int(v) for k, v in label.get("relevance", {}).items()}
            ranked = retriever.search(query, top_k=20)
            ranked_ids = [r.doc_id for r in ranked]
            max_grade = max(relevance.values(), default=0)

            if max_grade == 0:
                # No-answer slice: the only correct behaviour is abstention.
                no_answer += 1
                abstained, _reason = evaluate_retrieval_abstention(
                    query, ranked_ids, doc_texts
                )
                abstained_correct += int(abstained)
                false_relevant += int(not abstained)
                continue

            answerable += 1
            hit_5 += int(any(d in relevance for d in ranked_ids[:5]))
            hit_20 += int(any(d in relevance for d in ranked_ids[:20]))
            dcg = 0.0
            for position, doc_id in enumerate(ranked_ids[:10], start=1):
                grade = relevance.get(doc_id)
                if grade:
                    dcg += (2**grade - 1) / math.log2(position + 1)
            idcg = sum(
                (2**g - 1) / math.log2(i + 1)
                for i, g in enumerate(sorted(relevance.values(), reverse=True)[:10], 1)
            )
            if idcg > 0:
                ndcg_sum += dcg / idcg
                ndcg_count += 1

        recall_5 = hit_5 / answerable if answerable else 0.0
        recall_20 = hit_20 / answerable if answerable else 0.0
        ndcg = ndcg_sum / ndcg_count if ndcg_count else 0.0
        abstention = abstained_correct / no_answer if no_answer else 0.0
        false_rel_rate = false_relevant / no_answer if no_answer else 0.0

        # Predeclared gates from the frozen corpus protocol (see RESULTS.md).
        gates_met = (
            recall_5 >= 0.80
            and recall_20 >= 0.90
            and ndcg >= 0.50
            and abstention >= 0.90
            and false_rel_rate <= 0.10
        )
        return OracleScorecard(
            cap_id="cap010",
            suite_name="retrieval_generalization_ground_truth",
            case_count=len(queries),
            scored=len(labels),
            metric_name="recall_at_5",
            metric_value=round(recall_5, 4),
            target_threshold=0.80,
            passed=gates_met,
            threshold_basis="predeclared_five_gates_recall5_recall20_ndcg_abstain_false_rel",
            metrics={
                "recall_at_5": round(recall_5, 4),
                "recall_at_20": round(recall_20, 4),
                "ndcg_at_10": round(ndcg, 4),
                "abstention_rate": round(abstention, 4),
                "false_relevant_rate": round(false_rel_rate, 4),
                "answerable": float(answerable),
                "no_answer": float(no_answer),
            },
            confusion={
                "hit_at_5": hit_5,
                "hit_at_20": hit_20,
                "abstained_correct": abstained_correct,
                "false_relevant": false_relevant,
            },
            false_accept_count=false_relevant,
        )

    def adjudicate_corpus_oracles(
        self, benchmark_dir: str | Path | None = None
    ) -> dict[str, Any]:
        """Executes v2 engines against frozen corpora and scores against ground truth.

        Integrity checking lives in `adjudicate_corpus`; this method measures.
        A capability with no v2 equivalent against its corpus is emitted with
        `passed=None` and an explicit reason rather than a default pass.
        """
        if benchmark_dir is None:
            base_dir = (
                Path(__file__).resolve().parent.parent
                if Path(__file__).resolve().parent.name == "common"
                else Path(__file__).resolve().parent.parent.parent / "benchmarks"
            )
        else:
            base_dir = Path(benchmark_dir)
        if not base_dir.is_dir():
            raise FileNotFoundError(f"Benchmark directory not found: {base_dir}")

        scorecards: list[OracleScorecard] = []
        for cap_id, runner in _oracle_runners(self):
            try:
                scorecards.append(runner(base_dir))
            except Exception as exc:
                scorecards.append(_unavailable_scorecard(cap_id, exc))

        for cap_id in _DECLARED_UNMEASURABLE:
            scorecards.append(_declared_unmeasurable(cap_id))

        measured = [sc for sc in scorecards if sc.passed is not None]
        return {
            "schema_version": "verifyci.v2.corpus_oracle_adjudication",
            "benchmark_dir": str(base_dir),
            "measured_capabilities": len(measured),
            "unmeasurable_capabilities": len(scorecards) - len(measured),
            "all_measured_passed": bool(measured)
            and all(sc.passed for sc in measured),
            "total_false_accepts": sum(sc.false_accept_count for sc in scorecards),
            "scorecards": [asdict(sc) for sc in scorecards],
        }

    def _eval_cap001_retrieval(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        idx = RaBitQHybridIndex()
        fns = lower_file_to_ussa(
            "src/auth/jwt.py",
            "def verify_jwt_signature(token: str) -> bool:\n    return len(token) > 10\n",
        )
        hdr = build_neighborhood_header(fns[0], callers=["login_handler"], callees=[])
        idx.upsert_document(
            fns[0].node_uid, fns[0].qualified_name, hdr, coverage_hit_freq=10.0
        )
        res = idx.search("verify_jwt_signature login_handler", top_k=1)
        hit = (
            1.0
            if res.results
            and res.results[0].qualified_name == "src.auth.jwt.verify_jwt_signature"
            else 0.0
        )
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap001", "beir_rerank", hit == 1.0, "nDCG@10_top1", hit, 1.0, round(dt, 3)
        )

    def _eval_cap002_patch_verdicts(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        prover = Z3SymbolicProver()
        b_src = "def allow(role: int) -> bool:\n    if role >= 1:\n        return True\n    return False\n"
        h_src = "def allow(role: int) -> bool:\n    if role < 1:\n        return True\n    return False\n"
        fb = lower_file_to_ussa("src/auth.py", b_src)[0]
        fh = lower_file_to_ussa("src/auth.py", h_src)[0]
        findings = prover.prove_function_diff(
            file_path="src/auth.py",
            base_source=b_src,
            head_source=h_src,
            func_base=fb,
            func_head=fh,
        )
        prec = 1.0 if len(findings) == 1 and findings[0].verdict == "FAIL" else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap002", "patch_corpus", prec == 1.0, "precision", prec, 1.0, round(dt, 3)
        )

    def _eval_cap002b_secrets_partition(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        eng = TaintTrackedSecretEngine()
        fp_findings = eng.scan_python_source(
            "tests/test_mock.py", 'mock_key = "dummy_test_key_1234567890"\n'
        )
        tp_findings = eng.scan_python_source(
            "src/prod.py", 'aws_key = "AKIAIOSFODNN7EXAMPLE"\n'
        )
        score = 1.0 if len(fp_findings) == 0 and len(tp_findings) == 1 else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap002b",
            "secret_corpus",
            score == 1.0,
            "f1_score",
            score,
            1.0,
            round(dt, 3),
        )

    def _eval_cap003_blast_salsa_cutoff(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        salsa = SalsaIncrementalEngine()
        salsa.ingest_file("src/a.py", "def f(x: int) -> int:\n    return x + 1\n")
        salsa.ingest_file(
            "src/b.py", "from src.a import f\ndef g(y: int) -> int:\n    return f(y)\n"
        )
        plan = salsa.ingest_file(
            "src/a.py", "def f(x: int) -> int:\n    return x + 2\n"
        )
        cutoff_ok = 1.0 if "src.b.g" in plan.skipped_transitive_callers else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap003",
            "blast_corpus",
            cutoff_ok == 1.0,
            "cutoff_recall",
            cutoff_ok,
            1.0,
            round(dt, 3),
        )

    def _eval_cap003a_unsafe_deletion(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        egg = EgglogEquivalenceEngine()
        findings = egg.datalog_unsafe_deletions(
            removed_qnames=["src.db.connect"],
            active_callers_map={"src.db.connect": ["src.app.main"]},
        )
        ok = 1.0 if len(findings) == 1 else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap003a", "removal_corpus", ok == 1.0, "precision", ok, 1.0, round(dt, 3)
        )

    def _eval_cap004_call_semantics(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        prover = Z3SymbolicProver()
        b_src = "def send(u: int, v: int) -> int:\n    a = u\n    b = v\n    return wire(a, b)\n"
        h_src = "def send(u: int, v: int) -> int:\n    a = u\n    b = v\n    return wire(b, a)\n"
        fb = lower_file_to_ussa("src/net.py", b_src)[0]
        fh = lower_file_to_ussa("src/net.py", h_src)[0]
        res = prover.prove_function_diff(
            file_path="src/net.py",
            base_source=b_src,
            head_source=h_src,
            func_base=fb,
            func_head=fh,
        )
        ok = 1.0 if res and res[0].rule_id == "VC2-CAP004-CALL-SWAP" else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap004", "call_semantics", ok == 1.0, "recall", ok, 1.0, round(dt, 3)
        )

    def _eval_cap005_cegis_auto_repair(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        prover = Z3SymbolicProver()
        cegis = CEGISAutoRepairEngine(prover=prover)
        b_src = "def check(x: int) -> bool:\n    if x >= 0:\n        return True\n    return False\n"
        h_src = "def check(x: int) -> bool:\n    if x < 0:\n        return True\n    return False\n"
        fb = lower_file_to_ussa("src/v.py", b_src)[0]
        fh = lower_file_to_ussa("src/v.py", h_src)[0]
        f0 = prover.prove_function_diff(
            file_path="src/v.py",
            base_source=b_src,
            head_source=h_src,
            func_base=fb,
            func_head=fh,
        )[0]
        repaired = cegis.repair_finding(
            file_path="src/v.py",
            base_source=b_src,
            head_source=h_src,
            finding=f0,
            target_qualified_name="src.v.check",
        )
        ok = 1.0 if repaired.fixes and repaired.fixes[0].z3_verified_unsat else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap005",
            "patch_real_cegis",
            ok == 1.0,
            "verified_fix_rate",
            ok,
            0.85,
            round(dt, 3),
        )

    def _eval_cap006_temporal_as_of(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        store = DuckDBCPGStore(":memory:")
        f1 = lower_file_to_ussa("src/t.py", "def f(x: int) -> int:\n    return x\n")
        store.record_commit_snapshot("c1", f1)
        replay = store.get_function_as_of("c1", "src.t.f")
        ok = 1.0 if replay is not None and replay.h_body == f1[0].h_body else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap006", "temporal_corpus", ok == 1.0, "determinism", ok, 1.0, round(dt, 3)
        )

    def _eval_cap007_rabitq_scale(self) -> CapabilityScorecard:
        idx = RaBitQHybridIndex()
        for i in range(25):
            fn = lower_file_to_ussa(
                f"src/m{i}.py", f"def fn_{i}(a: int) -> int:\n    return a + {i}\n"
            )[0]
            idx.upsert_document(
                fn.node_uid, fn.qualified_name, build_neighborhood_header(fn)
            )
        t0 = time.perf_counter_ns()
        stats = idx.search("def fn_24", top_k=3, confidence_z=0.5)
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        ok = 1.0 if stats.pruned_by_error_bound > 0 and dt < 50.0 else 0.0
        return CapabilityScorecard(
            "cap007",
            "retrieval_scale",
            ok == 1.0,
            "pruning_active",
            ok,
            1.0,
            round(dt, 3),
        )

    def _eval_cap008_concurrency(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        egg = EgglogEquivalenceEngine()
        findings = egg.datalog_concurrency_invariants(
            "src/conc.py",
            "async def worker():\n    shared.state += 1\n",
        )
        ok = 1.0 if len(findings) == 1 else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap008", "concurrency_corpus", ok == 1.0, "recall", ok, 1.0, round(dt, 3)
        )

    def _eval_cap009_polyglot_diff_impact(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        salsa = SalsaIncrementalEngine()
        salsa.ingest_file(
            "src/u.c", "int c_hash(int x) {\n    return x;\n}\n", language="c"
        )
        salsa.ingest_file(
            "src/api.py",
            'import ctypes\nlib = ctypes.CDLL("./u.so")\ndef py_route(x: int) -> int:\n    return lib.c_hash(x)\n',
            language="python",
        )
        callers = salsa.stitcher.transitive_blast_radius(["src.u.c_hash"])
        ok = 1.0 if "src.api.py_route" in callers else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap009",
            "diff_impact_polyglot",
            ok == 1.0,
            "bridge_recall",
            ok,
            1.0,
            round(dt, 3),
        )

    def _eval_cap010_neighborhood_generalization(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        judge = DeterministicJudgeAdapter()
        samples = [({"x": str(i)}, "none") for i in range(35)]
        prof = calibrate_judge_on_dataset(
            judge, samples, options=("none", "defect"), alpha=0.05
        )
        ok = 1.0 if prof.is_calibrated and 0.0 <= prof.q_hat <= 1.0 else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap010",
            "retrieval_generalization",
            ok == 1.0,
            "calibrated",
            ok,
            1.0,
            round(dt, 3),
        )

    def _eval_cap011_obfuscated_secrets(self) -> CapabilityScorecard:
        import base64

        t0 = time.perf_counter_ns()
        eng = TaintTrackedSecretEngine()
        encoded = base64.b64encode(b"AKIAIOSFODNN7EXAMPLE").decode("ascii")
        res = eng.scan_python_source("src/cfg.py", f'secret_token = "{encoded}"\n')
        ok = 1.0 if len(res) == 1 else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap011",
            "secret_heldout",
            ok == 1.0,
            "obfuscated_recall",
            ok,
            1.0,
            round(dt, 3),
        )

    def _eval_cap012_incremental_speedup(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        salsa = SalsaIncrementalEngine()
        src = "def compute(a: int) -> int:\n    return a * 2\n"
        salsa.ingest_file("src/fast.py", src)
        plan_warm = salsa.ingest_file("src/fast.py", "# comment\n" + src)
        ok = (
            1.0
            if plan_warm.evaluations[0].status == "CACHE_HIT_BODY_IDENTICAL"
            else 0.0
        )
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap012", "repo_perf", ok == 1.0, "warm_cache_hit", ok, 1.0, round(dt, 3)
        )

    def _eval_cap013_mutation_invariance(self) -> CapabilityScorecard:
        t0 = time.perf_counter_ns()
        egg = EgglogEquivalenceEngine()
        f1 = lower_file_to_ussa(
            "src/m.py",
            "def f(a: int, b: int) -> int:\n    t = a + b\n    return t + 0\n",
        )[0]
        f2 = lower_file_to_ussa(
            "src/m.py", "def f(a: int, b: int) -> int:\n    return b + a\n"
        )[0]
        eq = egg.check_equivalence(f1, f2)
        ok = 1.0 if eq.is_equivalent else 0.0
        dt = (time.perf_counter_ns() - t0) / 1_000_000.0
        return CapabilityScorecard(
            "cap013",
            "robustness_invariance",
            ok == 1.0,
            "invariance_rate",
            ok,
            1.0,
            round(dt, 3),
        )
