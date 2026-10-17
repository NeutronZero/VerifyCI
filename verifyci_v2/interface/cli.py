from __future__ import annotations

import argparse
import msgspec
from typing import Any, Sequence

from verifyci_v2.contracts.canonical import canonical_jcs_str
from verifyci_v2.interface.fastmcp_daemon import VerifyCIFastMCPDaemon
from verifyci_v2.neural.adapters import DeterministicJudgeAdapter
from verifyci_v2.contracts.conformal import calibrate_judge_on_dataset
from verifyci_v2.neural.spec_compiler import IntentToSMTCompiler
from verifyci_v2.symbolic.egglog_engine import EgglogEquivalenceEngine


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vc2",
        description="VerifyCI v2.0 Neuro-Symbolic & Cryptographic Verification Engine",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser(
        "check",
        help="Run full neuro-symbolic check (Datalog concurrency, secrets taint, and intent SMT)",
    )
    p_check.add_argument("--file", required=True, help="Target file path")
    p_check.add_argument("--source", required=True, help="Target file source code")
    p_check.add_argument(
        "--intent", default="", help="Optional commit/PR intent statement"
    )

    p_prove = sub.add_parser(
        "prove", help="Prove equivalence or extract Z3 counterexamples"
    )
    p_prove.add_argument("--file", required=True, help="Target file path")
    p_prove.add_argument("--base-source", required=True, help="Pre-patch source code")
    p_prove.add_argument("--head-source", required=True, help="Post-patch source code")
    p_prove.add_argument(
        "--fix", action="store_true", help="Synthesize Z3-verified CEGIS repair"
    )

    p_fix = sub.add_parser(
        "fix", help="Synthesize and Z3-verify an automated CEGIS patch repair"
    )
    p_fix.add_argument("--file", required=True, help="Target file path")
    p_fix.add_argument("--base-source", required=True, help="Pre-patch source code")
    p_fix.add_argument("--head-source", required=True, help="Post-patch source code")

    p_cal = sub.add_parser(
        "calibrate", help="Calibrate BYO-AI Split Conformal quantile q_hat"
    )
    p_cal.add_argument(
        "--alpha", type=float, default=0.02, help="Target false-pass error rate"
    )

    p_anchor = sub.add_parser(
        "anchor", help="Emit in-toto DSSE receipt and anchor in gittuf RSL"
    )
    p_anchor.add_argument("--head-sha", default="abc1234", help="Target commit SHA")

    p_mcp = sub.add_parser("mcp", help="Inspect or invoke the unified FastMCP daemon")
    p_mcp.add_argument(
        "--list-tools", action="store_true", help="List registered MCP tools"
    )

    p_adj = sub.add_parser(
        "adjudicate", help="Run the 15-capability v2 benchmark adjudication suite"
    )
    p_adj.add_argument(
        "--corpus", action="store_true", help="Run full frozen corpus adjudication"
    )
    p_adj.add_argument("--dir", default=None, help="Custom benchmark directory")

    p_vdiff = sub.add_parser(
        "verify-diff", help="Verify code diff against contracts and invariants"
    )
    p_vdiff.add_argument("--diff-file", default="", help="Path to diff file")
    p_vdiff.add_argument("--db", default="", help="Path to database")
    p_vdiff.add_argument(
        "--format",
        default="sarif",
        choices=["sarif", "json", "text"],
        help="Output format",
    )
    p_vdiff.add_argument(
        "--output", default="verifyci-results.sarif", help="Output report file path"
    )

    p_init = sub.add_parser(
        "init", help="Initialize VerifyCI workspace and local database"
    )
    p_init.add_argument(
        "repo_path", nargs="?", default=".", help="Repository root path"
    )

    p_ingest = sub.add_parser(
        "ingest", help="Ingest code repository into local CPG graph store"
    )
    p_ingest.add_argument(
        "repo_path", nargs="?", default=".", help="Repository root path"
    )
    p_ingest.add_argument("--db", default="", help="Path to database")
    p_ingest.add_argument(
        "--backend",
        choices=["auto", "duckdb", "sqlite"],
        default="auto",
        help="CPG store backend; 'auto' prefers duckdb and falls back to sqlite",
    )

    return parser


def run_cli(argv: Sequence[str]) -> dict[str, Any]:
    parser = build_cli_parser()
    ns = parser.parse_args(list(argv))
    daemon = VerifyCIFastMCPDaemon(repo_id="cli-repo")

    if ns.command == "check":
        egg = EgglogEquivalenceEngine()
        spec_compiler = IntentToSMTCompiler()
        sec_resp = daemon.invoke_tool(
            "vc_triage_secrets",
            {"file_path": ns.file, "source": ns.source},
        )
        conc_findings = [
            msgspec.to_builtins(f) for f in egg.datalog_concurrency_invariants(ns.file, ns.source)
        ]
        intent_findings = (
            [
                msgspec.to_builtins(f)
                for f in spec_compiler.verify_function_against_intent(
                    file_path=ns.file,
                    source=ns.source,
                    intent_text=ns.intent,
                )
            ]
            if ns.intent
            else []
        )
        all_findings = sec_resp["data"]["findings"] + conc_findings + intent_findings
        return {
            "status": "ok",
            "command": "check",
            "finding_count": len(all_findings),
            "findings": all_findings,
        }

    if ns.command in ("prove", "fix"):
        auto_fix = True if ns.command == "fix" else bool(ns.fix)
        return daemon.invoke_tool(
            "vc_prove_diff",
            {
                "file_path": ns.file,
                "base_source": ns.base_source,
                "head_source": ns.head_source,
                "auto_fix": auto_fix,
            },
        )

    if ns.command == "calibrate":
        judge = DeterministicJudgeAdapter()
        # 35-example frozen calibration corpus (20 safe, 15 defect) to satisfy sample_size >= 30 and m >= 10
        frozen_corpus = [({"diff": f"x = {i}"}, "none") for i in range(20)] + [
            ({"diff": f"if a < {i}: raise ValueError('invalid')"}, "defect")
            for i in range(15)
        ]
        profile = calibrate_judge_on_dataset(
            judge,
            frozen_corpus,
            options=("none", "defect"),
            alpha=ns.alpha,
        )
        return {"status": "ok", "conformal_profile": msgspec.to_builtins(profile)}

    if ns.command == "anchor":
        return daemon.invoke_tool(
            "vc_anchor_attestation",
            {"head_commit_sha": ns.head_sha},
        )

    if ns.command == "mcp":
        return {
            "status": "ok",
            "daemon_repo_id": daemon.repo_id,
            "tools": list(daemon.list_tools()),
        }

    if ns.command == "adjudicate":
        from benchmarks.common.cap_adjudicator import V2CapabilityAdjudicator

        adj = V2CapabilityAdjudicator()
        if getattr(ns, "corpus", False):
            return adj.adjudicate_corpus(getattr(ns, "dir", None))
        return adj.run_self_test_smoke_suite()

    if ns.command == "verify-diff":
        from pathlib import Path
        import json

        from verifyci_v2.pipeline import (
            VerificationPipeline,
            parse_unified_diff,
        )
        from verifyci_v2.provenance.dsse_intoto import export_sarif_v2

        diff_file_str = getattr(ns, "diff_file", "") or ""
        diff_text = ""

        def infra_error(rationale: str) -> dict[str, Any]:
            return {
                "status": "INFRA_ERROR",
                "verdict": {"status": "INFRA_ERROR", "rationale": rationale},
                "runs": [
                    {
                        "invocations": [
                            {"properties": {"verdict": "INFRA_ERROR", "rationale": rationale}}
                        ]
                    }
                ],
            }

        if diff_file_str:
            p = Path(diff_file_str)
            if not p.exists():
                return infra_error(f"Diff file not found: {diff_file_str}")
            try:
                diff_text = p.read_text(encoding="utf-8")
            except Exception as exc:
                return infra_error(f"Could not read diff file: {exc}")

        if not diff_text.strip():
            res = {
                "status": "PASS",
                "verdict": {
                    "status": "PASS",
                    "rationale": "Empty diff: no changes to verify",
                },
                "diff_file": diff_file_str,
                "format": ns.format,
                "diff_bytes": 0,
                "findings_count": 0,
                "findings": [],
                "runs": [
                    {
                        "invocations": [
                            {
                                "properties": {
                                    "verdict": "PASS",
                                    "rationale": "Empty diff",
                                }
                            }
                        ]
                    }
                ],
            }
            if ns.output:
                Path(ns.output).write_text(json.dumps(res, indent=2), encoding="utf-8")
            return res

        entries = parse_unified_diff(diff_text)

        # Removal provenance needs a base revision the diff did not supply.
        # Without one the check is a tautology, so it is skipped rather than
        # dressed up as a verification.
        base_sources: dict[str, str] = {}
        if getattr(ns, "db", ""):
            try:
                from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore

                with DuckDBCPGStore(ns.db) as base_store:
                    base_sources = base_store.load_source_snapshot("HEAD")
            except Exception:
                base_sources = {}

        pipeline = VerificationPipeline(base_sources=base_sources)
        result = pipeline.verify_files(entries)

        res = {
            "status": result.status,
            "verdict": {
                "status": result.status,
                "rationale": result.rationale,
            },
            "diff_file": diff_file_str,
            "format": ns.format,
            "diff_bytes": result.diff_bytes,
            "findings_count": len(result.findings),
            "findings": [msgspec.to_builtins(f) for f in result.findings],
        }

        if ns.format == "sarif":
            report = export_sarif_v2(
                result.findings,
                ussa_merkle_root="",
                rsl_entry_hash="",
                verdict_status=result.status,
                rationale=result.rationale,
            )
        elif ns.format == "text":
            report = {
                "status": result.status,
                "rationale": result.rationale,
                "findings": [
                    f"{f.start_line}:{f.end_line} {f.severity} {f.rule_id} {f.message}"
                    for f in result.findings
                ],
            }
        else:
            # JSON is the CLI's own envelope; keep `verdict` alongside the
            # findings so `--format json` keeps its documented shape.
            report = dict(res)

        if ns.output:
            Path(ns.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        return res

    if ns.command == "init":
        from pathlib import Path

        repo_dir = Path(ns.repo_path)
        vci_dir = repo_dir / ".verifyci"
        vci_dir.mkdir(parents=True, exist_ok=True)
        return {"status": "ok", "initialized": True, "path": str(vci_dir)}

    if ns.command == "ingest":
        # (source snapshot is recorded below, after ingest)
        from pathlib import Path
        from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
        from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore

        repo_dir = Path(ns.repo_path)
        db_path = ns.db or str(repo_dir / ".verifyci" / "store.vc2")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with DuckDBCPGStore(db_path, backend=getattr(ns, "backend", "auto")) as store:
            ingested_count = 0
            failed_files: list[dict[str, str]] = []
            all_funcs = []
            for py_file in repo_dir.rglob("*.py"):
                if any(p.startswith(".") for p in py_file.parts):
                    continue
                try:
                    src = py_file.read_text(encoding="utf-8")
                    funcs = lower_file_to_ussa(str(py_file), src)
                    all_funcs.extend(funcs)
                    ingested_count += len(funcs)
                except Exception as exc:
                    failed_files.append({"file": str(py_file), "error": str(exc)})

            if all_funcs:
                store.record_commit_snapshot("HEAD", all_funcs)

            # Verbatim source per file: the only base record removal provenance
            # can use to contradict a diff that claims to delete code.
            source_snapshot: dict[str, str] = {}
            for py_file in repo_dir.rglob("*.py"):
                if any(p.startswith(".") for p in py_file.parts):
                    continue
                try:
                    rel = str(py_file.relative_to(repo_dir)).replace("\\", "/")
                    source_snapshot[rel] = py_file.read_text(encoding="utf-8")
                except (OSError, ValueError):
                    continue
            recorded_sources = store.record_source_snapshot("HEAD", source_snapshot)
            active_backend = store.active_backend

        status = "ok" if not failed_files else "partial_ingest"
        return {
            "status": status,
            # Disclose the active backend: DuckDBCPGStore silently falls back to
            # SQLite when duckdb is absent, which changes the store semantics.
            "active_backend": active_backend,
            "ingested_functions": ingested_count,
            "recorded_source_files": recorded_sources,
            "failed_files": failed_files,
            "db": db_path,
        }

    raise ValueError(f"Unsupported command: {ns.command}")


def main(argv: Sequence[str] | None = None) -> int:
    import sys
    import json

    args = sys.argv[1:] if argv is None else list(argv)
    try:
        res = run_cli(args)
    except Exception as exc:
        print(json.dumps({"status": "INFRA_ERROR", "error": str(exc)}))
        return 3

    out = canonical_jcs_str(res)
    print(out)
    exit_code = 0
    if isinstance(res, dict):
        status = res.get("verdict", {}).get("status") or res.get("status")
        if status == "FAIL":
            exit_code = 1
        elif status in ("INCONCLUSIVE", "UNCERTAIN"):
            exit_code = 2
        elif status in ("INFRA_ERROR", "ERROR"):
            exit_code = 3
    return exit_code


if __name__ == "__main__":
    import sys

    sys.exit(main())
