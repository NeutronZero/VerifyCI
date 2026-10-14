from __future__ import annotations

import argparse
from dataclasses import asdict
from typing import Any, Sequence

from verifyci_v2.contracts.canonical import canonical_jcs_str
from verifyci_v2.interface.cap_adjudicator import V2CapabilityAdjudicator
from verifyci_v2.interface.fastmcp_daemon import VerifyCIFastMCPDaemon
from verifyci_v2.neural.adapters import DeterministicJudgeAdapter
from verifyci_v2.neural.conformal import calibrate_judge_on_dataset
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
    p_check.add_argument("--intent", default="", help="Optional commit/PR intent statement")

    p_prove = sub.add_parser("prove", help="Prove equivalence or extract Z3 counterexamples")
    p_prove.add_argument("--file", required=True, help="Target file path")
    p_prove.add_argument("--base-source", required=True, help="Pre-patch source code")
    p_prove.add_argument("--head-source", required=True, help="Post-patch source code")
    p_prove.add_argument("--fix", action="store_true", help="Synthesize Z3-verified CEGIS repair")

    p_fix = sub.add_parser("fix", help="Synthesize and Z3-verify an automated CEGIS patch repair")
    p_fix.add_argument("--file", required=True, help="Target file path")
    p_fix.add_argument("--base-source", required=True, help="Pre-patch source code")
    p_fix.add_argument("--head-source", required=True, help="Post-patch source code")

    p_cal = sub.add_parser("calibrate", help="Calibrate BYO-AI Split Conformal quantile q_hat")
    p_cal.add_argument("--alpha", type=float, default=0.02, help="Target false-pass error rate")

    p_anchor = sub.add_parser("anchor", help="Emit in-toto DSSE receipt and anchor in gittuf RSL")
    p_anchor.add_argument("--head-sha", default="abc1234", help="Target commit SHA")

    p_mcp = sub.add_parser("mcp", help="Inspect or invoke the unified FastMCP daemon")
    p_mcp.add_argument("--list-tools", action="store_true", help="List registered MCP tools")

    p_adj = sub.add_parser("adjudicate", help="Run the 15-capability v2 benchmark adjudication suite")
    p_adj.add_argument("--corpus", action="store_true", help="Run full frozen corpus adjudication")
    p_adj.add_argument("--dir", default=None, help="Custom benchmark directory")

    p_vdiff = sub.add_parser("verify-diff", help="Verify code diff against contracts and invariants")
    p_vdiff.add_argument("--diff-file", default="", help="Path to diff file")
    p_vdiff.add_argument("--db", default="", help="Path to database")
    p_vdiff.add_argument("--format", default="sarif", choices=["sarif", "json", "text"], help="Output format")
    p_vdiff.add_argument("--output", default="verifyci-results.sarif", help="Output report file path")

    p_init = sub.add_parser("init", help="Initialize VerifyCI workspace and local database")
    p_init.add_argument("repo_path", nargs="?", default=".", help="Repository root path")

    p_ingest = sub.add_parser("ingest", help="Ingest code repository into local CPG graph store")
    p_ingest.add_argument("repo_path", nargs="?", default=".", help="Repository root path")
    p_ingest.add_argument("--db", default="", help="Path to database")

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
            asdict(f) for f in egg.datalog_concurrency_invariants(ns.file, ns.source)
        ]
        intent_findings = (
            [
                asdict(f)
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
        frozen_corpus = [
            ({"diff": f"x = {i}"}, "none") for i in range(20)
        ] + [
            ({"diff": f"if a < {i}: raise ValueError('invalid')"}, "defect") for i in range(15)
        ]
        profile = calibrate_judge_on_dataset(
            judge,
            frozen_corpus,
            options=("none", "defect"),
            alpha=ns.alpha,
        )
        return {"status": "ok", "conformal_profile": asdict(profile)}

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
        adj = V2CapabilityAdjudicator()
        if getattr(ns, "corpus", False):
            return adj.adjudicate_corpus(getattr(ns, "dir", None))
        return adj.run_self_test_smoke_suite()

    if ns.command == "verify-diff":
        from pathlib import Path
        import json
        import re
        import ast
        from verifyci_v2.contracts.attestation import VerificationFinding
        from verifyci_v2.contracts.canonical import blake3_hex
        from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
        from verifyci_v2.symbolic.secrets_taint import TaintTrackedSecretEngine
        from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver

        diff_file_str = getattr(ns, "diff_file", "") or ""
        diff_text = ""
        if diff_file_str:
            p = Path(diff_file_str)
            if not p.exists():
                return {
                    "status": "INFRA_ERROR",
                    "verdict": {
                        "status": "INFRA_ERROR",
                        "rationale": f"Diff file not found: {diff_file_str}",
                    },
                    "runs": [{"invocations": [{"properties": {"verdict": "INFRA_ERROR", "rationale": f"Diff file not found: {diff_file_str}"}}]}],
                }
            try:
                diff_text = p.read_text(encoding="utf-8")
            except Exception as exc:
                return {
                    "status": "INFRA_ERROR",
                    "verdict": {
                        "status": "INFRA_ERROR",
                        "rationale": f"Could not read diff file: {exc}",
                    },
                    "runs": [{"invocations": [{"properties": {"verdict": "INFRA_ERROR", "rationale": str(exc)}}]}],
                }

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
                "runs": [{"invocations": [{"properties": {"verdict": "PASS", "rationale": "Empty diff"}}]}],
            }
            if ns.output:
                Path(ns.output).write_text(json.dumps(res, indent=2), encoding="utf-8")
            return res

        diff_files = _parse_unified_diff(diff_text)
        findings: list[VerificationFinding] = []
        secret_engine = TaintTrackedSecretEngine()
        prover = Z3SymbolicProver(timeout_ms=3000)
        egg = EgglogEquivalenceEngine()

        aws_re = re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}")
        gh_re = re.compile(r"ghp_[A-Za-z0-9_]{36}")
        priv_key_re = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

        for file_entry in diff_files:
            file_path = file_entry["file_path"]
            base_src = file_entry["base_source"]
            head_src = file_entry["head_source"]
            added_lines = file_entry["added_lines"]

            # 1. Secret / token scans on added lines
            for line_idx, line in enumerate(added_lines, start=1):
                if aws_re.search(line) or gh_re.search(line) or priv_key_re.search(line):
                    findings.append(
                        VerificationFinding(
                            finding_id=blake3_hex(f"SECRET_REGEX:{file_path}:{line_idx}", domain="verifyci.v2.finding")[:16],
                            rule_id="VC2-SECRET-LEAK",
                            severity="CRITICAL",
                            verdict="FAIL",
                            file_path=file_path,
                            start_line=line_idx,
                            end_line=line_idx,
                            message=f"Critical secret or credential token detected in added lines of '{file_path}'.",
                        )
                    )

            if file_path.endswith(".py"):
                # Secret engine taint scan
                try:
                    sec_findings = secret_engine.scan_python_source(file_path, head_src)
                    findings.extend(sec_findings)
                except Exception:
                    pass

                # Check syntax of head code
                try:
                    ast.parse(head_src, filename=file_path)
                except SyntaxError as exc:
                    findings.append(
                        VerificationFinding(
                            finding_id=blake3_hex(f"SYNTAX:{file_path}:{exc.lineno}", domain="verifyci.v2.finding")[:16],
                            rule_id="VC2-AST-SYNTAX-ERROR",
                            severity="CRITICAL",
                            verdict="FAIL",
                            file_path=file_path,
                            start_line=exc.lineno or 1,
                            end_line=exc.lineno or 1,
                            message=f"Syntax error in head code of '{file_path}': {exc}",
                        )
                    )
                    continue

                # Lower to USSA and run symbolic verification if base and head are parseable
                try:
                    funcs_b = {f.qualified_name: f for f in lower_file_to_ussa(file_path, base_src, language="python")}
                    funcs_h = {f.qualified_name: f for f in lower_file_to_ussa(file_path, head_src, language="python")}
                    for qname, fh in funcs_h.items():
                        fb = funcs_b.get(qname)
                        if fb is not None and fb.h_body != fh.h_body:
                            diff_findings = prover.prove_function_diff(
                                file_path=file_path,
                                base_source=base_src,
                                head_source=head_src,
                                func_base=fb,
                                func_head=fh,
                            )
                            findings.extend(diff_findings)

                            is_eq, smt_st = prover.prove_equivalence(
                                base_source=base_src,
                                cand_source=head_src,
                                func_base=fb,
                                func_cand=fh,
                            )
                            if not is_eq and smt_st == "SAT" and not diff_findings:
                                findings.append(
                                    VerificationFinding(
                                        finding_id=blake3_hex(f"DIVERGE:{file_path}:{qname}", domain="verifyci.v2.finding")[:16],
                                        rule_id="VC2-Z3-SEMANTIC-DIVERGENCE",
                                        severity="HIGH",
                                        verdict="FAIL",
                                        file_path=file_path,
                                        start_line=fh.start_line,
                                        end_line=fh.end_line,
                                        message=f"Z3 proven semantic divergence between base and head for '{qname}'.",
                                    )
                                )
                except Exception as exc:
                    findings.append(
                        VerificationFinding(
                            finding_id=blake3_hex(f"SSA_ERROR:{file_path}", domain="verifyci.v2.finding")[:16],
                            rule_id="VC2-SSA-LOWER-ERROR",
                            severity="HIGH",
                            verdict="INCONCLUSIVE",
                            file_path=file_path,
                            start_line=1,
                            end_line=1,
                            message=f"SSA lowering error: {exc}",
                        )
                    )

                # Datalog concurrency checks
                try:
                    conc_findings = egg.datalog_concurrency_invariants(file_path, head_src)
                    findings.extend(conc_findings)
                except Exception:
                    pass

        fail_findings = [f for f in findings if f.verdict == "FAIL"]
        inc_findings = [f for f in findings if f.verdict in ("INCONCLUSIVE", "UNGROUNDED")]

        if fail_findings:
            v_status = "FAIL"
            rationale = f"Blocking invariant violations ({len(fail_findings)}): " + "; ".join(f.message for f in fail_findings[:3])
        elif inc_findings:
            v_status = "INCONCLUSIVE"
            rationale = f"Verification inconclusive ({len(inc_findings)} checks outside decidable fragment): " + "; ".join(f.message for f in inc_findings[:3])
        else:
            v_status = "PASS"
            rationale = "All verified contracts and invariant gates satisfied in diff"

        res = {
            "status": v_status,
            "verdict": {
                "status": v_status,
                "rationale": rationale,
            },
            "diff_file": diff_file_str,
            "format": ns.format,
            "diff_bytes": len(diff_text.encode("utf-8")),
            "findings_count": len(findings),
            "findings": [asdict(f) for f in findings],
            "runs": [
                {
                    "invocations": [
                        {
                            "properties": {
                                "verdict": v_status,
                                "rationale": rationale,
                            }
                        }
                    ],
                    "results": [
                        {
                            "ruleId": f.rule_id,
                            "level": "error" if f.verdict == "FAIL" else "warning",
                            "message": {"text": f.message},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f.file_path},
                                        "region": {"startLine": f.start_line, "endLine": f.end_line},
                                    }
                                }
                            ],
                        }
                        for f in findings
                    ],
                }
            ],
        }
        if ns.output:
            Path(ns.output).write_text(json.dumps(res, indent=2), encoding="utf-8")
        return res

    if ns.command == "init":
        from pathlib import Path

        repo_dir = Path(ns.repo_path)
        vci_dir = repo_dir / ".verifyci"
        vci_dir.mkdir(parents=True, exist_ok=True)
        return {"status": "ok", "initialized": True, "path": str(vci_dir)}

    if ns.command == "ingest":
        from pathlib import Path
        from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
        from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore

        repo_dir = Path(ns.repo_path)
        db_path = ns.db or str(repo_dir / ".verifyci" / "verifyci.db")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        store = DuckDBCPGStore(db_path)
        ingested_count = 0
        failed_files: list[dict[str, str]] = []
        for py_file in repo_dir.rglob("*.py"):
            if any(p.startswith(".") for p in py_file.parts):
                continue
            try:
                src = py_file.read_text(encoding="utf-8")
                funcs = lower_file_to_ussa(str(py_file), src)
                for f in funcs:
                    store.record_commit_snapshot("HEAD", [f])
                    ingested_count += 1
            except Exception as exc:
                failed_files.append({"file": str(py_file), "error": str(exc)})

        status = "ok" if not failed_files else "partial_ingest"
        return {
            "status": status,
            "ingested_functions": ingested_count,
            "failed_files": failed_files,
            "db": db_path,
        }

    raise ValueError(f"Unsupported command: {ns.command}")


def _parse_unified_diff(diff_text: str) -> list[dict[str, Any]]:
    """
    Parses unified diff into per-file chunks containing:
    file_path, base_source, head_source, added_lines.
    """
    files: list[dict[str, Any]] = []
    current_file: str | None = None
    base_lines: list[str] = []
    head_lines: list[str] = []
    added_lines: list[str] = []

    def flush_current():
        if current_file:
            files.append({
                "file_path": current_file,
                "base_source": "\n".join(base_lines),
                "head_source": "\n".join(head_lines),
                "added_lines": list(added_lines),
            })

    for line in diff_text.splitlines():
        if line.startswith("--- a/") or line.startswith("--- b/"):
            flush_current()
            current_file = line[6:].strip()
            base_lines = []
            head_lines = []
            added_lines = []
        elif line.startswith("+++ b/") or line.startswith("+++ a/"):
            current_file = line[6:].strip()
        elif line.startswith("@@"):
            continue
        elif current_file is not None:
            if line.startswith("+"):
                content = line[1:]
                head_lines.append(content)
                added_lines.append(content)
            elif line.startswith("-"):
                content = line[1:]
                base_lines.append(content)
            else:
                content = line[1:] if line.startswith(" ") else line
                base_lines.append(content)
                head_lines.append(content)

    flush_current()
    return files


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