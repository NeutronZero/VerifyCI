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

    sub.add_parser("adjudicate", help="Run the 15-capability v2 benchmark adjudication suite")

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
        sample_corpus = [
            ({"diff": "x = 1"}, "none"),
            ({"diff": "if a < b: raise ValueError()"}, "defect"),
            ({"diff": "return y + 1"}, "none"),
        ]
        profile = calibrate_judge_on_dataset(
            judge,
            sample_corpus,
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
        return V2CapabilityAdjudicator().adjudicate_all()

    raise ValueError(f"Unsupported command: {ns.command}")


def main(argv: Sequence[str] | None = None) -> str:
    res = run_cli(argv or [])
    return canonical_jcs_str(res)