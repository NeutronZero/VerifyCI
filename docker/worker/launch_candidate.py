#!/usr/bin/env python3
"""Trusted Candidate Worker Launcher (§15.10 Component A).

Runs inside the restricted container sandbox.
Imports candidate module strictly from /candidate via explicit sys.path insertion,
executes the requested check or gate, and emits structured JSON to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time


def parse_args():
    parser = argparse.ArgumentParser(description="VerifyCI Candidate Worker Launcher")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    case_cmd = sub.add_parser("check-case", help="Execute single benchmark check case")
    case_cmd.add_argument("--candidate-root", default="/candidate", help="Path to mounted candidate source")
    case_cmd.add_argument("--repo-root", default="/repo", help="Path to mounted test repository")
    case_cmd.add_argument("--base", required=True, help="Base commit SHA")
    case_cmd.add_argument("--head", required=True, help="Head commit SHA")
    case_cmd.add_argument("--policy-toml", default="", help="Policy configuration TOML")
    case_cmd.add_argument("--as-of-date", default=None, help="Authoritative evaluation as-of date (YYYY-MM-DD)")
    case_cmd.add_argument("--toolchain-fingerprint", default=None, help="Trusted toolchain fingerprint")
    case_cmd.add_argument(
        "--object-format",
        default=None,
        help="Git object format (sha1 or sha256; default: sha1 or VERIFYCI_OBJECT_FORMAT env)",
    )
    case_cmd.add_argument(
        "--source-root",
        action="append",
        dest="source_roots",
        default=None,
        help="Source root directory (repeatable or comma-separated)",
    )
    case_cmd.add_argument(
        "--source-roots",
        dest="source_roots_str",
        default=None,
        help="Comma-separated source root directories",
    )

    gate_cmd = sub.add_parser("gate", help="Execute candidate gate CLI")
    gate_cmd.add_argument("--candidate-root", default="/candidate", help="Path to mounted candidate source")
    gate_cmd.add_argument("--repo-root", default="/repo", help="Path to mounted test repository")
    gate_cmd.add_argument("--base", required=True, help="Base commit SHA")
    gate_cmd.add_argument("--head", required=True, help="Head commit SHA")
    gate_cmd.add_argument("--format", default="json", choices=("json", "text"))

    return parser.parse_args()


def main():
    args = parse_args()
    cand_root = Path(args.candidate_root).resolve()
    if not cand_root.is_dir():
        sys.stderr.write(f"candidate root does not exist: {cand_root}\n")
        return 3

    # Add candidate root to sys.path so verifyci package is imported from candidate source
    if str(cand_root) not in sys.path:
        sys.path.insert(0, str(cand_root))

    if args.subcommand == "check-case":
        try:
            from verifyci.checks.base import CheckContext
            from verifyci.checks.security import run as run_security
            from verifyci.gate.orchestrator import _augment_scope_with_repository
            from verifyci.gate.policy import parse_policy_bytes
            from verifyci.scm.git import GitRepo
            from verifyci.scope.entities import build_changed_scope

            repo = GitRepo(Path(args.repo_root))
            entries, _ = repo.diff_entries(args.base, args.head)
            scope = build_changed_scope(entries)
            obj_format = (
                args.object_format
                or os.environ.get("VERIFYCI_OBJECT_FORMAT")
                or os.environ.get("OBJECT_FORMAT")
                or "sha1"
            )
            parsed_roots: list[str] = []
            if args.source_roots:
                for item in args.source_roots:
                    parsed_roots.extend(part.strip() for part in item.split(",") if part.strip())
            if args.source_roots_str:
                parsed_roots.extend(part.strip() for part in args.source_roots_str.split(",") if part.strip())
            if not parsed_roots and os.environ.get("VERIFYCI_SOURCE_ROOTS"):
                parsed_roots.extend(
                    part.strip() for part in os.environ["VERIFYCI_SOURCE_ROOTS"].split(",") if part.strip()
                )
            source_roots = tuple(parsed_roots)

            scope = _augment_scope_with_repository(
                scope, git=repo, base_rev=args.base, head_rev=args.head, source_roots=source_roots
            )
            policy = parse_policy_bytes(args.policy_toml.encode("utf-8"))

            eval_date = args.as_of_date or time.strftime("%Y-%m-%d", time.gmtime())
            eval_toolchain = args.toolchain_fingerprint or "sha256:a053a0d6a509c1b5fcafba6b0c580ec69174533a70903be4ca9d3462b47ebea9"
            ctx = CheckContext(
                git=repo,
                policy=policy,
                entries=tuple(entries),
                scope=scope,
                as_of_date=eval_date,
                target_base_commit=args.base,
                merge_base_commit=args.base,
                head_commit=args.head,
                object_format=obj_format,
                toolchain_fingerprint=eval_toolchain,
                source_roots=source_roots,
            )
            res = run_security(ctx)
            payload = {
                "outcome": res.outcome.value,
                "coverage": res.coverage.value,
                "reason_codes": list(res.reason_codes),
                "findings": [
                    {
                        "defect_id": f.defect_id,
                        "message": f.message,
                        "tier": getattr(f.tier, "value", str(f.tier)),
                    }
                    for f in res.findings
                ],
            }
            sys.stdout.write(json.dumps(payload, sort_keys=True) + "\n")
            sys.stdout.flush()

            # Exit code mapping: 0=PASS, 1=FAIL, 2=INCONCLUSIVE, 3=ERROR,
            # 4=NOT_APPLICABLE.  The IPC validator accepts the canonical
            # Coverage enum (COMPLETE/PARTIAL/UNKNOWN) emitted above.
            if res.outcome.value == "PASS":
                return 0
            if res.outcome.value == "FAIL":
                return 1
            if res.outcome.value == "INCONCLUSIVE":
                return 2
            if res.outcome.value == "NOT_APPLICABLE":
                return 4
            return 3

        except Exception as exc:
            err_payload = {
                "outcome": "ERROR",
                "coverage": "UNKNOWN",
                "reason_codes": ["execution_exception"],
                "findings": [],
            }
            sys.stdout.write(json.dumps(err_payload) + "\n")
            sys.stdout.flush()
            sys.stderr.write(f"execution failed: {exc}\n")
            return 3

    elif args.subcommand == "gate":
        try:
            import verifyci.cli as cli
            gate_args = [
                "gate",
                "--repo", str(args.repo_root),
                "--base", args.base,
                "--head", args.head,
                "--format", args.format,
            ]
            return cli.main(gate_args)
        except Exception as exc:
            sys.stderr.write(f"gate invocation failed: {exc}\n")
            return 3

    return 3


if __name__ == "__main__":
    raise SystemExit(main())
