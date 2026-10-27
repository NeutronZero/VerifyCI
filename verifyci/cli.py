"""``vc gate`` CLI for VerifyCI v3.1.10."""

from __future__ import annotations

import argparse
import os
import json
from pathlib import Path
import sys
from typing import Sequence

from verifyci import __version__ as TOOL_VERSION


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vc", description="VerifyCI deterministic pre-merge gate")
    parser.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    gate = sub.add_parser("gate", help="verify a commit range")
    gate.add_argument("--repo", default=".", help="repository directory")
    gate.add_argument("--base", required=True, help="target-branch revision (policy authority)")
    gate.add_argument("--head", default="HEAD", help="head revision (default: HEAD)")
    gate.add_argument("--merge-base", default=None, help="explicit verified merge base")
    gate.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    gate.add_argument("--output", default=None, help="write output to this path")
    gate.add_argument("--as-of", default=None, help="evaluation date YYYY-MM-DD")
    cache = gate.add_mutually_exclusive_group()
    cache.add_argument("--cache-dir", default=None)
    cache.add_argument("--no-cache", action="store_true", default=False)
    gate.add_argument(
        "--cache-mode",
        choices=("authenticated", "none", "local"),
        default=None,
        help="cache trust mode (defaults to local when --cache-dir is supplied, otherwise none)",
    )
    gate.add_argument("--allow-local-cache", action="store_true")
    gate.add_argument("--cache-read-only", action="store_true", help="never write cache entries")
    gate.add_argument("--jobs", type=int, default=1)
    gate.add_argument("--review-mode", choices=("fail", "codeowners"), default="fail")
    return parser


def _validate_cache(
    repo: Path,
    cache_dir: str | None,
    no_cache: bool,
    *,
    allow_local_cache: bool,
    cache_mode: str,
) -> tuple[str, str] | None:
    if no_cache or cache_dir is None:
        return None
    if cache_mode == "local" and not allow_local_cache:
        return (
            "invalid_cache_location",
            "local cache requires --allow-local-cache",
        )
    resolved = Path(cache_dir).expanduser().resolve(strict=False)
    root = repo.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError:
        return None
    return ("invalid_cache_location", "cache directory must be outside the working tree")


def _write_output(text: str, output: str | None) -> None:
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def _text_summary(bundle) -> str:
    payload = bundle.payload
    verdict = payload["verdict"]
    lines = [
        f"VERDICT: {verdict['status']} (exit {verdict['exit_code']})",
        f"Policy: {payload['policy']['authoritative_policy_source']} {payload['policy']['effective_policy_hash']}",
    ]
    reasons = verdict.get("reason_codes", [])
    if reasons:
        lines.append("Reasons: " + ", ".join(reasons))
    findings = payload.get("findings", [])
    if findings:
        lines.append("Findings:")
        for finding in findings:
            subject = finding.get("subject", {})
            where = subject.get("path", "")
            if subject.get("symbol"):
                where += f" {subject['symbol']}"
            lines.append(
                f"  [{finding.get('tier', '').upper()}] {finding.get('defect_id')} "
                f"({finding.get('reason_code')}) {where}: {finding.get('message')}"
            )
    waivers = payload.get("waivers", [])
    if waivers:
        lines.append("Waivers: " + ", ".join(w["id"] for w in waivers))
    assumptions = payload.get("assumptions", [])
    if assumptions:
        lines.append("Assumptions: " + ", ".join(a["id"] for a in assumptions))
    cache = bundle.envelope.get("cache", {})
    if cache.get("authoritative") is False:
        lines.append("NOTE: local cache mode; this result is non-authoritative.")
    lines.append(f"Evidence payload: {bundle.envelope.get('payload_hash')}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "gate":
        return 2
    if args.jobs < 1:
        sys.stderr.write("jobs must be >= 1\n")
        return 2

    from verifyci.evidence.sarif import bundle_to_sarif
    from verifyci.gate.orchestrator import GateRequest, run_gate

    repo = Path(args.repo)
    cache_mode = args.cache_mode or ("local" if args.cache_dir else "none")
    if args.no_cache:
        if args.cache_mode not in (None, "none"):
            sys.stderr.write("--no-cache conflicts with --cache-mode\n")
            return 2
        cache_mode = "none"
    if cache_mode == "local" and not args.allow_local_cache:
        sys.stderr.write("local cache requires --allow-local-cache\n")
        return 3
    cache_error = _validate_cache(
        repo,
        args.cache_dir,
        args.no_cache,
        allow_local_cache=args.allow_local_cache,
        cache_mode=cache_mode,
    )
    if cache_error:
        code, detail = cache_error
        sys.stderr.write(json.dumps({"error": code, "detail": detail}) + "\n")
        return 3
    cache_key: bytes | None = None
    if cache_mode == "authenticated":
        raw_key = os.environ.pop("VERIFYCI_CACHE_KEY", "")
        if len(raw_key) == 64:
            try:
                parsed_key = bytes.fromhex(raw_key)
                cache_key = parsed_key if len(parsed_key) == 32 else None
            except ValueError:
                cache_key = None
    request = GateRequest(
        repo=repo,
        base=args.base,
        head=args.head,
        merge_base=args.merge_base,
        as_of_date=args.as_of,
        review_mode=args.review_mode,
        cache_mode=cache_mode,
        allow_local_cache=args.allow_local_cache,
        cache_dir=args.cache_dir,
        cache_key=cache_key,
        cache_key_id=os.environ.pop("VERIFYCI_CACHE_KEY_ID", "k1"),
        cache_read_only=args.cache_read_only,
        jobs=args.jobs,
    )
    bundle = run_gate(request)
    if args.format == "sarif":
        text = json.dumps(bundle_to_sarif(bundle), indent=2, sort_keys=True) + "\n"
    elif args.format == "json":
        text = json.dumps(bundle.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    else:
        text = _text_summary(bundle) + "\n"
    _write_output(text, args.output)
    if args.review_mode == "codeowners" and bundle.payload.get("gate_integrity", {}).get("review_cleared"):
        return 0
    return bundle.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
