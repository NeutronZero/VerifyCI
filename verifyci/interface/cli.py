"""Modern, lightweight CLI for VerifyCI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from verifyci import __version__
from verifyci.contracts.verdict import VerificationVerdict
from verifyci.core.diff_parser import DiffFileEntry, parse_unified_diff
from verifyci.core.engine import VerificationKernel
from verifyci.extensions.protocols import DictBaseSourceProvider
from verifyci.extensions.z3_adapter import Z3ProverAdapter
from verifyci.interface.sarif_exporter import certificate_to_sarif


def _format_text_summary(cert) -> str:
    verdict = cert.verdict.value
    files_str = ", ".join(cert.payload.files) or "none"
    lines = [
        f"VERDICT: {verdict}",
        f"Digest: {cert.digest[:16]}... ({cert.digest_algorithm})",
        f"Rationale: {cert.rationale}",
        f"Files: {files_str}",
    ]
    if cert.payload.findings:
        lines.append("\nFindings:")
        for f in cert.payload.findings:
            lines.append(
                f"  [{f.verdict.value}] {f.rule_id} ({f.reason.value}) at {f.file_path}:{f.start_line} - {f.message}"
            )
    return "\n".join(lines)


def run_verify_diff(args: argparse.Namespace) -> int:
    """Verify a unified diff file against invariants and safety gates."""
    diff_path = Path(args.diff_file)
    if not diff_path.is_file():
        sys.stderr.write(f"Error: diff file '{args.diff_file}' does not exist\n")
        return 3

    try:
        diff_text = diff_path.read_text(encoding="utf-8")
    except Exception as exc:
        sys.stderr.write(f"Error reading diff file: {exc}\n")
        return 3

    entries = parse_unified_diff(diff_text)
    if not entries:
        sys.stderr.write("Notice: diff contains no file changes.\n")

    base_sources: dict[str, str] = {}
    if args.base_dir:
        base_dir = Path(args.base_dir)
        for entry in entries:
            target_path = base_dir / entry.old_file_path
            if target_path.is_file():
                try:
                    base_sources[entry.file_path] = target_path.read_text(encoding="utf-8")
                except Exception:
                    pass

    extension_checkers = []
    if args.with_prover:
        prover = Z3ProverAdapter(default_timeout_ms=args.timeout)

        def prover_checker(entry: DiffFileEntry, base_srcs: Any) -> list[Any]:
            base_src = base_srcs.get(entry.file_path, "")
            if not base_src:
                return []
            results = prover.prove_function_diff(
                entry.file_path, base_src, entry.head_source, timeout_ms=args.timeout
            )
            findings = []
            for r in results:
                findings.extend(r.findings)
            return findings

        extension_checkers.append(prover_checker)

    kernel = VerificationKernel(
        base_sources=base_sources,
        extension_checkers=extension_checkers,
    )

    cert = kernel.verify_entries(entries)

    # Output formatting
    output_fmt = args.format.lower()
    if output_fmt == "json":
        rendered = json.dumps(cert.to_dict(), indent=2)
    elif output_fmt == "sarif":
        rendered = json.dumps(certificate_to_sarif(cert), indent=2)
    else:
        rendered = _format_text_summary(cert)

    if args.output:
        try:
            Path(args.output).write_text(rendered, encoding="utf-8")
        except Exception as exc:
            sys.stderr.write(f"Error writing output file: {exc}\n")
            return 3
    else:
        print(rendered)

    if cert.verdict == VerificationVerdict.FAIL:
        return 1
    elif cert.verdict == VerificationVerdict.INCONCLUSIVE:
        return 2
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verifyci",
        description="VerifyCI: Deterministic, local-first code verification engine",
    )
    parser.add_argument("--version", action="version", version=f"VerifyCI {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # verify-diff
    vd_parser = subparsers.add_parser("verify-diff", help="Verify diff against invariants")
    vd_parser.add_argument("--diff-file", "-d", required=True, help="Path to unified diff patch file")
    vd_parser.add_argument(
        "--format", "-f", choices=["text", "json", "sarif"], default="text", help="Output format"
    )
    vd_parser.add_argument("--output", "-o", help="Write report to output file")
    vd_parser.add_argument("--base-dir", help="Directory containing base revision files")
    vd_parser.add_argument("--with-prover", action="store_true", help="Enable formal Z3 SMT prover")
    vd_parser.add_argument("--timeout", type=int, default=3000, help="SMT solver timeout in milliseconds")

    # version
    subparsers.add_parser("version", help="Print version")

    args = parser.parse_args(argv)

    if args.subcommand == "verify-diff":
        return run_verify_diff(args)
    elif args.subcommand == "version":
        print(f"VerifyCI {__version__}")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
