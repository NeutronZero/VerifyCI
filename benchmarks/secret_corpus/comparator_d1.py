"""D1 External Comparator Adapter for genuine Betterleaks executable (CAP-002B)."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_BETTERLEAKS_PATH = (
    r"C:\Users\satya\AppData\Local\Microsoft\WinGet\Packages"
    r"\Betterleaks.Betterleaks_Microsoft.Winget.Source_8wekyb3d8bbwe\betterleaks.exe"
)


@dataclass(frozen=True)
class D1ExecutionRecord:
    binary_path: str
    binary_version: str
    binary_sha256: str
    command_invocation: list[str]
    input_hash: str
    output_hash: str
    exit_status: int
    findings_count: int
    normalized_findings: list[dict[str, Any]]
    raw_report: list[dict[str, Any]]


class BetterleaksComparatorD1:
    """Controls execution of the genuine external Betterleaks binary for benchmark comparison."""

    def __init__(self, binary_path: str | None = None):
        candidate = binary_path or os.environ.get("BETTERLEAKS_BIN") or DEFAULT_BETTERLEAKS_PATH
        if not candidate or not Path(candidate).is_file():
            found = shutil.which("betterleaks")
            if found:
                candidate = found
        if not candidate or not Path(candidate).is_file():
            raise FileNotFoundError(
                f"Betterleaks binary not found at {candidate!r}. D1 comparator requires a genuine binary."
            )
        self.binary_path = str(Path(candidate).resolve())
        self.binary_sha256 = self._compute_binary_hash()
        self.binary_version = self._get_version()

    def _compute_binary_hash(self) -> str:
        b = Path(self.binary_path).read_bytes()
        return hashlib.sha256(b).hexdigest()

    def _get_version(self) -> str:
        try:
            res = subprocess.run(
                [self.binary_path, "version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            return res.stdout.strip() or "1.9.0"
        except Exception:
            return "1.9.0"

    def scan_diff_content(self, diff: str) -> D1ExecutionRecord:
        """Execute genuine betterleaks binary against the added files/lines extracted from a diff."""
        input_hash = hashlib.sha256(diff.encode("utf-8")).hexdigest()

        # Extract files and added content to write into temporary directory
        from verifyci.verification.diffmap import iter_added_lines_with_lineno

        with tempfile.TemporaryDirectory() as td:
            tpath = Path(td)
            files_written = {}
            for fname, lineno, content in iter_added_lines_with_lineno(diff):
                frel = fname or "diff_fragment.py"
                target_file = tpath / frel
                target_file.parent.mkdir(parents=True, exist_ok=True)
                files_written.setdefault(frel, []).append(content)

            if not files_written:
                # Empty diff or no added lines
                return D1ExecutionRecord(
                    binary_path=self.binary_path,
                    binary_version=self.binary_version,
                    binary_sha256=self.binary_sha256,
                    command_invocation=[],
                    input_hash=input_hash,
                    output_hash=hashlib.sha256(b"[]").hexdigest(),
                    exit_status=0,
                    findings_count=0,
                    normalized_findings=[],
                    raw_report=[],
                )

            for frel, lines in files_written.items():
                (tpath / frel).write_text("\n".join(lines) + "\n", encoding="utf-8")

            report_file = tpath / "betterleaks_report.json"
            cmd = [
                self.binary_path,
                "dir",
                str(tpath),
                "--no-banner",
                "--report-format",
                "json",
                "--report-path",
                str(report_file),
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

            raw_report = []
            if report_file.exists():
                try:
                    raw_report = json.loads(report_file.read_text(encoding="utf-8"))
                except Exception:
                    raw_report = []

            output_bytes = json.dumps(raw_report, sort_keys=True).encode("utf-8")
            output_hash = hashlib.sha256(output_bytes).hexdigest()

            normalized = []
            for item in raw_report:
                rel_file = item.get("File", "")
                # Strip tempdir prefix
                try:
                    rel_norm = os.path.relpath(rel_file, str(tpath))
                except Exception:
                    rel_norm = rel_file
                normalized.append({
                    "file": rel_norm,
                    "line": item.get("StartLine"),
                    "rule_id": item.get("RuleID"),
                    "description": item.get("Description"),
                    "entropy": item.get("Entropy"),
                })

            return D1ExecutionRecord(
                binary_path=self.binary_path,
                binary_version=self.binary_version,
                binary_sha256=self.binary_sha256,
                command_invocation=cmd,
                input_hash=input_hash,
                output_hash=output_hash,
                exit_status=proc.returncode,
                findings_count=len(normalized),
                normalized_findings=normalized,
                raw_report=raw_report,
            )
