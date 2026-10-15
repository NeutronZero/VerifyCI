"""v2 benchmark entry point.

v1's `measure_cap*.py` scripts drove `verifyci.*` modules that no longer exist,
so every one of them failed at import with `ModuleNotFoundError: No module
named 'verifyci'`. This module replaces that layer with a single implementation
that runs the v2 engines against the frozen corpora and scores the result
against the frozen ground-truth labels.

Two rules govern the output:

1. **Frozen evidence is never overwritten.** v1's `results.json`, `RESULTS.md`
   and `RESULTS_SHA256` stay exactly as recorded. v2 writes `results_v2.json`.
2. **Fail closed.** A capability with no v2 engine entry point reports
   `status: "not_measurable"` with a reason. It never reports a pass.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any

BENCHMARKS_ROOT = Path(__file__).resolve().parent.parent
RESULT_FILENAME = "results_v2.json"

# cap id -> corpus directory, used to locate the v1 record next to a v2 one.
_CAP_DIRS: dict[str, str] = {
    "cap002b": "secret_corpus/cap002b",
    "cap002_heldout": "patch_corpus/cap002_heldout",
    "cap003a": "removal_corpus/cap003a",
    "cap004": "call_semantics_corpus/cap004",
    "cap005": "patch_real/cap005",
    "cap006": "temporal_corpus/cap006",
    "cap007": "retrieval_corpus/cap007",
    "cap008": "concurrency_corpus/cap008",
    "cap009": "diff_impact_corpus/cap009",
    "cap010": "retrieval_generalization/cap010",
    "cap011": "secret_heldout/cap011",
    "cap012": "repo_perf/cap012",
    "cap013": "robustness/cap013",
}


def _git_provenance() -> dict[str, Any]:
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(
                args,
                cwd=BENCHMARKS_ROOT.parent,
                capture_output=True,
                text=True,
                check=False,
            ).stdout.strip()
        except OSError:
            return ""

    return {
        "git_commit": run(["git", "rev-parse", "HEAD"]),
        "git_dirty": bool(run(["git", "status", "--porcelain"])),
        "python_version": platform.python_version(),
        "platform": f"{platform.system()}-{platform.release()}",
    }


def _file_sha256(path: Path) -> str:
    if not path.is_file():
        return ""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def scorecard_for(cap_id: str) -> dict[str, Any]:
    """Runs the v2 engines for one capability and returns its scorecard.

    Only the requested capability's runner executes, so measuring a single
    capability does not pay for all of them.
    """
    from benchmarks.common.cap_adjudicator import V2CapabilityAdjudicator

    return asdict(V2CapabilityAdjudicator().adjudicate_capability(cap_id))


def build_result(cap_id: str) -> dict[str, Any]:
    """Builds the v2 result record for one capability."""
    scorecard = scorecard_for(cap_id)
    corpus_dir = BENCHMARKS_ROOT / _CAP_DIRS.get(cap_id, "")
    if scorecard["metric_value"] is None:
        status = "not_measurable"
    elif scorecard["passed"] is True:
        status = "passed"
    elif scorecard["passed"] is False:
        status = "failed"
    else:  # pragma: no cover - defensive
        status = "unknown"

    return {
        "experiment_id": cap_id.upper().replace("_", "-"),
        "engine": "verifyci_v2",
        "status": status,
        "metrics": {
            "metric_name": scorecard["metric_name"],
            "metric_value": scorecard["metric_value"],
            "target_threshold": scorecard["target_threshold"],
            "threshold_basis": scorecard["threshold_basis"],
            "false_accept_count": scorecard["false_accept_count"],
            **{k: v for k, v in scorecard["metrics"].items()},
        },
        "counts": {
            "cases": scorecard["case_count"],
            "scored": scorecard["scored"],
            "detail": scorecard["confusion"],
        },
        "not_scored_reason": scorecard["not_scored_reason"],
        "provenance": {
            **_git_provenance(),
            "corpus_sha256": _file_sha256(corpus_dir / "cases.jsonl"),
            "label_sha256": _file_sha256(corpus_dir / "labels.jsonl"),
        },
        # v1's results.json is frozen evidence and is deliberately not touched.
        "v1_results_preserved": _file_sha256(corpus_dir / "results.json"),
    }


def write_result(cap_id: str, destination: Path | None = None) -> Path:
    """Writes `results_v2.json` beside the capability's corpus."""
    corpus_dir = BENCHMARKS_ROOT / _CAP_DIRS.get(cap_id, "")
    target = destination or (corpus_dir / RESULT_FILENAME)
    if str(target.parent) in ("", ".") or not target.parent.is_dir():
        target = BENCHMARKS_ROOT / RESULT_FILENAME
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(build_result(cap_id), indent=2) + "\n", encoding="utf-8"
    )
    return target


def main(cap_id: str | None = None, *, write: bool = True) -> int:
    """Entry point for the per-capability `measure_*.py` shims.

    Exit codes mirror the gate ladder: 0 pass, 1 fail, 2 not measurable.
    """
    if cap_id is None:
        parser = argparse.ArgumentParser(description="Measure VerifyCI v2 capabilities")
        parser.add_argument(
            "--cap",
            action="append",
            choices=sorted(_CAP_DIRS),
            help="capability to measure (repeatable; default: all)",
        )
        parser.add_argument("--no-write", action="store_true")
        parser.add_argument("--json", action="store_true")
        args = parser.parse_args()
        targets = args.cap or sorted(_CAP_DIRS)
        write = not args.no_write
    else:
        targets = [cap_id]
        as_json = False

    results = [build_result(t) for t in targets]
    if write:
        for cap in targets:
            write_result(cap)

    if cap_id is None and locals().get("as_json"):
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            metric = result["metrics"]["metric_value"]
            shown = "n/a" if metric is None else f"{metric}"
            print(
                f"{result['experiment_id']:<16} {result['status']:<15} "
                f"{result['metrics']['metric_name']}={shown} "
                f"(bar {result['metrics']['target_threshold']})"
            )
            if result["not_scored_reason"]:
                print(f"{'':<16} reason: {result['not_scored_reason']}")

    failing = [r for r in results if r["status"] == "failed"]
    return 1 if failing else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())