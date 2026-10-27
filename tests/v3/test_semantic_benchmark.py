"""Corpus-backed benchmark and evaluation test suite for VerifyCI M4 Semantic check.

Evaluates the production semantic check (verifyci.checks.semantic) against the
frozen 18-case semantic corpus (corpora/semantic/cases.jsonl) to establish:
1. Exact outcome, coverage, and reason-code agreement across all 18 cases.
2. Perfect precision (1.00) and recall (1.00) across all declared defect types:
   - SEM-GUARD-REMOVED (guard_removed)
   - SEM-GUARD-WEAKENED (guard_weakened)
   - SEM-GUARD-INVERTED (guard_inverted)
   - SEM-BINDING-SWAP (binding_swap)
   - SEM-EXCEPTION-REMOVED (exception_removed)
3. Normative fail-closed handling for dynamic calls, unknown decorators, and unsupported language:
   - dynamic_call -> Outcome.INCONCLUSIVE, Coverage.PARTIAL
   - unknown_decorator -> Outcome.INCONCLUSIVE, Coverage.PARTIAL
   - unsupported_language -> Outcome.INCONCLUSIVE, Coverage.UNKNOWN
4. Complete applicability evidence for negative/unmodified/comment-only controls:
   - Outcome.NOT_APPLICABLE, Coverage.COMPLETE
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from verifyci.checks.base import CheckContext
from verifyci.checks.semantic import run as run_semantic
from verifyci.contracts.model import CheckResult
from verifyci.gate.orchestrator import _augment_scope_with_repository
from verifyci.gate.policy import parse_policy_bytes
from verifyci.scm.git import GitRepo
from verifyci.scope.entities import build_changed_scope

CORPUS_ROOT = Path("corpora/semantic")
CASES_FILE = CORPUS_ROOT / "cases.jsonl"


def load_semantic_cases() -> list[dict]:
    assert CASES_FILE.is_file(), f"missing {CASES_FILE}"
    cases = []
    for line in CASES_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            cases.append(json.loads(line))
    return cases


def _build_case_repo(case: dict, target_dir: Path) -> tuple[GitRepo, str, str, str]:
    repo_dir = target_dir / case["case_id"]
    if repo_dir.exists():
        shutil.rmtree(repo_dir)
    repo_dir.mkdir(parents=True)

    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(repo_dir)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.name", "TestRunner"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.email", "test@verifyci.dev"],
        check=True,
        capture_output=True,
    )

    for rel_path, content in case["base_files"].items():
        file_path = repo_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8", newline="")

    subprocess.run(
        ["git", "-C", str(repo_dir), "add", "-A"], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "-q", "-m", "base"],
        check=True,
        capture_output=True,
    )
    base_commit = subprocess.check_output(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True
    ).strip()

    for item in repo_dir.iterdir():
        if item.name != ".git":
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

    for rel_path, content in case["head_files"].items():
        file_path = repo_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8", newline="")

    subprocess.run(
        ["git", "-C", str(repo_dir), "add", "-A"], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "-q", "-m", "head", "--allow-empty"],
        check=True,
        capture_output=True,
    )
    head_commit = subprocess.check_output(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True
    ).strip()

    return GitRepo(repo_dir), base_commit, base_commit, head_commit


def _execute_case(case: dict, tmp_path: Path) -> CheckResult:
    repo, base, mb, head = _build_case_repo(case, tmp_path)
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(
        scope, git=repo, base_rev=base, head_rev=head, source_roots=()
    )

    base_policy = parse_policy_bytes(b"")
    policy = dataclasses.replace(
        base_policy,
        protected_guards=case.get("policy", {}).get("protected_guards", {}),
        protected_errors=case.get("policy", {}).get("protected_errors", {}),
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    return run_semantic(ctx)


@pytest.mark.invariant
def test_semantic_check_empirical_benchmark(tmp_path: Path):
    cases = load_semantic_cases()
    assert len(cases) == 18, f"expected 18 cases, got {len(cases)}"

    outcome_matches = 0
    coverage_matches = 0
    reason_matches = 0
    findings_matches = 0
    discrepancies: list[str] = []

    defects = [
        "SEM-GUARD-REMOVED",
        "SEM-GUARD-WEAKENED",
        "SEM-GUARD-INVERTED",
        "SEM-BINDING-SWAP",
        "SEM-EXCEPTION-REMOVED",
    ]
    confusion = {d: {"TP": 0, "FP": 0, "FN": 0, "TN": 0} for d in defects}

    for case in cases:
        cid = case["case_id"]
        exp = case["expected"]
        res = _execute_case(case, tmp_path)

        if res.outcome.value == exp["outcome"]:
            outcome_matches += 1
        else:
            discrepancies.append(
                f"{cid}: outcome {res.outcome.value} != {exp['outcome']}"
            )

        if res.coverage.value == exp["coverage"]:
            coverage_matches += 1
        else:
            discrepancies.append(
                f"{cid}: coverage {res.coverage.value} != {exp['coverage']}"
            )

        got_rc = sorted(res.reason_codes)
        exp_rc = sorted(exp.get("reason_codes", []))
        if got_rc == exp_rc:
            reason_matches += 1
        else:
            discrepancies.append(f"{cid}: reason codes {got_rc} != {exp_rc}")

        got_findings = sorted(f.defect_id for f in res.findings)
        exp_findings = sorted(f["defect_id"] for f in exp.get("findings", []))
        if got_findings == exp_findings:
            findings_matches += 1
        else:
            discrepancies.append(f"{cid}: findings {got_findings} != {exp_findings}")

        got_def_set = set(got_findings)
        exp_def_set = set(exp_findings)
        for did in defects:
            in_got = did in got_def_set
            in_exp = did in exp_def_set
            if in_got and in_exp:
                confusion[did]["TP"] += 1
            elif in_got and not in_exp:
                confusion[did]["FP"] += 1
            elif not in_got and in_exp:
                confusion[did]["FN"] += 1
            else:
                confusion[did]["TN"] += 1

    print("\n" + "=" * 60)
    print("M4 SEMANTIC CHECK EMPIRICAL BENCHMARK REPORT")
    print("=" * 60)
    print(f"Total Cases Evaluated:         {len(cases)}/18 (100.0%)")
    print(
        f"Outcome Agreement:             {outcome_matches}/{len(cases)} ({(outcome_matches / len(cases)) * 100:.1f}%)"
    )
    print(
        f"Coverage Agreement:            {coverage_matches}/{len(cases)} ({(coverage_matches / len(cases)) * 100:.1f}%)"
    )
    print(
        f"Reason Code Agreement:         {reason_matches}/{len(cases)} ({(reason_matches / len(cases)) * 100:.1f}%)"
    )
    print(
        f"Defect ID Matches:             {findings_matches}/{len(cases)} ({(findings_matches / len(cases)) * 100:.1f}%)"
    )
    print("-" * 60)
    print("Confusion Matrix per Defect ID:")
    for did in defects:
        c = confusion[did]
        tp, fp, fn, tn = c["TP"], c["FP"], c["FN"], c["TN"]
        prec = 1.0 if (tp + fp == 0) else tp / (tp + fp)
        rec = 1.0 if (tp + fn == 0) else tp / (tp + fn)
        print(
            f"  {did:<24} TP={tp:<2} FP={fp:<2} FN={fn:<2} TN={tn:<2} | Prec={prec:.2f} Rec={rec:.2f}"
        )
    print("=" * 60)

    if discrepancies:
        pytest.fail(
            "Benchmark discrepancies encountered:\n" + "\n".join(discrepancies[:10])
        )

    assert outcome_matches == 18
    assert coverage_matches == 18
    assert reason_matches == 18
    assert findings_matches == 18
    for did in defects:
        assert confusion[did]["FP"] == 0, f"{did} produced false positives"
        assert confusion[did]["FN"] == 0, f"{did} produced false negatives"
