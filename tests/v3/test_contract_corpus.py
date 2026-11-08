"""Independent integrity and oracle-consistency validator for the M3 contract corpus.

This module intentionally imports only Python's standard library. It must not import,
execute, or consult the VerifyCI production check, frontend, scope, index, or gate.
The hand-authored labels in cases.jsonl remain the oracle; this validator checks their
structure, source coordinates, and AST syntax, not mapper output.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

import pytest

ROOT = Path(__file__).resolve().parents[2] / "corpora" / "contract"
CASES_FILE = ROOT / "cases.jsonl"
SUMS_FILE = ROOT / "SHA256SUMS"

VALID_OUTCOMES = {"PASS", "FAIL", "INCONCLUSIVE", "ERROR", "NOT_APPLICABLE"}
VALID_COVERAGE = {"COMPLETE", "PARTIAL", "UNKNOWN"}

DEFECT_REASON = {
    "CTR-SIGNATURE-BREAK": "signature_break",
    "CTR-EXPORT-BREAK": "export_break",
    "CTR-CALL-INCOMPATIBLE": "call_incompatible",
}

ALLOWED_EVIDENCE_KINDS = {"call_site", "reference"}


def load_cases() -> list[dict]:
    assert CASES_FILE.is_file(), f"missing {CASES_FILE}"
    rows = []
    for n, line in enumerate(CASES_FILE.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            pytest.fail(f"cases.jsonl:{n}: invalid JSON: {exc}")
    return rows


def _valid_repo_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and not path.is_absolute()
        and "\\" not in value
        and all(part not in ("", ".", "..") for part in path.parts)
    )


def _check_source_coordinate(case: dict, witness: dict, label: str) -> None:
    side, path, line = witness.get("side"), witness.get("path"), witness.get("line")
    assert side in ("base", "head"), (
        f"{case['case_id']}: {label}: side must be base/head"
    )
    files = case[f"{side}_files"]
    assert path in files, f"{case['case_id']}: {label}: {side} path {path!r} absent"
    assert isinstance(line, int) and not isinstance(line, bool) and line >= 1, (
        f"{case['case_id']}: {label}: line must be one-indexed integer"
    )
    lines = files[path].splitlines()
    assert line <= len(lines), f"{case['case_id']}: {label}: line {line} outside {path}"
    token = witness.get("token")
    assert isinstance(token, str) and token, (
        f"{case['case_id']}: {label}: missing token"
    )
    assert token in lines[line - 1], (
        f"{case['case_id']}: {label}: token {token!r} absent at {path}:{line}"
    )


@pytest.mark.invariant
def test_contract_corpus_checksum_inventory():
    assert SUMS_FILE.is_file(), "SHA256SUMS missing"
    recorded = {}
    for row in SUMS_FILE.read_text(encoding="utf-8").splitlines():
        if not row.strip():
            continue
        digest, rel = row.split("  ", 1)
        assert re.fullmatch(r"[0-9a-f]{64}", digest), f"invalid digest for {rel}"
        assert rel not in recorded, f"duplicate inventory path: {rel}"
        recorded[rel] = digest

    actual = {
        p.relative_to(ROOT).as_posix()
        for p in ROOT.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS"
    }
    assert set(recorded) == actual, (
        f"inventory mismatch; missing={sorted(actual - set(recorded))}, "
        f"stale={sorted(set(recorded) - actual)}"
    )
    for rel, expected in recorded.items():
        got = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
        assert got == expected, f"digest drift: {rel}: {got} != {expected}"


@pytest.mark.invariant
def test_contract_cases_are_frozen_unique_and_complete():
    cases = load_cases()
    assert len(cases) == 17, f"expected 17 cases, found {len(cases)}"
    ids = [case.get("case_id") for case in cases]
    assert len(set(ids)) == len(ids), "duplicate case ID"
    assert all(isinstance(cid, str) and cid.startswith("CTR-") for cid in ids)
    assert all(c.get("status") == "frozen" for c in cases)
    assert all(
        "§11.4" in c.get("spec_refs", []) and "§16" in c.get("spec_refs", [])
        for c in cases
    )
    defect_ids = {
        f["defect_id"] for c in cases for f in c["expected"].get("findings", [])
    }
    assert defect_ids == set(DEFECT_REASON), f"defect IDs mismatch: {defect_ids}"


@pytest.mark.invariant
def test_contract_case_paths_and_ground_truth():
    for case in load_cases():
        case_id = case["case_id"]
        for side in ("base_files", "head_files"):
            files = case.get(side, {})
            assert isinstance(files, dict) and files, (
                f"{case_id}: {side} must be non-empty mapping"
            )
            for path, source in files.items():
                assert _valid_repo_path(path), (
                    f"{case_id}: unsafe fixture path {path!r}"
                )
                assert isinstance(source, str), (
                    f"{case_id}: source for {path} must be text"
                )
                if path.endswith(".py"):
                    try:
                        ast.parse(source)
                    except SyntaxError as exc:
                        pytest.fail(
                            f"{case_id}: {side} file {path} has syntax error: {exc}"
                        )

        expected = case["expected"]
        for finding in expected.get("findings", []):
            did = finding.get("defect_id")
            assert did in DEFECT_REASON, f"{case_id}: unknown defect {did}"
            assert finding.get("reason_code") == DEFECT_REASON[did]
            assert finding.get("tier") == "blocking"
            assert finding.get("defect_semantics_version") == 1
            assert finding.get("disposition") == "OPEN"
            ekind = finding.get("evidence", {}).get("kind")
            assert ekind in ALLOWED_EVIDENCE_KINDS, (
                f"{case_id}: invalid evidence kind {ekind}"
            )
            witness = finding.get("witness", {})
            _check_source_coordinate(case, witness, "finding witness")

        for gap in expected.get("coverage_gaps", []):
            if isinstance(gap, dict) and "line" in gap:
                _check_source_coordinate(case, {"side": "head", **gap}, "coverage gap")


@pytest.mark.invariant
def test_contract_outcome_coverage_and_applicability():
    for case in load_cases():
        cid = case["case_id"]
        exp = case["expected"]
        outcome, coverage = exp["outcome"], exp["coverage"]
        assert outcome in VALID_OUTCOMES, f"{cid}: invalid outcome {outcome}"
        assert coverage in VALID_COVERAGE, f"{cid}: invalid coverage {coverage}"
        findings = exp.get("findings", [])
        reasons = set(exp.get("reason_codes", []))

        if outcome == "PASS":
            assert coverage == "COMPLETE"
            assert not findings, f"{cid}: PASS cannot carry findings"
            assert not reasons, f"{cid}: PASS cannot carry error/gap reasons"
        elif outcome == "FAIL":
            assert findings, f"{cid}: FAIL must carry at least one finding"
            assert coverage in ("COMPLETE", "PARTIAL")
        elif outcome == "INCONCLUSIVE":
            assert not findings, f"{cid}: INCONCLUSIVE alone cannot invent findings"
            assert coverage in ("PARTIAL", "UNKNOWN")
            assert reasons, f"{cid}: INCONCLUSIVE must record reason codes"
        elif outcome == "NOT_APPLICABLE":
            assert coverage == "COMPLETE"
            assert not findings, f"{cid}: NOT_APPLICABLE cannot carry findings"
            assert not reasons
