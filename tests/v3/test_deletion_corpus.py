"""Independent integrity and oracle-consistency validator for the M2 deletion corpus.

This module intentionally imports only Python's standard library. It must not import,
execute, or consult the VerifyCI production check, frontend, scope, index, or gate.
The hand-authored labels in cases.jsonl remain the oracle; this validator checks their
structure and source witnesses, not mapper output.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parents[2] / "corpora" / "deletion"
CASES_FILE = ROOT / "cases.jsonl"
SUMS_FILE = ROOT / "SHA256SUMS"
VALID_OUTCOMES = {"PASS", "FAIL", "INCONCLUSIVE", "ERROR", "NOT_APPLICABLE"}
VALID_COVERAGE = {"COMPLETE", "PARTIAL", "UNKNOWN"}
DEFECT_REASON = {
    "DEL-REACHABLE-SYMBOL": "symbol_live",
    "DEL-DANGLING-REFERENCE": "dangling_reference",
    "DEL-DYNAMIC-REFERENCE": "dynamic_reference_removed",
}
REQUIRED_KINDS = {
    "unused_private_symbol",
    "public_api_policy_entry",
    "reexport_through_init",
    "rename_all_references_updated",
    "rename_with_missed_reference",
    "test_only_reference_is_live",
    "all_exports_still_names_removed_symbol",
    "typescript_default_export_still_consumed",
    "deleted_module_with_dangling_import",
    "dynamic_getattr_proven_removed_symbol",
    "computed_property_target_unresolved",
    "string_dispatch_target_unresolved",
    "generated_path_exclusion",
    "multi_file_package_reachability_and_dangling",
    "typescript_barrel_reexport",
    "entrypoint_policy_symbol",
    "unsupported_language_removal_relevant",
    "no_removed_symbols",
}


def load_cases() -> list[dict]:
    assert CASES_FILE.is_file(), f"missing {CASES_FILE}"
    rows = []
    for n, line in enumerate(CASES_FILE.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
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


def _declaration_pattern(name: str) -> re.Pattern[str]:
    quoted = re.escape(name)
    patterns = (
        rf"^\s*(?:async\s+)?def\s+{quoted}\b",
        rf"^\s*(?:(?:export|declare|default|async)\s+)*(?:function|class|interface|type|const|let|var)\s+{quoted}\b",
        rf"^\s*func\s+(?:\([^)]*\)\s*)?{quoted}\b",
    )
    return re.compile("|".join(f"(?:{p})" for p in patterns))


def _declared_in_files(files: dict, name: str) -> bool:
    pat = _declaration_pattern(name)
    return any(
        pat.search(line) for source in files.values() for line in source.splitlines()
    )


def _source_for_side(case: dict, side: str) -> dict:
    assert side in ("base", "head"), f"{case['case_id']}: invalid source side {side!r}"
    return case[f"{side}_files"]


def _check_source_coordinate(case: dict, witness: dict, label: str) -> None:
    side, path, line = witness.get("side"), witness.get("path"), witness.get("line")
    assert side in ("base", "head"), (
        f"{case['case_id']}: {label}: side must be base/head"
    )
    files = _source_for_side(case, side)
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
def test_deletion_corpus_checksum_inventory():
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
def test_deletion_cases_are_frozen_unique_and_complete():
    cases = load_cases()
    assert len(cases) == 18, f"expected 18 cases, found {len(cases)}"
    ids = [case.get("case_id") for case in cases]
    assert len(set(ids)) == len(ids), "duplicate case ID"
    assert all(isinstance(cid, str) and cid.startswith("DEL-") for cid in ids)
    assert all(c.get("status") == "frozen" for c in cases)
    assert {c.get("kind") for c in cases} == REQUIRED_KINDS
    assert all(
        "§11.3" in c.get("spec_refs", []) and "§16" in c.get("spec_refs", [])
        for c in cases
    )
    assert {f["defect_id"] for c in cases for f in c["expected"]["findings"]} == set(
        DEFECT_REASON
    )


@pytest.mark.invariant
def test_case_paths_and_removed_symbol_ground_truth():
    for case in load_cases():
        case_id = case["case_id"]
        for side in ("base_files", "head_files"):
            files = case.get(side)
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

        expected = case["expected"]
        base_files, head_files = case["base_files"], case["head_files"]
        seen_removed = set()
        for symbol in expected.get("removed_symbols", []):
            qname, path, name, line = (
                symbol.get("qname"),
                symbol.get("path"),
                symbol.get("name"),
                symbol.get("base_line"),
            )
            assert isinstance(qname, str) and qname and qname not in seen_removed
            seen_removed.add(qname)
            assert path in base_files, f"{case_id}: missing base source for {qname}"
            lines = base_files[path].splitlines()
            assert isinstance(line, int) and 1 <= line <= len(lines), (
                f"{case_id}: bad base_line for {qname}"
            )
            assert _declaration_pattern(name).search(lines[line - 1]), (
                f"{case_id}: expected removed declaration {name!r} absent at {path}:{line}"
            )
            assert not _declared_in_files(head_files, name), (
                f"{case_id}: removed declaration {name!r} still defined in head"
            )

        for finding in expected.get("findings", []):
            assert finding.get("defect_id") in DEFECT_REASON
            assert finding.get("reason_code") == DEFECT_REASON[finding["defect_id"]]
            assert finding.get("tier") == "blocking"
            assert finding.get("defect_semantics_version") == 1
            assert finding.get("disposition") == "OPEN"
            assert finding.get("evidence", {}).get("kind") == "reference"
            subject_symbol = finding.get("subject", {}).get("symbol")
            assert subject_symbol in seen_removed, (
                f"{case_id}: finding symbol is not a removed symbol"
            )
            witness = finding.get("witness", {})
            _check_source_coordinate(case, witness, "finding witness")
            payload = finding["evidence"]["payload"]
            assert payload.get("removed", {}).get("qname") == subject_symbol
            ref = payload.get("reference", {})
            for key in ("kind", "path", "line", "token"):
                assert ref.get(key) == witness.get(key), (
                    f"{case_id}: evidence reference mismatch on {key}"
                )

        for witness in expected.get("gap_witnesses", []):
            _check_source_coordinate(case, witness, "coverage-gap witness")


@pytest.mark.invariant
def test_outcome_coverage_and_applicability_contract():
    for case in load_cases():
        exp = case["expected"]
        outcome, coverage = exp["outcome"], exp["coverage"]
        assert outcome in VALID_OUTCOMES, (
            f"{case['case_id']}: invalid outcome {outcome}"
        )
        assert coverage in VALID_COVERAGE, (
            f"{case['case_id']}: invalid coverage {coverage}"
        )
        findings = exp.get("findings", [])
        reasons = set(exp.get("reason_codes", []))
        removed = exp.get("removed_symbols", [])

        if outcome == "PASS":
            assert coverage == "COMPLETE" and not findings and not reasons
            assert removed, f"{case['case_id']}: PASS must exercise a deletion"
        elif outcome == "FAIL":
            assert findings, f"{case['case_id']}: FAIL requires a blocking finding"
            assert coverage in ("COMPLETE", "PARTIAL")
        elif outcome == "INCONCLUSIVE":
            assert not findings, (
                f"{case['case_id']}: unresolved scope alone must not invent finding"
            )
            assert coverage in ("PARTIAL", "UNKNOWN")
            if "dynamic_target_unresolved" in reasons:
                assert coverage == "PARTIAL"
            if "unsupported_language" in reasons:
                assert coverage == "UNKNOWN"
        elif outcome == "NOT_APPLICABLE":
            assert coverage == "COMPLETE" and not findings
            policy = case.get("policy", {})
            excluded = policy.get("excluded_paths", [])
            paths = [item["path"] for item in removed]
            evidence = exp.get("applicability_evidence", {})
            assert "removed_symbols" in evidence
            if removed:
                assert paths and all(
                    any(fnmatch.fnmatchcase(path, pattern) for pattern in excluded)
                    for path in paths
                ), f"{case['case_id']}: removed symbols are not all excluded"
                assert sorted(evidence.get("excluded_paths", [])) == sorted(paths)
            else:
                assert evidence.get("inspected_paths"), (
                    f"{case['case_id']}: no-removal NOT_APPLICABLE requires inspected-scope evidence"
                )

    by_kind = {case["kind"]: case for case in load_cases()}
    assert (
        by_kind["dynamic_getattr_proven_removed_symbol"]["expected"]["outcome"]
        == "FAIL"
    )
    for kind in (
        "computed_property_target_unresolved",
        "string_dispatch_target_unresolved",
    ):
        exp = by_kind[kind]["expected"]
        assert exp["outcome"] == "INCONCLUSIVE"
        assert exp["coverage"] == "PARTIAL"
        assert "dynamic_target_unresolved" in exp["reason_codes"]
