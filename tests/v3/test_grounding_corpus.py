"""Corpus-first grounding test suite and independent oracle validator.

Enforces zero hash drift, unique IDs, reason code bijection, span integrity,
git blob identity, and fail-closed grounding invariants.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from verifyci.contracts.model import Coverage, Outcome
from verifyci.contracts.reason_codes import ALL_CODES, validate_finding_triple
from verifyci.gate.policy import parse_policy_bytes


CORPUS_ROOT = Path("corpora/grounding")
CASES_FILE = CORPUS_ROOT / "cases.jsonl"
SUMS_FILE = CORPUS_ROOT / "SHA256SUMS"


def _git_hash_object(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def load_cases() -> list[dict]:
    assert CASES_FILE.exists(), f"Missing {CASES_FILE}"
    cases = []
    with CASES_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


@pytest.mark.invariant
def test_corpus_checksum_inventory():
    """Verify zero hash drift across every fixture, policy, and label file."""
    assert SUMS_FILE.exists(), "SHA256SUMS missing from grounding corpus"
    recorded = {}
    with SUMS_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                digest, rel_path = line.split("  ", 1)
                recorded[rel_path] = digest

    actual_files = set()
    for p in CORPUS_ROOT.rglob("*"):
        if p.is_file() and p.name != "SHA256SUMS":
            rel = p.relative_to(CORPUS_ROOT).as_posix()
            actual_files.add(rel)
            assert rel in recorded, f"Untracked corpus file: {rel}"
            actual_digest = hashlib.sha256(p.read_bytes()).hexdigest()
            assert actual_digest == recorded[rel], f"Hash mismatch for {rel}"

    missing = set(recorded) - actual_files
    assert not missing, f"Missing corpus files recorded in SHA256SUMS: {missing}"


@pytest.mark.invariant
def test_case_ids_unique_and_frozen():
    """Verify all case IDs are unique, validly formatted, and marked frozen."""
    cases = load_cases()
    assert len(cases) >= 20, f"Expected at least 20 cases, found {len(cases)}"
    seen_ids = set()
    for case in cases:
        case_id = case["case_id"]
        assert case_id not in seen_ids, f"Duplicate case ID: {case_id}"
        seen_ids.add(case_id)
        assert case_id.startswith("GRD-"), f"Invalid case ID prefix: {case_id}"
        assert case["status"] == "frozen", f"Case {case_id} not marked frozen"
        assert "kind" in case
        assert "language" in case
        assert "spec_refs" in case and len(case["spec_refs"]) > 0


@pytest.mark.invariant
def test_cases_schema_and_enums():
    """Verify outcome and coverage match normative model enums."""
    valid_outcomes = {o.value for o in Outcome}
    valid_coverages = {c.value for c in Coverage}

    for case in load_cases():
        case_id = case["case_id"]
        expected = case["expected"]
        outcome = expected["outcome"]
        coverage = expected["coverage"]
        assert outcome in valid_outcomes, f"{case_id}: unknown outcome {outcome}"
        assert coverage in valid_coverages, f"{case_id}: unknown coverage {coverage}"

        # Spec Invariant 1: No PASS with incomplete relevant coverage
        if outcome == Outcome.PASS.value:
            assert coverage == Coverage.COMPLETE.value, (
                f"{case_id}: PASS requires COMPLETE coverage, got {coverage}"
            )


@pytest.mark.invariant
def test_reason_codes_are_valid():
    """Verify all expected reason codes belong to the normative reason codes registry."""
    for case in load_cases():
        case_id = case["case_id"]
        for code in case["expected"].get("reason_codes", []):
            assert code in ALL_CODES, f"{case_id}: unknown reason code {code}"


@pytest.mark.invariant
def test_findings_conform_to_contract():
    """Verify findings conform to GRD-UNGROUNDED-EDIT and pass validate_finding_triple."""
    for case in load_cases():
        case_id = case["case_id"]
        findings = case["expected"].get("findings", [])
        if case["expected"]["outcome"] == Outcome.FAIL.value:
            assert len(findings) > 0, f"{case_id}: FAIL outcome must record blocking finding"
            for finding in findings:
                assert finding["tier"] == "tier1_blocking"
                assert finding["defect_id"] == "GRD-UNGROUNDED-EDIT"
                assert finding["reason_code"] == "policy_prohibited"
                assert finding["defect_semantics_version"] == "3.1.10"
                assert "subject" in finding
                evidence = finding["evidence"]
                assert evidence["kind"] == "provenance"
                payload = evidence["payload"]
                assert "primary_rule_id" in payload
                assert "matched_rule_ids" in payload
                assert payload["primary_rule_id"] in payload["matched_rule_ids"]
                assert validate_finding_triple(
                    finding["defect_id"],
                    finding["reason_code"],
                    evidence["kind"],
                )
        else:
            assert len(findings) == 0, f"{case_id}: non-FAIL outcome must have no findings"


@pytest.mark.invariant
def test_fixture_policy_schema_conformance():
    """Verify all policy fixtures parse without error according to policy schema."""
    for case in load_cases():
        case_id = case["case_id"]
        policy_rel = case.get("policy")
        if not policy_rel:
            continue
        policy_path = CORPUS_ROOT / policy_rel
        assert policy_path.exists(), f"{case_id}: missing policy file {policy_path}"
        policy = parse_policy_bytes(policy_path.read_bytes())
        assert policy is not None


@pytest.mark.invariant
def test_span_slice_integrity():
    """Verify exact byte offsets match file length and slice cleanly."""
    for case in load_cases():
        case_id = case["case_id"]
        expected = case["expected"]
        entities = expected.get("entities", [])
        for ent in entities:
            qname = ent["qname"]
            # Check base span
            if ent.get("base_span") is not None and case.get("base_files"):
                base_file = CORPUS_ROOT / case["base_files"][0]
                base_bytes = base_file.read_bytes()
                span = ent["base_span"]
                assert 0 <= span["start_byte"] < span["end_byte"] <= len(base_bytes), (
                    f"{case_id} {qname}: invalid base byte bounds"
                )
                slice_bytes = base_bytes[span["start_byte"]:span["end_byte"]]
                assert slice_bytes.decode("utf-8", "replace"), (
                    f"{case_id} {qname}: base slice is empty or invalid"
                )

            # Check head span
            if ent.get("head_span") is not None and case.get("head_files"):
                head_file = CORPUS_ROOT / case["head_files"][0]
                head_bytes = head_file.read_bytes()
                span = ent["head_span"]
                assert 0 <= span["start_byte"] < span["end_byte"] <= len(head_bytes), (
                    f"{case_id} {qname}: invalid head byte bounds"
                )
                slice_bytes = head_bytes[span["start_byte"]:span["end_byte"]]
                assert slice_bytes.decode("utf-8", "replace"), (
                    f"{case_id} {qname}: head slice is empty or invalid"
                )


@pytest.mark.invariant
def test_git_blob_identity_accuracy():
    """Verify git blob IDs in oracle match git plumbing calculation."""
    for case in load_cases():
        case_id = case["case_id"]
        for ent in case["expected"].get("entities", []):
            if ent.get("base_blob") and case.get("base_files"):
                base_bytes = (CORPUS_ROOT / case["base_files"][0]).read_bytes()
                expected_blob = _git_hash_object(base_bytes)
                assert ent["base_blob"] == expected_blob, (
                    f"{case_id} {ent['qname']}: base_blob mismatch: {ent['base_blob']} != {expected_blob}"
                )
            if ent.get("head_blob") and case.get("head_files"):
                head_bytes = (CORPUS_ROOT / case["head_files"][0]).read_bytes()
                expected_blob = _git_hash_object(head_bytes)
                assert ent["head_blob"] == expected_blob, (
                    f"{case_id} {ent['qname']}: head_blob mismatch: {ent['head_blob']} != {expected_blob}"
                )


@pytest.mark.invariant
def test_fail_closed_grounding_invariants():
    """Verify §9.2 and §15 fail-closed semantics across all case classes."""
    cases_by_id = {c["case_id"]: c for c in load_cases()}

    # 1. Syntax error in supported language produces INCONCLUSIVE (parse_error), NOT ERROR
    parse_case = cases_by_id["GRD-PARSE-001"]
    assert parse_case["expected"]["outcome"] == Outcome.INCONCLUSIVE.value
    assert parse_case["expected"]["coverage"] == Coverage.PARTIAL.value
    assert "parse_error" in parse_case["expected"]["reason_codes"]

    # 2. Unmapped change produces INCONCLUSIVE (mapping_unresolved), NOT ERROR or PASS
    unmapped_case = cases_by_id["GRD-UNMAPPED-001"]
    assert unmapped_case["expected"]["outcome"] == Outcome.INCONCLUSIVE.value
    assert unmapped_case["expected"]["coverage"] == Coverage.PARTIAL.value
    assert "mapping_unresolved" in unmapped_case["expected"]["reason_codes"]

    # 3. Ambiguous symbol rule produces INCONCLUSIVE (mapping_unresolved)
    ambig_case = cases_by_id["GRD-POLICY-003"]
    assert ambig_case["expected"]["outcome"] == Outcome.INCONCLUSIVE.value
    assert ambig_case["expected"]["coverage"] == Coverage.PARTIAL.value
    assert "mapping_unresolved" in ambig_case["expected"]["reason_codes"]

    # 4. Integrity error produces ERROR (provenance_integrity_error)
    int_case = cases_by_id["GRD-INT-001"]
    assert int_case["expected"]["outcome"] == Outcome.ERROR.value
    assert int_case["expected"]["coverage"] == Coverage.UNKNOWN.value
    assert "provenance_integrity_error" in int_case["expected"]["reason_codes"]

    # 5. Denied paths and symbols produce FAIL with COMPLETE coverage
    for fail_id in ("GRD-POLICY-001", "GRD-POLICY-002", "GRD-POLICY-004", "GRD-POLICY-005"):
        c = cases_by_id[fail_id]
        assert c["expected"]["outcome"] == Outcome.FAIL.value
        assert c["expected"]["coverage"] == Coverage.COMPLETE.value
        assert len(c["expected"]["findings"]) == 1
        assert c["expected"]["findings"][0]["defect_id"] == "GRD-UNGROUNDED-EDIT"

    # 6. Policy excluded paths produce NOT_APPLICABLE with COMPLETE coverage
    excl_case = cases_by_id["GRD-EXCL-001"]
    assert excl_case["expected"]["outcome"] == Outcome.NOT_APPLICABLE.value
    assert excl_case["expected"]["coverage"] == Coverage.COMPLETE.value
    assert "excluded_paths" in excl_case["expected"]["applicability_evidence"]


@pytest.mark.invariant
def test_checkspec_grounding_corpus_fingerprint():
    """Verify that CheckSpec['grounding'] records the exact frozen corpus digest."""
    from verifyci.contracts.manifest import CHECK_SPECS

    grounding_spec = CHECK_SPECS["grounding"]
    actual_sums_hash = "sha256:" + hashlib.sha256(SUMS_FILE.read_bytes()).hexdigest()
    assert grounding_spec.corpus_fingerprint == actual_sums_hash, (
        f"CheckSpec corpus_fingerprint mismatch: {grounding_spec.corpus_fingerprint} != {actual_sums_hash}"
    )
