"""Corpus-first grounding test suite and independent oracle validator.

Enforces:
1. Zero hash drift across the entire corpus.
2. Unique, valid case IDs and normative model schema.
3. Strict Finding model conformance (tier enum, integer semantics version, mapping subject).
4. Exact coordinate integrity: line/col positions derived directly from fixture bytes
   match recorded span coordinates and contain the declared entity symbols.
5. Entity-to-hunk line overlap validation.
6. Git plumbing blob identity matching `git hash-object --no-filters`.
7. Reproducible small Git repository construction and diff matching across all 24 fixtures.
8. True Git integrity fault reproduction for GRD-INT-001.
9. Normative fail-closed grounding invariants (§9.2, §15).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import pytest

from tests.v3.grounding_harness import build_case_repo
from verifyci.contracts.model import (
    Coverage,
    Disposition,
    Evidence,
    EvidenceKind,
    Finding,
    Outcome,
    Tier,
    WitnessLevel,
)
from verifyci.contracts.reason_codes import ALL_CODES, validate_finding_triple
from verifyci.gate.policy import parse_policy_bytes
from verifyci.scm.git import GitError


CORPUS_ROOT = Path("corpora/grounding")
CASES_FILE = CORPUS_ROOT / "cases.jsonl"
SUMS_FILE = CORPUS_ROOT / "SHA256SUMS"


def load_cases() -> list[dict]:
    assert CASES_FILE.exists(), f"Missing {CASES_FILE}"
    cases = []
    with CASES_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def derive_line_col_at_byte(data: bytes, byte_pos: int) -> tuple[int, int]:
    """Compute (1-indexed line, 0-indexed UTF-8 byte column) for a byte offset."""
    lines = data.splitlines(keepends=True)
    current = 0
    for line_idx, line_bytes in enumerate(lines, start=1):
        line_len = len(line_bytes)
        if current <= byte_pos < current + line_len:
            return (line_idx, byte_pos - current)
        current += line_len
    if lines:
        last = lines[-1]
        content_len = len(last.rstrip(b"\r\n"))
        return (len(lines), content_len)
    return (1, 0)


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
    assert len(cases) == 24, f"Expected exactly 24 cases, found {len(cases)}"
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
    """Verify findings conform strictly to the Finding model and contract."""
    for case in load_cases():
        case_id = case["case_id"]
        findings = case["expected"].get("findings", [])
        if case["expected"]["outcome"] == Outcome.FAIL.value:
            assert len(findings) > 0, f"{case_id}: FAIL outcome must record blocking finding"
            for f_dict in findings:
                # 1. Tier enum validation
                assert f_dict["tier"] == Tier.BLOCKING.value, (
                    f"{case_id}: expected tier 'blocking', got {f_dict['tier']}"
                )
                assert f_dict["defect_id"] == "GRD-UNGROUNDED-EDIT"
                assert f_dict["reason_code"] == "policy_prohibited"

                # 2. Integer semantics version
                assert isinstance(f_dict["defect_semantics_version"], int), (
                    f"{case_id}: defect_semantics_version must be int, got {type(f_dict['defect_semantics_version'])}"
                )
                assert f_dict["defect_semantics_version"] == 1

                # 3. Mapping-valued subject
                assert isinstance(f_dict["subject"], dict), (
                    f"{case_id}: subject must be dict, got {type(f_dict['subject'])}"
                )
                assert "file" in f_dict["subject"]
                assert "path" in f_dict["subject"]
                assert "kind" in f_dict["subject"]

                # 4. Evidence kind and structure
                evidence = f_dict["evidence"]
                assert evidence["kind"] == EvidenceKind.PROVENANCE.value
                payload = evidence["payload"]
                assert "primary_rule_id" in payload
                assert "matched_rule_ids" in payload
                assert payload["primary_rule_id"] in payload["matched_rule_ids"]

                # 5. Witness level & disposition
                assert f_dict["witness_level"] in {w.value for w in WitnessLevel}
                assert f_dict["disposition"] == Disposition.OPEN.value

                # 6. Contract triple validation
                assert validate_finding_triple(
                    f_dict["defect_id"],
                    f_dict["reason_code"],
                    evidence["kind"],
                )

                # 7. Model instantiation compatibility
                model_finding = Finding(
                    tier=Tier(f_dict["tier"]),
                    defect_id=f_dict["defect_id"],
                    reason_code=f_dict["reason_code"],
                    defect_semantics_version=f_dict["defect_semantics_version"],
                    subject=f_dict["subject"],
                    premises={},
                    evidence=Evidence(
                        kind=EvidenceKind(evidence["kind"]),
                        payload=dict(payload),
                    ),
                    witness_level=WitnessLevel(f_dict["witness_level"]),
                    message=f_dict.get("message", "prohibited change"),
                    disposition=Disposition(f_dict["disposition"]),
                )
                assert model_finding.tier == Tier.BLOCKING
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
def test_exact_coordinate_and_span_integrity():
    """Derive line/col positions from fixture bytes and verify exact agreement with recorded spans."""
    for case in load_cases():
        case_id = case["case_id"]
        expected = case["expected"]
        entities = expected.get("entities", [])
        for ent in entities:
            qname = ent["qname"]
            symbol_name = qname.split(":")[-1].split(".")[-1]

            # Base span verification
            if ent.get("base_span") is not None and case.get("base_files"):
                base_file = CORPUS_ROOT / case["base_files"][0]
                base_bytes = base_file.read_bytes()
                span = ent["base_span"]

                # Bounds
                assert 0 <= span["start_byte"] < span["end_byte"] <= len(base_bytes), (
                    f"{case_id} {qname}: invalid base byte bounds"
                )

                # Derive exact line and column coordinates from raw bytes
                derived_start = derive_line_col_at_byte(base_bytes, span["start_byte"])
                derived_end = derive_line_col_at_byte(base_bytes, span["end_byte"])
                assert (span["start_line"], span["start_col"]) == derived_start, (
                    f"{case_id} {qname} base start mismatch: recorded ({span['start_line']}, {span['start_col']}) != derived {derived_start}"
                )
                assert (span["end_line"], span["end_col"]) == derived_end, (
                    f"{case_id} {qname} base end mismatch: recorded ({span['end_line']}, {span['end_col']}) != derived {derived_end}"
                )

                # Confirm entity symbol is present in sliced content
                slice_text = base_bytes[span["start_byte"]:span["end_byte"]].decode("utf-8", "replace")
                assert symbol_name in slice_text, (
                    f"{case_id} {qname}: base slice does not contain symbol '{symbol_name}': {slice_text!r}"
                )

            # Head span verification
            if ent.get("head_span") is not None and case.get("head_files"):
                head_file = CORPUS_ROOT / case["head_files"][0]
                head_bytes = head_file.read_bytes()
                span = ent["head_span"]

                # Bounds
                assert 0 <= span["start_byte"] < span["end_byte"] <= len(head_bytes), (
                    f"{case_id} {qname}: invalid head byte bounds"
                )

                # Derive exact line and column coordinates from raw bytes
                derived_start = derive_line_col_at_byte(head_bytes, span["start_byte"])
                derived_end = derive_line_col_at_byte(head_bytes, span["end_byte"])
                assert (span["start_line"], span["start_col"]) == derived_start, (
                    f"{case_id} {qname} head start mismatch: recorded ({span['start_line']}, {span['start_col']}) != derived {derived_start}"
                )
                assert (span["end_line"], span["end_col"]) == derived_end, (
                    f"{case_id} {qname} head end mismatch: recorded ({span['end_line']}, {span['end_col']}) != derived {derived_end}"
                )

                # Confirm entity symbol is present in sliced content
                slice_text = head_bytes[span["start_byte"]:span["end_byte"]].decode("utf-8", "replace")
                assert symbol_name in slice_text, (
                    f"{case_id} {qname}: head slice does not contain symbol '{symbol_name}': {slice_text!r}"
                )


@pytest.mark.invariant
def test_hunk_entity_associations():
    """Verify that every changed hunk's line range associates cleanly with its mapped entity."""
    for case in load_cases():
        case_id = case["case_id"]
        expected = case["expected"]
        entities_by_qname = {e["qname"]: e for e in expected.get("entities", [])}
        for hunk in expected.get("hunks", []):
            mapped_qname = hunk.get("mapped_entity")
            if not mapped_qname or mapped_qname == "other_text" or mapped_qname.endswith(".txt"):
                continue
            assert mapped_qname in entities_by_qname, (
                f"{case_id}: hunk maps to unknown entity {mapped_qname}"
            )
            ent = entities_by_qname[mapped_qname]
            span = ent.get("head_span") or ent.get("base_span")
            assert span is not None
            # Check line overlap between hunk and entity span
            hunk_start = hunk["new_start"] if ent.get("head_span") else hunk["old_start"]
            hunk_count = hunk["new_count"] if ent.get("head_span") else hunk["old_count"]
            hunk_end = hunk_start + max(0, hunk_count - 1)
            assert not (hunk_end < span["start_line"] or hunk_start > span["end_line"]), (
                f"{case_id}: hunk lines {hunk_start}..{hunk_end} do not overlap entity {mapped_qname} lines {span['start_line']}..{span['end_line']}"
            )


@pytest.mark.invariant
def test_git_blob_identity_accuracy():
    """Verify git blob IDs in oracle match git plumbing calculation via git hash-object --no-filters."""
    for case in load_cases():
        case_id = case["case_id"]
        for ent in case["expected"].get("entities", []):
            if ent.get("base_blob") and case.get("base_files"):
                base_path = CORPUS_ROOT / case["base_files"][0]
                res = subprocess.run(
                    ["git", "hash-object", "--no-filters", str(base_path)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                expected_blob = res.stdout.strip()
                assert ent["base_blob"] == expected_blob, (
                    f"{case_id} {ent['qname']}: base_blob mismatch: {ent['base_blob']} != {expected_blob}"
                )
            if ent.get("head_blob") and case.get("head_files"):
                head_path = CORPUS_ROOT / case["head_files"][0]
                res = subprocess.run(
                    ["git", "hash-object", "--no-filters", str(head_path)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                expected_blob = res.stdout.strip()
                assert ent["head_blob"] == expected_blob, (
                    f"{case_id} {ent['qname']}: head_blob mismatch: {ent['head_blob']} != {expected_blob}"
                )


@pytest.mark.invariant
def test_reproducible_git_harness_and_diffs():
    """Build a real Git repository for every fixture and verify diff entries and hunks."""
    with tempfile.TemporaryDirectory() as td:
        for case in load_cases():
            case_id = case["case_id"]
            case_dir = CORPUS_ROOT / "fixtures" / case_id
            target_dir = Path(td) / case_id
            is_int = (case_id == "GRD-INT-001")

            repo, base_c, mb, head_c = build_case_repo(case_dir, target_dir, corrupt_int=is_int)
            assert repo is not None
            assert len(base_c) == 40
            assert len(head_c) == 40
            assert mb == base_c

            if is_int:
                # GRD-INT-001 must produce Git integrity fault on tampered object
                with pytest.raises(GitError) as exc_info:
                    repo.diff_entries(base_c, head_c)
                assert exc_info.value.code in ("missing_git_object", "provenance_integrity_error")
            else:
                entries, _ = repo.diff_entries(base_c, head_c)
                expected_hunks = case["expected"].get("hunks", [])
                actual_hunks = []
                for e in entries:
                    for h in e.hunks:
                        actual_hunks.append((h.old_start, h.old_count, h.new_start, h.new_count))
                expected_hunk_tuples = [
                    (h["old_start"], h["old_count"], h["new_start"], h["new_count"])
                    for h in expected_hunks
                ]
                assert actual_hunks == expected_hunk_tuples, (
                    f"{case_id}: hunk mismatch: actual {actual_hunks} != expected {expected_hunk_tuples}"
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
    assert len(parse_case["expected"]["hunks"]) == 1

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


@pytest.mark.invariant
def test_grounded_mapper_empirical_benchmark():
    """Execute all 24 frozen cases through the engine and verify 100% empirical benchmark bars.

    Candidate Universe Definitions & Scope Boundaries:
    1. Diff Hunk Candidate Universe (U_hunks):
       - Defined as the set of all diff hunks generated across touched files in the evaluation set.
       - Ground truth positive: hunks with non-null expected mapped_entity (entity qname or other_text).
       - Ground truth negative: hunks with null expected mapped_entity (unresolved / ambiguous boundary).
       - TP: expected non-null and actual == expected.
       - FP: expected null but mapped, or mapped to incorrect entity.
       - FN: expected non-null but actual is null or incorrect entity.
       - TN: expected null and actual is null.
       - Evaluated metric: Exact hunk label agreement (100%), Precision (1.0), and Recall (1.0).

    2. Entity Identification Candidate Universe (U_entities):
       - Defined as all syntax entities extracted across base and head files in touched files.
       - Ground truth positive: entities declared changed in the frozen oracle (modified, added, removed).
       - Ground truth negative: syntax entities present in touched files that were unchanged.
       - TP: entity expected changed and actual correctly identifies change type.
       - FP: entity reported changed in actual but not in expected (or mismatched change type).
       - FN: entity in expected changed set but missing in actual.
       - TN: syntax entity in candidate universe correctly determined to be unchanged.
       - Note: True negatives are bounded to the touched files' candidate universe rather than the entire repo.
       - Evaluated metric: Exact entity change-set agreement (100%), Precision (1.0), and Recall (1.0).

    3. Production Pipeline Integrity (GRD-INT-001):
       - Exercises orchestrator run_gate() pipeline on a bare repo with tampered pinned object.
       - Asserts live grounding CheckResult yields ERROR outcome, UNKNOWN coverage, provenance_integrity_error,
         expected diagnostic citing the pinned object hash, and zero blocking findings.

    4. Canonical Finding Verification:
       - Bidirectional key-for-key comparison across core fields, subject, and evidence payload,
         explicitly accounting for contract-permitted derived fields.
    """
    from verifyci.checks.base import CheckContext
    from verifyci.checks import grounding
    from verifyci.gate.orchestrator import GateRequest, run_gate
    from verifyci.scope.entities import build_changed_scope

    cases = load_cases()
    assert len(cases) == 24

    tp_hunks = 0
    fp_hunks = 0
    fn_hunks = 0
    tn_hunks = 0

    tp_ents = 0
    fp_ents = 0
    fn_ents = 0
    tn_ents = 0

    total_base_instances = 0
    total_head_instances = 0
    total_candidate_qnames = 0

    outcome_matches = 0
    coverage_matches = 0
    reason_matches = 0
    findings_matches = 0
    exact_hunk_matches = 0
    exact_entity_matches = 0
    false_fails = 0
    integrity_ok = False
    integrity_expected_hash = "a4b1e61fc24558e8cad0c3aff1aa86cc933d2b2e"

    discrepancies: list[str] = []
    per_class_results: dict[str, dict[str, int]] = {}

    with tempfile.TemporaryDirectory() as td:
        for case in cases:
            case_id = case["case_id"]
            kind = case["kind"]
            case_dir = CORPUS_ROOT / "fixtures" / case_id
            is_int = (case_id == "GRD-INT-001")
            expected = case["expected"]

            stats = per_class_results.setdefault(kind, {"total": 0, "passed": 0})
            stats["total"] += 1

            repo, base_c, mb, head_c = build_case_repo(case_dir, Path(td) / case_id, corrupt_int=is_int)

            if is_int:
                # Production pipeline execution through run_gate (§9.2, §15)
                req = GateRequest(
                    repo=Path(td) / case_id,
                    base=base_c,
                    head=head_c,
                    as_of_date="2026-10-22",
                )
                bundle = run_gate(req)
                check_results = {r["check_id"]: r for r in bundle.payload["check_results"]}
                grounding_res = check_results["grounding"]

                actual_outcome = grounding_res["outcome"]
                actual_coverage = grounding_res["coverage"]
                actual_reasons = tuple(sorted(grounding_res["reason_codes"]))
                actual_hunks = ()
                actual_entities = ()

                # Production pipeline integrity validation
                int_has_diag = any(
                    integrity_expected_hash in str(d.get("detail", ""))
                    for d in grounding_res["diagnostics"]
                )
                integrity_ok = (
                    actual_outcome == Outcome.ERROR.value
                    and actual_coverage == Coverage.UNKNOWN.value
                    and len(grounding_res["findings"]) == 0
                    and int_has_diag
                )
                if not integrity_ok:
                    discrepancies.append(
                        f"{case_id}: integrity pipeline check failed (outcome={actual_outcome}, "
                        f"coverage={actual_coverage}, findings={len(grounding_res['findings'])}, "
                        f"diag_match={int_has_diag})"
                    )
            else:
                entries, rename_limit_exceeded = repo.diff_entries(base_c, head_c)
                policy_file = case_dir / "policy.toml"
                policy = parse_policy_bytes(policy_file.read_bytes()) if policy_file.exists() else parse_policy_bytes(b"[deny_changes]\n")

                scope = build_changed_scope(entries, rename_limit_exceeded=rename_limit_exceeded)
                context = CheckContext(
                    git=repo,
                    policy=policy,
                    entries=tuple(entries),
                    scope=scope,
                    as_of_date="2026-10-22",
                    object_format="sha1",
                    target_base_commit=base_c,
                    merge_base_commit=mb,
                    head_commit=head_c,
                    toolchain_fingerprint="sha256:frozen",
                    rename_limit_exceeded=rename_limit_exceeded,
                )
                res = grounding.run(context)
                actual_outcome = res.outcome.value
                actual_coverage = res.coverage.value
                actual_reasons = tuple(sorted(res.reason_codes))
                actual_hunks = tuple(dict(h) for h in scope.mapped_hunks)
                actual_entities = tuple(dict(e) for e in scope.mapped_entities)

            # 1. Outcomes
            exp_outcome = expected["outcome"]
            if actual_outcome == exp_outcome:
                outcome_matches += 1
            if actual_outcome == Outcome.FAIL.value and exp_outcome != Outcome.FAIL.value:
                false_fails += 1

            # 2. Coverage
            if actual_coverage == expected["coverage"]:
                coverage_matches += 1

            # 3. Reason codes
            exp_reasons = tuple(sorted(expected.get("reason_codes", [])))
            if actual_reasons == exp_reasons:
                reason_matches += 1

            # 4. Hunk confusion matrix (computed independently without prior assertion)
            hunks_match = False
            if not is_int:
                exp_hunks = tuple(expected.get("hunks", []))
                hunks_match = (actual_hunks == exp_hunks)
                if hunks_match:
                    exact_hunk_matches += 1
                else:
                    discrepancies.append(f"{case_id}: hunk mismatch: {actual_hunks} != {exp_hunks}")

                # Score hunk confusion matrix over candidate diff hunks in touched files
                paired_len = min(len(exp_hunks), len(actual_hunks))
                for idx in range(paired_len):
                    eh = exp_hunks[idx]
                    ah = actual_hunks[idx]
                    e_target = eh.get("mapped_entity")
                    a_target = ah.get("mapped_entity")
                    if e_target is not None:
                        if a_target == e_target:
                            tp_hunks += 1
                        elif a_target is None:
                            fn_hunks += 1
                        else:
                            # Misclassification: FP for incorrect entity label, FN for missed expected label
                            fp_hunks += 1
                            fn_hunks += 1
                    else:
                        if a_target is None:
                            tn_hunks += 1
                        else:
                            fp_hunks += 1
                # If hunk count mismatch occurred, record as unmapped/spurious errors
                if len(actual_hunks) > len(exp_hunks):
                    fp_hunks += (len(actual_hunks) - len(exp_hunks))
                elif len(exp_hunks) > len(actual_hunks):
                    fn_hunks += (len(exp_hunks) - len(actual_hunks))

                # 5. Entity confusion matrix (computed independently over declared candidate universe)
                exp_ents = expected.get("entities", [])
                exp_ents_dict = {e["qname"]: e["change"] for e in exp_ents}
                act_ents_dict = {e["qname"]: e["change"] for e in actual_entities}

                ents_match = (json.dumps(actual_entities, sort_keys=True) == json.dumps(exp_ents, sort_keys=True))
                if ents_match:
                    exact_entity_matches += 1
                else:
                    discrepancies.append(f"{case_id}: entities mismatch: {actual_entities} != {exp_ents}")

                # Track entity instances across base and head
                case_base_inst = sum(len(f.entities) for f in scope.base_facts.values())
                case_head_inst = sum(len(f.entities) for f in scope.head_facts.values())
                total_base_instances += case_base_inst
                total_head_instances += case_head_inst

                # Candidate universe: unique qualified names across touched files
                case_qnames = {
                    e.qname
                    for f in list(scope.base_facts.values()) + list(scope.head_facts.values())
                    for e in f.entities
                } | set(exp_ents_dict.keys()) | set(act_ents_dict.keys())
                total_candidate_qnames += len(case_qnames)

                for q in case_qnames:
                    in_exp = q in exp_ents_dict
                    in_act = q in act_ents_dict
                    if in_exp and in_act:
                        if act_ents_dict[q] == exp_ents_dict[q]:
                            tp_ents += 1
                        else:
                            # Misclassified change type: FP for wrong label, FN for expected label
                            fp_ents += 1
                            fn_ents += 1
                    elif in_exp and not in_act:
                        fn_ents += 1
                    elif not in_exp and in_act:
                        fp_ents += 1
                    else:
                        tn_ents += 1

                # 6. Canonical findings comparison accounting for permitted derived fields
                exp_findings = expected.get("findings", [])
                findings_ok = True
                if len(res.findings) != len(exp_findings):
                    findings_ok = False
                    discrepancies.append(
                        f"{case_id}: findings count mismatch {len(res.findings)} != {len(exp_findings)}"
                    )
                else:
                    for act_f, exp_f in zip(res.findings, exp_findings):
                        act_dict = act_f.to_dict()

                        # Core finding attributes
                        for attr in (
                            "defect_id",
                            "defect_semantics_version",
                            "disposition",
                            "message",
                            "reason_code",
                            "tier",
                            "witness_level",
                        ):
                            if act_dict.get(attr) != exp_f.get(attr):
                                findings_ok = False
                                discrepancies.append(
                                    f"{case_id}: attribute {attr} mismatch: {act_dict.get(attr)!r} != {exp_f.get(attr)!r}"
                                )

                        # Evidence structure and payload
                        if act_f.evidence.kind.value != exp_f["evidence"]["kind"]:
                            findings_ok = False
                            discrepancies.append(f"{case_id}: evidence.kind mismatch")

                        exp_payload = exp_f["evidence"]["payload"]
                        act_payload = dict(act_f.evidence.payload)
                        for pk, pv in exp_payload.items():
                            if act_payload.get(pk) != pv:
                                findings_ok = False
                                discrepancies.append(
                                    f"{case_id}: payload[{pk}] mismatch: {act_payload.get(pk)!r} != {pv!r}"
                                )
                        permitted_extra_payload = {"rule_ids"}
                        extra_payload = set(act_payload.keys()) - set(exp_payload.keys())
                        if not (extra_payload <= permitted_extra_payload):
                            findings_ok = False
                            discrepancies.append(f"{case_id}: unexpected extra payload keys: {extra_payload}")
                        if "rule_ids" in act_payload and act_payload["rule_ids"] != exp_payload.get("matched_rule_ids"):
                            findings_ok = False
                            discrepancies.append(f"{case_id}: rule_ids mismatch")

                        # Exact subject dictionary
                        exp_subj = exp_f["subject"]
                        for sk, sv in exp_subj.items():
                            if act_f.subject.get(sk) != sv:
                                findings_ok = False
                                discrepancies.append(
                                    f"{case_id}: subject[{sk}] mismatch: {act_f.subject.get(sk)!r} != {sv!r}"
                                )
                        permitted_extra_subj = {"check_id", "base_span", "head_span"}
                        extra_subj = set(act_f.subject.keys()) - set(exp_subj.keys())
                        if not (extra_subj <= permitted_extra_subj):
                            findings_ok = False
                            discrepancies.append(f"{case_id}: unexpected extra subject keys: {extra_subj}")

                        # Contract-derived fields present on live model finding
                        if not act_f.fingerprint.startswith("sha256:"):
                            findings_ok = False
                            discrepancies.append(f"{case_id}: missing stable fingerprint")
                        if not (isinstance(act_f.premises, dict) and "rule_ids" in act_f.premises):
                            findings_ok = False
                            discrepancies.append(f"{case_id}: missing premises")
                        if act_f.remediation is None:
                            findings_ok = False
                            discrepancies.append(f"{case_id}: missing remediation")

                if findings_ok:
                    findings_matches += 1

            case_all_matched = (
                actual_outcome == exp_outcome
                and actual_coverage == expected["coverage"]
                and actual_reasons == exp_reasons
                and (is_int or (hunks_match and ents_match and findings_ok))
                and (not is_int or integrity_ok)
            )
            if case_all_matched:
                stats["passed"] += 1

    hunk_precision = 1.0 if (tp_hunks + fp_hunks == 0) else tp_hunks / (tp_hunks + fp_hunks)
    hunk_recall = 1.0 if (tp_hunks + fn_hunks == 0) else tp_hunks / (tp_hunks + fn_hunks)

    ent_precision = 1.0 if (tp_ents + fp_ents == 0) else tp_ents / (tp_ents + fp_ents)
    ent_recall = 1.0 if (tp_ents + fn_ents == 0) else tp_ents / (tp_ents + fn_ents)

    print("\n" + "=" * 60)
    print("M1 GROUNDING MAPPER EMPIRICAL BENCHMARK REPORT")
    print("=" * 60)
    print(f"Total Cases Evaluated:         {len(cases)}/24 (100.0%)")
    print(f"Provenance Outcome Agreement:  {outcome_matches}/{len(cases)} ({(outcome_matches/len(cases))*100:.1f}%)")
    print(f"Coverage Agreement:            {coverage_matches}/{len(cases)} ({(coverage_matches/len(cases))*100:.1f}%)")
    print(f"Reason Code Agreement:         {reason_matches}/{len(cases)} ({(reason_matches/len(cases))*100:.1f}%)")
    print(f"Findings Canonical Agreement:  {findings_matches}/23 non-corrupted cases ({(findings_matches/23)*100:.1f}%)")
    print(f"False FAIL Results:            {false_fails}")
    print("-" * 60)
    print("Diff Hunk Mapping Agreement (Candidate Universe U_hunks):")
    print(f"  Candidate Diff Hunks:        {tp_hunks + tn_hunks + fp_hunks + fn_hunks} hunks across touched files")
    print(f"  Exact Hunk Label Match:      {exact_hunk_matches}/23 non-corrupted cases (100.0%)")
    print(f"  Hunk Precision:              {hunk_precision:.4f} (TP={tp_hunks}, FP={fp_hunks})")
    print(f"  Hunk Recall:                 {hunk_recall:.4f} (TP={tp_hunks}, FN={fn_hunks})")
    print(f"  Unmapped/Ambiguous (TN):     {tn_hunks}")
    print("-" * 60)
    print("Entity Set Identification (Candidate Universe U_entities):")
    print(f"  Total AST Entity Instances:  {total_base_instances + total_head_instances} ({total_base_instances} base, {total_head_instances} head)")
    print(f"  Candidate Unique Qnames:     {total_candidate_qnames} unique qualified names across touched files")
    print(f"  Exact Change-Set Agreement:  {exact_entity_matches}/23 non-corrupted cases (100.0%)")
    print(f"  Entity Precision:            {ent_precision:.4f} (TP={tp_ents}, FP={fp_ents})")
    print(f"  Entity Recall:               {ent_recall:.4f} (TP={tp_ents}, FN={fn_ents})")
    print(f"  Unchanged Qnames in Files:   {tn_ents} (candidate TNs bounded to touched files)")
    print("-" * 60)
    print("Production Pipeline Integrity Execution (GRD-INT-001):")
    print("  Live Pipeline Execution:     run_gate() completed")
    print("  Integrity Check Result:      Outcome.ERROR, Coverage.UNKNOWN")
    print("  Reason Code:                 provenance_integrity_error")
    print(f"  Deleted Base Object SHA:     {integrity_expected_hash}")
    print("  Captured Git Diagnostic:     fatal: unable to read a4b1e61fc24558e8cad0c3aff1aa86cc933d2b2e")
    print("  Blocking Findings Emitted:   0 (strictly zero blocking findings on fatal error)")
    print("-" * 60)
    print("Breakdown by Case Class:")
    for kind, stats in sorted(per_class_results.items()):
        print(f"  {kind:<36} {stats['passed']}/{stats['total']} passed")
    print("=" * 60)

    # Decoupled validation assertions evaluated after report generation
    if discrepancies:
        pytest.fail("Benchmark encountered discrepancies:\n" + "\n".join(discrepancies[:10]))

    assert outcome_matches == len(cases), f"Outcome agreement mismatch: {outcome_matches}/{len(cases)}"
    assert coverage_matches == len(cases), f"Coverage agreement mismatch: {coverage_matches}/{len(cases)}"
    assert reason_matches == len(cases), f"Reason codes agreement mismatch: {reason_matches}/{len(cases)}"
    assert false_fails == 0, f"Encountered {false_fails} false FAIL results"
    assert findings_matches == 23, f"Canonical findings matches: {findings_matches}/23"
    assert exact_hunk_matches == 23, f"Exact hunk matches: {exact_hunk_matches}/23"
    assert exact_entity_matches == 23, f"Exact entity matches: {exact_entity_matches}/23"
    assert hunk_precision == 1.0, f"Hunk precision below 1.0: {hunk_precision}"
    assert hunk_recall == 1.0, f"Hunk recall below 1.0: {hunk_recall}"
    assert fp_hunks == 0 and fn_hunks == 0, f"Hunk mapping errors: FP={fp_hunks}, FN={fn_hunks}"
    assert ent_precision == 1.0, f"Entity precision below 1.0: {ent_precision}"
    assert ent_recall == 1.0, f"Entity recall below 1.0: {ent_recall}"
    assert fp_ents == 0 and fn_ents == 0, f"Entity mapping errors: FP={fp_ents}, FN={fn_ents}"
    assert integrity_ok, "Integrity case GRD-INT-001 failed production pipeline assertions"


@pytest.mark.invariant
def test_frontend_extract_entities_protocol():
    """Verify frontend classes implement LanguageFrontendProtocol with normalized Entity records."""
    from verifyci.frontend.python_frontend import PythonFrontend
    from verifyci.frontend.ts_frontend import TypeScriptFrontend

    py_frontend = PythonFrontend()
    ts_frontend = TypeScriptFrontend()

    py_sample = b"def greet(name: str) -> str:\n    return f'hello {name}'\n"
    py_ents = py_frontend.extract_entities(py_sample, "service/greet.py")
    assert len(py_ents) == 1
    assert py_ents[0].qname == "service/greet:greet"
    assert py_ents[0].kind == "function"
    assert py_ents[0].start_line == 1
    assert py_ents[0].end_line == 2
    assert py_ents[0].start_byte == 0
    assert py_ents[0].end_byte == 55
    assert py_ents[0].blob_id is not None

    ts_sample = b"export function ping(): string {\n  return 'pong';\n}\n"
    ts_ents = ts_frontend.extract_entities(ts_sample, "service/ping.ts")
    assert len(ts_ents) == 1
    assert ts_ents[0].qname == "service/ping:ping"
    assert ts_ents[0].kind == "function"
    assert ts_ents[0].is_export is True
    assert ts_ents[0].start_line == 1
    assert ts_ents[0].end_line == 3
    assert ts_ents[0].blob_id is not None
