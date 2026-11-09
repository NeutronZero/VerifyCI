# verifyci.contracts

## Overview
The `verifyci.contracts` package defines the normative machine-readable contracts, schemas, data models, capability declarations, and reason-code taxonomies governing VerifyCI per the v3.1 specification. It models core entities such as diff entries, check results, findings, coverage gaps, policy rules, evidence bundles, and release promotion validation records.

## Interface
- `[capabilities.py:Capability]`: Canonical enum representing required analysis capabilities (e.g. SMT solving, AST parsing).
- `[capabilities.py:ProviderClass]`: Normative capability provider classification enum.
- `[capabilities.py:provider_for_capability]`: Resolves the assigned provider class for a given analysis capability.
- `[capabilities.py:validate_capabilities]`: Validates capability declarations against provider requirements.
- `[capabilities.py:ExecutionStatus]`: Execution status enum for capability checks.
- `[capabilities.py:CapabilityDeclaration]`: Dataclass capturing capability requirements and execution outcomes.
- `[manifest.py:CheckSpec]`: Dataclass specifying metadata, thresholds, and requirements for a published verification check.
- `[manifest.py:manifest_payload]`: Compiles the canonical dictionary structure of the published check manifest from check specs (`_GROUNDING`, `_DELETION`, `_CONTRACT`, `_SEMANTIC`, `_SECURITY`).
- `[manifest.py:release_summary]`: Computes normative maturity-derived release summaries per § 6.4 and § 11.8.
- `[manifest.py:manifest_bytes]`: Serializes the check manifest into canonical UTF-8 JSON bytes.
- `[manifest.py:manifest_hash]`: Computes the SHA-256 digest hex string of `manifest_bytes`.
- `[manifest.py:validate_manifest]`: Validates check manifest structure, syntax coverage, and threshold bounds.
- `[model.py:Verdict]`: Primary gate verdict enum (`PASS`, `FAIL`, `INCONCLUSIVE`, `ERROR`, `REVIEW`).
- `[model.py:Coverage]`: Check coverage assessment enum (`COMPLETE`, `PARTIAL`, `NONE`).
- `[model.py:Outcome]`: Check outcome enum (`CLEAN`, `DEFECT_DETECTED`, `INCONCLUSIVE`, `ERROR`).
- `[model.py:Tier]`: Check tier enum (`BLOCKING`, `SHADOW`).
- `[model.py:Maturity]`: Check maturity status enum (`MATURE`, `PROVISIONAL`, `EXPERIMENTAL`).
- `[model.py:Disposition]`: Finding disposition enum (`BLOCKING`, `WARNING`, `INFORMATIONAL`).
- `[model.py:WitnessLevel]`: Counterexample witness classification enum.
- `[model.py:EvidenceKind]`: Categorization enum for supporting evidence.
- `[model.py:Hunk]`: Unified diff hunk representation.
- `[model.py:DiffEntry]`: File-level diff container capturing paths, mode, status, and hunks.
- `[model.py:Entity]`: Code entity model capturing qualified name, kind, line boundaries, and hashes.
- `[model.py:Evidence]`: Container for concrete witness traces and counterexample data.
- `[model.py:Finding]`: Declared defect model with stable fingerprint, reason code, and locations.
- `[model.py:CoverageGap]`: Uncovered scope container with reason code and target paths/symbols.
- `[model.py:CheckResult]`: Result container for individual check executions.
- `[model.py:WaiverRecord]`: Waiver specification excusing specific findings.
- `[model.py:AcceptanceRecord]`: Coverage acceptance specification excusing specific gaps.
- `[model.py:Policy]`: Authoritative policy configuration model.
- `[model.py:VerdictResult]`: Overall evaluation verdict container.
- `[model.py:EvidenceBundle]`: Complete cryptographic evidence bundle representation.
- `[model.py:glob_match]`: Matches paths against glob patterns.
- `[names.py:NameError]`: Exception raised for invalid naming formats or path traversal attempts.
- `[names.py:normalize_repo_path]`: Normalizes POSIX repository-relative paths and prevents directory traversal.
- `[names.py:is_safe_repo_path]`: Validates paths against traversal sequences and control characters.
- `[names.py:validate_glob_pattern]`: Checks glob pattern validity.
- `[names.py:normalize_module_name]`: Maps file paths to canonical module dot-paths.
- `[names.py:qualify]`: Constructs canonical `path:symbol` qualified names.
- `[names.py:parse_qualified_name]`: Splits a qualified name into `(path, symbol)`.
- `[names.py:normalize_evidence_identity]`: Normalizes evidence identity tuples.
- `[names.py:stable_finding_fingerprint]`: Computes a deterministic SHA-256 fingerprint for findings.
- `[names.py:glob_union_is_universal]`: Evaluates if glob union forms a universal match.
- `[names.py:path_matches_any]`: Checks if a path matches any pattern in a list of globs.
- `[names.py:symbol_matches_any]`: Checks if a symbol matches any pattern in a list of globs.
- `[promotion.py:validate_promotion_chain]`: Validates cryptographic promotion evidence chains per § 15.10.
- `[reason_codes.py:ReasonClass]`: Classification enum for reason codes.
- `[reason_codes.py:ReasonCode]`: Closed enumeration of normative reason codes.
- `[reason_codes.py:is_acceptable_gap]`: Checks whether a reason code is eligible for coverage acceptance.
- `[reason_codes.py:is_finding_code]`: Validates finding defect reason codes.
- `[reason_codes.py:is_fault_code]`: Validates error/fault reason codes.
- `[reason_codes.py:is_review_code]`: Validates review reason codes.
- `[reason_codes.py:reason_class]`: Returns the `ReasonClass` category for a reason code.
- `[reason_codes.py:validate_finding_triple]`: Verifies defect ID, reason code, and evidence kind consistency.
- `[release_validation.py:get_verifyci_root]`: Resolves the root directory of the VerifyCI repository.
- `[release_validation.py:get_commit_sha]`: Resolves Git commit SHA for a revision.
- `[release_validation.py:get_parent_commit]`: Retrieves parent commit SHA.
- `[release_validation.py:get_changed_files_between]`: Enumerates changed paths between commits.
- `[release_validation.py:compute_implementation_fingerprint]`: Computes SHA-256 implementation fingerprint across codebase.
- `[release_validation.py:compute_attestation_signature]`: Computes cryptographic signature over attestation payload.
- `[release_validation.py:verify_release_validation_evidence]`: Verifies release attestation signatures and fingerprints.
- `[release_validation.py:generate_release_validation_record]`: Generates release attestation records for tags.

## Invariants
- `[names.py:normalize_repo_path]`: Rejects empty paths, absolute paths, backslashes, `.` or `..` segments, raising `NameError`.
- `[names.py:stable_finding_fingerprint]`: Returns a deterministic 64-character hex SHA-256 string derived from canonical check, defect, path, and symbol parameters.
- `[manifest.py:validate_manifest]`: Enforces precision threshold 1.0, recall threshold >= 0.9, and coverage threshold 1.0 for all blocking checks.
- `[reason_codes.py:validate_finding_triple]`: Mandates that findings reference only registered defect reason codes and valid evidence kinds from the Appendix A closed catalog.

## Side Effects
- `[release_validation.py:get_commit_sha]`, `[release_validation.py:get_parent_commit]`, `[release_validation.py:get_changed_files_between]`: Reads Git repository history and commit objects via subprocess calls.

## Verification
- Run: `pytest`
