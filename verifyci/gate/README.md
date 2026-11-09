# verifyci.gate

## Overview
The `verifyci.gate` package is the central coordination engine of VerifyCI. It manages gate orchestration, target-base policy loading, CODEOWNERS-driven gate integrity enforcement, waiver and acceptance adjudication, and fail-closed verdict aggregation across all verification checks.

## Interface
- `[integrity.py:is_protected_path]`: Checks whether a given path is a protected gate-integrity path (e.g. `.verifyci/`, `.github/workflows/`).
- `[integrity.py:protected_paths_in_diff]`: Filters diff entries to detect modifications to protected files.
- `[integrity.py:policy_changed]`: Determines whether policy configuration files have changed in the diff.
- `[integrity.py:gate_integrity]`: Assesses diff entries against gate integrity rules, returning review requirements when protected paths are touched.
- `[integrity.py:CodeownersRule]`: Dataclass modeling a single CODEOWNERS path pattern and its designated owners.
- `[integrity.py:CodeownersFile]`: Parsed representation of a repository CODEOWNERS configuration.
- `[integrity.py:CodeownersCoverage]`: Coverage model for paths evaluated against CODEOWNERS rules.
- `[integrity.py:parse_codeowners]`: Parses raw CODEOWNERS file text into structured rules.
- `[integrity.py:evaluate_codeowners]`: Evaluates changed paths against CODEOWNERS rules to determine required approvals.
- `[integrity.py:load_codeowners]`: Loads CODEOWNERS configuration from a Git tree at a specific commit.
- `[orchestrator.py:GateRequest]`: Execution request dataclass carrying target repository path, base/head revisions, output formats, review mode, and budget limits.
- `[orchestrator.py:run_gate]`: Main gate execution pipeline coordinating diff analysis, policy evaluation, check execution, and evidence bundling.
- `[policy.py:PolicyError]`: Exception raised on invalid policy schemas or file contents.
- `[policy.py:ProposedReview]`: Dataclass summarizing review requirements when a PR proposes changes to policy.
- `[policy.py:canonical_bytes]`: Serializes policy configurations to canonical byte representation.
- `[policy.py:validate_safe_root]`: Validates that policy paths do not escape repository boundaries.
- `[policy.py:parse_policy_bytes]`: Parses YAML or JSON policy bytes into a validated `Policy` model.
- `[policy.py:load_policy_at]`: Loads the authoritative policy from the target-base commit in Git.
- `[policy.py:builtin_bootstrap_policy]`: Provides a default fail-closed policy when no policy configuration exists in the repository.
- `[policy.py:review_proposed_policy]`: Analyzes proposed policy changes in the PR against authoritative base policy.
- `[verdict.py:Aggregation]`: Dataclass capturing aggregated results, final verdict, applied waivers, and accepted gaps.
- `[verdict.py:apply_waivers]`: Applies valid, non-expired waiver records to matching findings.
- `[verdict.py:apply_acceptances]`: Applies valid, non-expired acceptance records to matching coverage gaps.
- `[verdict.py:aggregate]`: Aggregates check results into the final `Verdict` using the strict exit ladder.

## Invariants
- `[verdict.py:aggregate]`: Enforces the strict verdict precedence ladder: `ERROR > FAIL > INCONCLUSIVE > REVIEW > PASS`.
- `[policy.py:load_policy_at]`: The authoritative policy is always loaded from the target-base revision, preventing PRs from weakening their own verification criteria.
- `[integrity.py:gate_integrity]`: Changes to gate integrity paths require explicit review status and cannot pass autonomously.

## Side Effects
- `[orchestrator.py:run_gate]`: Executes Git read operations, accesses the verification cache, and writes output files (e.g., SARIF, JSON) to the filesystem when an output path is configured.

## Verification
- Run: `pytest`
