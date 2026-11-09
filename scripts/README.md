# Scripts Component Package

## Overview
The `scripts/` package provides authoritative operational tooling, CI test selection, evidence bundle generation, and the cryptographic release validation pipeline for VerifyCI v3.1. It implements §15.10 security isolation boundaries, separating unprivileged measurement collection from protected authority signing, strictly preventing untrusted candidate code execution from accessing release signing credentials.

## Interface
- [`build_evidence_bundle.py:_git`](./build_evidence_bundle.py): Fail-closed git command execution and output capture helper.
- [`build_evidence_bundle.py:main`](./build_evidence_bundle.py): CLI entrypoint to execute the v3 test suite, verify clean git status, compute test digest, and write the canonical RFC 8785 M0 test-verification bundle to `evidence/evidence-bundle.json`.
- [`ci_test_selector.py:CORE_INVARIANTS`](./ci_test_selector.py): Permanent core invariant test target set (`tests/v3/test_gate_v3.py`) executed on every CI run regardless of diff.
- [`ci_test_selector.py:FULL_RUN_TRIGGERS`](./ci_test_selector.py): Repository configuration and infrastructure path prefixes triggering a full test run.
- [`ci_test_selector.py:get_changed_files`](./ci_test_selector.py): Git diff and status inspection utility returning normalized paths of modified files.
- [`ci_test_selector.py:select_tests`](./ci_test_selector.py): Change-aware test selector mapping modified files to relevant pytest targets while always including core invariants.
- [`ci_test_selector.py:validate_test_targets`](./ci_test_selector.py): Path sanitization helper ensuring test targets are repository-relative paths without directory traversal.
- [`ci_test_selector.py:main`](./ci_test_selector.py): CLI entry point that outputs validated, newline-delimited test targets for CI consumption.
- [`generate_trusted_attestation.py:parse_args`](./generate_trusted_attestation.py): CLI argument parser for candidate SHA, measurement run ID, attempt, and artifact output paths.
- [`generate_trusted_attestation.py:main`](./generate_trusted_attestation.py): Authoritative attestation generator running in the isolated attestation job; verifies measurement job conclusion, acquires GitHub OIDC token, awaits token expiration window, and outputs `evidence/release/measurement_attestation.json`.
- [`run_trusted_tests.py`](./run_trusted_tests.py): Authoritative supervisor bootstrap script executing pytest in isolated Python mode (`-I`) with `TrustedWorkerPlugin` and sanitized environment.
- [`standalone_signer.py:isolate_execution_environment`](./standalone_signer.py): Process isolation guard purging repository-controlled paths from `sys.path`.
- [`standalone_signer.py:verify_imported_module_origins`](./standalone_signer.py): Security boundary check verifying no module in `sys.modules` originates from candidate repository code.
- [`standalone_signer.py:assert_no_repository_imports`](./standalone_signer.py): Security assertion ensuring `verifyci` is never imported in the signer process.
- [`standalone_signer.py:canonical_json_bytes`](./standalone_signer.py): Zero-dependency pure-Python RFC 8785 canonical JSON serializer.
- [`standalone_signer.py:compute_implementation_fingerprint`](./standalone_signer.py): Deterministic SHA256 calculator over critical implementation source files.
- [`standalone_signer.py:verify_security_corpus_sums`](./standalone_signer.py): Verifier checking security corpus integrity against `corpora/security/SHA256SUMS`.
- [`standalone_signer.py:get_commit_sha`](./standalone_signer.py): Git HEAD commit SHA resolver.
- [`standalone_signer.py:fetch_github_oidc_jwks`](./standalone_signer.py): Fetches GitHub Actions RS256 JWKS public key set.
- [`standalone_signer.py:verify_github_oidc_token`](./standalone_signer.py): Cryptographically verifies GitHub Actions OIDC JWT against JWKS and validates claims.
- [`standalone_signer.py:verify_github_actions_provenance`](./standalone_signer.py): Verifies GitHub Actions run status, job conclusion, and artifact metadata via GitHub REST API.
- [`standalone_signer.py:load_measurement_artifact`](./standalone_signer.py): Extracts and validates measurement payload and attestation from an artifact zip archive.
- [`standalone_signer.py:sign_release_evidence`](./standalone_signer.py): Core signing engine validating provenance, test metrics, and benchmark thresholds before applying Ed25519 signature to produce `release_validation.json`.
- [`standalone_signer.py:main`](./standalone_signer.py): CLI entry point for standalone release evidence signing.
- [`validate_release.py:verify_security_corpus_sums`](./validate_release.py): Checks security corpus files against `corpora/security/SHA256SUMS`.
- [`validate_release.py:verify_corpus_cases`](./validate_release.py): Verifies security case count and required defect family coverage.
- [`validate_release.py:execute_security_benchmark`](./validate_release.py): Executes the benchmark worker in a credential-scrubbed subprocess.
- [`validate_release.py:execute_test_suite`](./validate_release.py): Executes pytest test suite in a credential-scrubbed subprocess.
- [`validate_release.py:collect_measurements`](./validate_release.py): Unprivileged orchestrator executing preflight checks, benchmark, and test suites.
- [`validate_release.py:generate_measurement_attestation`](./validate_release.py): Generates authenticated measurement attestation binding execution context and OIDC tokens.
- [`validate_release.py:sign_measurements`](./validate_release.py): Protected orchestrator executing `standalone_signer.py` in a separate subprocess.
- [`validate_release.py:main`](./validate_release.py): CLI entrypoint supporting `--measure-only`, `--sign-only`, or combined pipeline workflows.

## Invariants
- [`build_evidence_bundle.py:main`](./build_evidence_bundle.py): The working tree must be clean (excluding uncommitted release evidence files), and `GITHUB_SHA` (if set) must strictly match git HEAD.
- [`ci_test_selector.py:CORE_INVARIANTS`](./ci_test_selector.py): `tests/v3/test_gate_v3.py` must always be included in the selected test targets regardless of changed files.
- [`ci_test_selector.py:select_tests`](./ci_test_selector.py): Empty diffs or changes to `FULL_RUN_TRIGGERS` (`pyproject.toml`, `.github/`, `.gitattributes`, `scripts/`) must fail closed by selecting the entire `tests/` directory.
- [`ci_test_selector.py:validate_test_targets`](./ci_test_selector.py): All test targets must begin with `tests/`, match safe character patterns, and never contain directory traversal (`..`).
- [`generate_trusted_attestation.py:main`](./generate_trusted_attestation.py): Candidate SHA must be a 40-character hexadecimal string; measurement job in GitHub Actions must have `status == "completed"` and `conclusion == "success"`.
- [`generate_trusted_attestation.py:main`](./generate_trusted_attestation.py): In CI, attestation publication is delayed until the acquired GitHub OIDC JWT has reached expiration time plus a 60-second safety window.
- [`run_trusted_tests.py`](./run_trusted_tests.py): Environment variables starting with `PYTEST_` or `PYTHON` must be scrubbed, `PYTEST_DISABLE_PLUGIN_AUTOLOAD` must be set to `1`, and candidate conftest discovery is prohibited.
- [`standalone_signer.py:assert_no_repository_imports`](./standalone_signer.py): Zero candidate repository code execution: `verifyci` must never be imported in the signer process, and `sys.path` must be purged of repo paths.
- [`standalone_signer.py:sign_release_evidence`](./standalone_signer.py): Cryptographic binding: `measurements.json` raw SHA256 and RFC 8785 canonical digest must match the hashes in `measurement_attestation.json`.
- [`standalone_signer.py:sign_release_evidence`](./standalone_signer.py): Quality gates: Test suite must report 0 failures, 0 errors, and >= 200 passed tests; security benchmark must evaluate >= 22 cases with zero false blocking and strict redaction, with defect precision 1.0 and recall >= 0.90.
- [`validate_release.py:execute_security_benchmark`](./validate_release.py): `VERIFYCI_RELEASE_SIGNING_KEY` must be scrubbed from the benchmark subprocess environment.
- [`validate_release.py:execute_test_suite`](./validate_release.py): `VERIFYCI_RELEASE_SIGNING_KEY` must be scrubbed from the pytest subprocess environment.

## Side Effects
- [`build_evidence_bundle.py:main`](./build_evidence_bundle.py): Executes pytest and git subprocesses; writes and unlinks temporary JUnit XML reports; writes `evidence/evidence-bundle.json`.
- [`ci_test_selector.py:get_changed_files`](./ci_test_selector.py): Spawns git subprocesses to inspect repository diffs and status; prints targets to stdout.
- [`generate_trusted_attestation.py:main`](./generate_trusted_attestation.py): Performs outbound HTTP network calls to GitHub REST API and GitHub Actions OIDC token provider; delays execution via `time.sleep`; atomically writes `evidence/release/measurement_attestation.json`.
- [`run_trusted_tests.py`](./run_trusted_tests.py): Modifies runner process environment and `sys.path`; executes `pytest.main()`.
- [`standalone_signer.py:sign_release_evidence`](./standalone_signer.py): Sanitizes process `sys.path`; performs HTTP calls to fetch GitHub JWKS and REST API data; creates directories and atomically writes `evidence/release/release_validation.json`.
- [`validate_release.py:collect_measurements`](./validate_release.py): Spawns benchmark worker and pytest subprocesses; writes `evidence/release/measurements.json`.
- [`validate_release.py:sign_measurements`](./validate_release.py): Spawns `standalone_signer.py` subprocess with signing credentials; writes `evidence/release/release_validation.json`.

## Verification
- Run: `pytest`
