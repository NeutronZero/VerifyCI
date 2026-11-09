# verifyci_release_trust

## Overview
Provides the VerifyCI Release Trust & Hardened Measurement Architecture (§15.10). The package implements cryptographic verification of OCI image provenance and GitHub Actions OIDC tokens, authoritative independent benchmark grading against a frozen security corpus and metamorphic held-out scenarios, strict hostile-input IPC parsing, hardened Docker container lifecycle isolation, RFC 8785 canonical JSON serialization with Ed25519 detached signatures, and immutable Git tree materialization directly from object database blobs.

## Interface
- `[__init__.py:__version__]`: Package semantic version string.
- `[attestations.py:OIDCTokenClaims]`: NamedTuple representing decoded and verified GitHub Actions OIDC token claims and hashes.
- `[attestations.py:fetch_github_jwks]`: Fetches GitHub Actions RS256 JSON Web Key Set (JWKS) from `.well-known/jwks`.
- `[attestations.py:parse_and_verify_oidc_token]`: Cryptographically verifies GitHub Actions RS256 OIDC token against JWKS and validates claims, repo, SHAs, and temporal boundaries.
- `[attestations.py:verify_image_attestation_cli]`: Cryptographically verifies worker OCI image provenance and builder commit via GitHub CLI attestation records.
- `[attestations.py:verify_attestation_timing_window]`: Validates that attestation publication occurs strictly after token expiration plus mandatory safety delay.
- `[evaluator.py:AUTHORITATIVE_SECURITY_CORPUS_HASH]`: SHA-256 digest of the frozen 22-case public security benchmark corpus.
- `[evaluator.py:REQUIRED_DEFECT_FAMILIES]`: Tuple of required defect families evaluated by the benchmark suite.
- `[evaluator.py:BenchmarkEvaluationResult]`: NamedTuple holding evaluation metrics, verdict, and error list.
- `[evaluator.py:load_authoritative_public_cases]`: Loads and cryptographically asserts the integrity of the frozen 22-case security benchmark corpus.
- `[evaluator.py:grade_case_result]`: Independently evaluates candidate worker responses against trusted outcomes, enforcing false-blocking and strict secret redaction rules.
- `[evaluator.py:aggregate_benchmark_metrics]`: Computes precision, recall, and confusion matrices across defect families.
- `[evaluator.py:generate_held_out_scenarios]`: Generates deterministic held-out metamorphic test scenarios from a 256-bit secret seed.
- `[evidence.py:canonical_jcs_bytes]`: Serializes Python data structures to deterministic canonical JSON according to RFC 8785 (JCS).
- `[evidence.py:canonical_jcs_digest]`: Computes SHA-256 digest string over RFC 8785 canonical JSON bytes.
- `[evidence.py:compute_file_sha256]`: Computes SHA-256 digest string over raw uncompressed file contents.
- `[evidence.py:compute_trusted_measurement_fingerprint]`: Generates composite measurement authority fingerprint binding all pipeline inputs and supervisor components.
- `[evidence.py:compute_trusted_signing_fingerprint]`: Generates composite signing authority fingerprint measured at signing time.
- `[evidence.py:build_evidence_bundle]`: Compiles explicit artifact digests and composite authority fingerprints.
- `[evidence.py:create_signed_evidence_payload]`: Assembles release validation v3 evidence record with OIDC binding and measurement results.
- `[ipc.py:MAX_IPC_BYTES]`: Maximum allowed IPC payload size limit (1 MB).
- `[ipc.py:MAX_DEPTH]`: Maximum JSON nesting depth limit (10).
- `[ipc.py:MAX_STRING_LENGTH]`: Maximum JSON string length limit (65,536).
- `[ipc.py:MAX_COLLECTION_SIZE]`: Maximum JSON collection/dictionary item count limit (1,000).
- `[ipc.py:MAX_SAFE_INTEGER]`: Maximum safe RFC 8785 IEEE-754 integer limit (`2**53 - 1`).
- `[ipc.py:MIN_SAFE_INTEGER]`: Minimum safe RFC 8785 IEEE-754 integer limit (`-(2**53 - 1)`).
- `[ipc.py:EXIT_CODE_MAP]`: Mapping of process exit codes to evaluation outcome strings (`0: PASS`, `1: FAIL`, `2: INCONCLUSIVE`, `3: ERROR`).
- `[ipc.py:IPCParseResult]`: NamedTuple representing parsed worker IPC data, outcome, and parsing errors.
- `[ipc.py:validate_rfc8785_and_depth]`: Validates AST nesting depth, string lengths, collection sizes, and numeric bounds on decoded JSON nodes.
- `[ipc.py:validate_check_result_schema]`: Enforces strict schema validation for worker responses, rejecting unauthorized fields.
- `[ipc.py:parse_strict_ipc_payload]`: Decodes UTF-8 worker payload, rejects duplicate keys or non-finites, and verifies process exit-code consistency against claimed outcomes.
- `[sandbox.py:STDOUT_LIMIT]`: Maximum buffered stdout limit for container execution (1 MB).
- `[sandbox.py:STDERR_LIMIT]`: Maximum buffered stderr limit for container execution (256 KB).
- `[sandbox.py:DEFAULT_TIMEOUT]`: Default container execution timeout in seconds (120.0s).
- `[sandbox.py:ContainerRunResult]`: NamedTuple representing sandboxed container execution outcome, exit code, stdout/stderr, and data.
- `[sandbox.py:StreamDrainer]`: Threaded stream reader that records bounded byte streams and flags buffer overflow.
- `[sandbox.py:verify_active_container_security]`: Inspects running Docker container to assert enforcement of kernel isolation, read-only rootfs, dropped capabilities, and resource limits.
- `[sandbox.py:run_candidate_in_docker]`: Manages execution of candidate code inside hardened Docker container under monotonic deadline with automatic termination and cleanup.
- `[signer.py:SIGNING_DOMAIN_SEPARATOR]`: Domain separator prefix byte sequence (`b"VERIFYCI-RELEASE-EVIDENCE\0"`).
- `[signer.py:DEFAULT_KEY_ID]`: Default Ed25519 key identifier.
- `[signer.py:DEFAULT_PUBLIC_KEY_HEX]`: Pinned public key hex string for release signature verification.
- `[signer.py:sign_release_payload]`: Signs canonical JCS release payloads with Ed25519 using domain separation and outputs enveloped structure.
- `[signer.py:verify_release_envelope]`: Cryptographically verifies Ed25519 detached signatures on release envelopes against pinned public keys.
- `[supervisor.py:run_supervisor_measurement_pipeline]`: Executes authoritative measurement pipeline including candidate tree staging, public and held-out benchmarking, immutability assertion, and atomic evidence generation.
- `[supervisor.py:main]`: Command-line interface entry point for the authoritative supervisor.
- `[tree_materializer.py:TreeEntry]`: NamedTuple representing Git tree mode, object type, object SHA, and relative path.
- `[tree_materializer.py:MaterializedManifest]`: NamedTuple representing commit SHA, tree SHA, manifest digest, fingerprint, and file count.
- `[tree_materializer.py:ALLOWED_TYPE_MODES]`: Set of permitted Git object type and mode pairs for materialized trees.
- `[tree_materializer.py:MAX_TREE_ENTRIES]`: Maximum permitted number of tree entries (20,000).
- `[tree_materializer.py:MAX_SINGLE_BLOB_SIZE]`: Maximum allowed size for a single blob (50 MB).
- `[tree_materializer.py:MAX_TOTAL_TREE_SIZE]`: Maximum allowed cumulative size of all materialized blobs (200 MB).
- `[tree_materializer.py:resolve_commit_tree]`: Resolves candidate commit SHA to its root tree SHA via Git plumbing.
- `[tree_materializer.py:enumerate_tree]`: Recursively enumerates all objects in a Git tree using null-delimited `ls-tree`.
- `[tree_materializer.py:validate_tree_paths]`: Validates tree entries to reject absolute paths, traversal paths, `.git` paths, escaping symlinks, or unpinned submodules.
- `[tree_materializer.py:materialize_tree_to_staging]`: Extracts files and symlinks directly from immutable Git blob objects and computes canonical candidate implementation fingerprint.
- `[tree_materializer.py:compute_staging_fingerprint]`: Recomputes implementation fingerprint over a staging directory to assert immutability.
- `[tree_materializer.py:TreeMaterializer]`: Helper utility class for sanitizing and validating paths within a destination root.

## Invariants
- `[attestations.py:parse_and_verify_oidc_token]`: OIDC tokens must use algorithm `RS256`, match GitHub Actions issuer `https://token.actions.githubusercontent.com`, match audience `verifyci-release-authority`, and satisfy `nbf <= iat <= exp`.
- `[attestations.py:verify_attestation_timing_window]`: Attestation publication timestamp must occur strictly after `jwt_exp + min_delay_seconds`.
- `[evaluator.py:load_authoritative_public_cases]`: Public benchmark cases must match `AUTHORITATIVE_SECURITY_CORPUS_HASH` (`sha256:8d45f911...`) and contain exactly 22 unique case IDs.
- `[evaluator.py:grade_case_result]`: Clean control cases where expected outcome is not `FAIL` must never evaluate to `FAIL` (zero false blocking); candidate finding messages must never leak unredacted raw secrets (`ghp_`, `AKIA`, `sk_live_`).
- `[evidence.py:canonical_jcs_bytes]`: RFC 8785 canonical serialization requires lexicographically sorted dictionary keys by UTF-16 code units and finite numeric values.
- `[ipc.py:parse_strict_ipc_payload]`: Exit code must match outcome (`0: PASS`, `1: FAIL`, `2: INCONCLUSIVE`, `3: ERROR`); payload must not exceed 1 MB, must not contain duplicate keys, and must not contain non-finite constants (`NaN`, `Infinity`).
- `[sandbox.py:verify_active_container_security]`: Docker containers must enforce read-only root filesystems, private PID/IPC namespaces, network isolation (`none`), dropped capabilities (`ALL`), `no-new-privileges`, memory <= 2GB, and pids <= 256.
- `[signer.py:sign_release_payload]` & `[signer.py:verify_release_envelope]`: Signatures must use Ed25519 and prepend domain separator `VERIFYCI-RELEASE-EVIDENCE\0` to RFC 8785 canonical payload bytes.
- `[supervisor.py:run_supervisor_measurement_pipeline]`: Candidate and trusted root directories must be distinct and non-nested; post-execution staging fingerprint must match pre-execution manifest fingerprint; valid held-out seed is mandatory for a `PASS` verdict.
- `[tree_materializer.py:validate_tree_paths]`: Tree paths must not be absolute, contain directory traversal segments (`..` or `.`), access `.git`, contain submodules, or have symlinks escaping staging root; tree entry counts and blob sizes must remain within defined capacity bounds.

## Side Effects
- `[attestations.py:fetch_github_jwks]`: Executes HTTP GET request to `https://token.actions.githubusercontent.com/.well-known/jwks`.
- `[attestations.py:verify_image_attestation_cli]`: Executes subprocess `gh attestation verify`.
- `[evaluator.py:load_authoritative_public_cases]`: Reads corpus file `corpora/security/cases.jsonl` from the local filesystem.
- `[evidence.py:compute_file_sha256]`: Reads raw file bytes from disk.
- `[sandbox.py:run_candidate_in_docker]`: Manages Docker container lifecycle via `docker create`, `docker inspect`, `docker start`, `docker kill`, and `docker rm` subprocess calls; spawns daemon reader threads.
- `[signer.py:sign_release_payload]`: Accesses environment variable `VERIFYCI_RELEASE_SIGNING_KEY`.
- `[supervisor.py:_build_case_git_repo]`: Creates temporary Git repositories and invokes `git init`, `git config`, `git add`, `git commit`, `git rev-parse`.
- `[supervisor.py:run_supervisor_measurement_pipeline]`: Creates temporary directories on disk, stages files, atomically writes measurements JSON file via `.tmp.<pid>` replace, executes Docker or Python subprocesses, and removes temporary directories.
- `[tree_materializer.py:materialize_tree_to_staging]`: Executes Git plumbing commands (`git rev-parse`, `git ls-tree`, `git cat-file`), creates staging directories, writes files and symlinks to disk, and updates file permissions.

## Verification
- Run: `pytest`
