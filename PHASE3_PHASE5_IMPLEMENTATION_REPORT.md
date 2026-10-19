# VerifyCI v2.3 — Phase 3–5 Implementation Report

## Scope

Implemented Phases 3–5 on the supplied Phase 1/2 runtime-remediation source archive. The uploaded archive did not contain `.git` metadata, so this delivery is a source package, not a commit on branch `refactor/kernel-redesign`.

## Phase 3 — Salsa artifacts and interprocedural taint

- Added `SalsaIncrementalEngine.ingest_compiled_file()` so the primary pipeline can ingest retained AST/U-SSA artifacts without lowering the same Python source again.
- Added persistent, versioned per-function verification fingerprints covering local body/interface identity, taint summaries, policy/configuration, and the transitive behavioral dependency closure.
- Only records fingerprints as reusable after the complete pipeline reaches `PASS`; stale/corrupt fingerprint state falls back to recomputation.
- Tracks removed direct/transitive callers and schedules changed dependencies for in-request caller re-verification. Unrequested callers whose obligations cannot be re-established produce `INCONCLUSIVE` findings.
- Extends interprocedural taint flow to bind positional, keyword, `*args`, and `**kwargs` calls against `ParameterSpec`, conservatively propagating through unknown calls and dynamic argument expansion.
- Added contract checks that consume pre-parsed AST calls.

## Phase 4 — storage, RaBitQ, and Git RSL

- Introduced one canonical RaBitQ sign-bit packing helper using little-endian 64-bit words; both in-memory indexing and durable storage use the same bit layout while retaining the prior per-path alignment/correction formulas.
- Removed writes to unused `cpg_blocks` and `cpg_instructions` tables; the canonical U-SSA payload remains in `function_nodes`, with taint, edges, and vector data in their existing query tables.
- Added per-file digests and a commit-bound manifest to source snapshots. When a Git repository path is configured, snapshot commit IDs are resolved to immutable commit SHAs and supplied source bytes are checked against the Git object database both when stored and when loaded.
- Tightened behavior when no Git repository is available: commit-bound source snapshots require an explicit test-only `allow_unverified_snapshots=True` option. Production code must provide a Git repository to create or consume Git-bound snapshot evidence.
- Added `GitPlumbingProtocol`, explicit `InMemoryGitPlumbingAdapter` and strict `SubprocessGitPlumbingAdapter`. A ledger without a repository now requires explicit adapter injection; the real adapter resolves target commits, creates RSL objects, binds the DSSE envelope to the RSL commit, and publishes the RSL ref using compare-and-swap `git update-ref`.

## Phase 5 — entrypoints, candidate repair, and snapshot identity

- Routes CLI `check` and `verify-diff`, and FastMCP `vc_prove_diff`, through the shared `VerificationPipeline` verdict and mandatory-gate logic.
- Normalizes in-repository paths and uses byte-preserving reads for workspace watcher ingestion.
- Validates snapshot content before graph mutation in committed ingestion requests and propagates snapshot integrity errors rather than downgrading them to absent baselines.
- Binds CEGIS repair to the active pipeline configuration. Each candidate is compiled separately, proved using the typed proof-result contract, checked against the triggering witness, and fully re-verified using an isolated copy of the active Salsa graph and the same intent/contracts/SMT/Wasm policy. The original finding remains `FAIL`; a verified candidate is metadata, not a replacement verdict.
- Adds synthesized-fix response metadata without treating an empty fix list as a successful verification.

## Tests and validation actually performed in this environment

- `python -m compileall -q verifyci_v2 tests`: **passed** after the Phase 3–5 modifications.
- Dependency-independent RaBitQ bit-packing check for dimensions `1, 7, 8, 63, 64, 65, 127, 128, 129`: **9/9 passed**.
- `python -m pytest -q tests/v2/test_v2_3_phase3_phase5_invariants.py`: **blocked at test collection** (`ModuleNotFoundError: No module named 'msgspec'`). Attempted dependency installation could not reach the package index due to DNS/network unavailability. `z3-solver`, DuckDB, and Egglog runtime behavior was therefore not executed here.

## Known limitations / not claimed as verified

1. The Git RSL adapter enforces strict object validation and atomic ref compare-and-swap, but an append still uses multiple Git subprocesses. The broader subprocess-batching performance optimization is not claimed complete; it should be benchmarked and implemented separately without weakening validation or CAS semantics.
2. Runtime pytest results for the new Phase 3–5 tests, the full `tests/v2` suite, frozen corpus adjudication, performance evidence, and release validation remain unverified in this environment due missing runtime dependencies.
3. This archive has no `.git` metadata; it cannot itself establish or create a repository commit. Integrate the package into the target clone, inspect the diff, run the full locked-dependency suite, and commit there.

## Recommended verification sequence in the target repository

```powershell
.venv\Scripts\python.exe -m compileall -q verifyci_v2 tests
.venv\Scripts\python.exe -m pytest tests/v2/test_v2_3_phase3_phase5_invariants.py -q
.venv\Scripts\python.exe -m pytest tests/v2 -q
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m verifyci_v2 adjudicate
.venv\Scripts\python.exe -m verifyci_v2 adjudicate --corpus
.venv\Scripts\python.exe scripts/adjudicate_cap.py
.venv\Scripts\python.exe scripts/adjudicate_performance_evidence.py
.venv\Scripts\python.exe scripts/validate_release.py
```

Do not promote or freeze v2.3 based only on syntax compilation and the isolated RaBitQ test. The required runtime, frozen-corpus, performance, and release gates must all pass against the exact target commit.
