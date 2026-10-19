# VerifyCI v2.3 — Phase 1 and Phase 2 implementation notes

This source package contains the Phase 1 and Phase 2 implementation work requested from the v2.3 specification. It is not a claim that all five phases of the broader v2.3 roadmap are complete.

## Included implementation

### Phase 1 — Reconstruction and compilation ownership

- Added `verifyci_v2/ingestion/compile_context.py` with `CompiledFilePair`, indexed AST artifacts, AST mutation digests, duplicate-safe added-line records, reconstruction-first compilation, and a single `lower_module_to_ussa` call for each parsed revision.
- Added `lower_module_to_ussa` to `ssa_lower.py`; retained `lower_file_to_ussa` as a compatibility wrapper.
- Reworked unified-diff reconstruction to validate hunk coordinates and old-side content, handle zero-length insertion/deletion ranges, preserve CRLF/LF and final-newline behavior, and reject malformed/stale patches.
- Updated the main pipeline to consume compiled AST/U-SSA artifacts, enforce a closed verdict lattice with mandatory-gate receipts, retain independent diff-local security findings after reconstruction failure, and check retained ASTs for mutation.
- Updated dangerous-call and secret scanning interfaces to accept pre-parsed and pre-lowered artifacts; added pre-parsed paths to stack-graph and polyglot bridge ingestion.
- Passed pre-lowered base functions to removal provenance and run baseline checks when a complete explicit base/head pair is provided.

### Phase 2 — Symbolic soundness

- Removed the module-global Egglog EGraph and scoped graph instances to individual checks.
- Removed heuristic-equivalence early returns from the structural prover; `INCONCLUSIVE` structural findings no longer prevent a later SMT proof from discovering a conclusive counterexample.
- Added a per-proof Z3 context with a collision-free `PyVal` datatype for `None`, `bool`, `int`, and `str`.
- Distinguished Python `==` (including bool/int numeric equality) from `is` identity. Unsupported non-singleton identity and unsupported dynamic operations abstain rather than using value equality as object identity.
- Added cycle, disconnected-block, duplicate-block, and malformed-edge validation before acyclic U-SSA DAG encoding. The DAG path uses topological processing rather than enumerating every path.
- Added typed proof outcomes and validated witness requirements via `EquivalenceProofResult`.
- Updated intent-expression translation to use the same context-scoped `PyVal` model, accept a pre-parsed AST, and emit inconclusive findings for unsupported expressions instead of silently skipping them.

## Added tests

`tests/v2/test_v2_3_phase1_phase2.py` contains focused regressions for patch reconstruction, duplicate-line retention, parse/lowering call counts, mandatory-gate receipts, typed Z3 return values, Python equality semantics, intent compilation against a retained AST, and concurrent Egglog use.

## Validation performed

- `python -m compileall -q verifyci_v2 tests/v2/test_v2_3_phase1_phase2.py` — passed.
- Standalone reconstruction checks using only Python's standard library — passed for CRLF/no-final-newline replacement, empty-file insertion, `+++`/`---`-prefixed source lines, multiple hunks with shifted EOF, stale-context rejection, and malformed blank-line rejection.
- `pytest -o addopts='' tests/v2/test_v2_3_phase1_phase2.py -q` — blocked during test collection because `msgspec` is not installed in this environment. Z3 and other project dependencies are also not available, so symbolic runtime tests could not be executed here.
- `ruff` lint could not run because `ruff` is not installed.

## Remaining work outside this delivery

The broader v2.3 specification's Phases 3–5 have not been implemented as part of this deliverable. In particular, full Salsa behavioral/transitive fingerprinting and taint parameter binding, RaBitQ and Git RSL changes, commit-bound source snapshots, CEGIS re-verification, and CLI/FastMCP parity still require their respective implementation and tests. `SalsaIncrementalEngine` and CLI/daemon compatibility paths still have source-based lowering callers; Phase 3/5 integration is required to eliminate those calls from the end-to-end run.

Do not treat this archive as accepted release evidence until the dependencies are installed and the focused tests, existing test suite, frozen-corpus adjudication, performance adjudication, and release validation are run in a suitable environment.
