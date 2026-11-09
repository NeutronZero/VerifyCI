# verifyci

## Overview
`verifyci` is the core package of the VerifyCI deterministic, local-first pre-merge verification gate. It coordinates static analysis, contract validation, security checks, and semantic equivalence proofs over Git diffs to prevent regressions and ungrounded modifications from merging.

## Interface
- `[cli.py:main]`: CLI entry point for the `vc` command line tool (`vc gate`). Parses command arguments, configures gate requests, invokes the verification pipeline, and sets exit status.
- `[__init__.py:__version__]`: Package semver version string (`3.1.10`).
- Subdirectories:
  - `[analysis](./analysis/README.md)`: Control-flow graphs, SSA form, guard condition analysis, effect models, and function summaries.
  - `[checks](./checks/README.md)`: Five core verification checks (`grounding`, `deletion`, `contract`, `security`, `semantic`) and witness replay harnesses.
  - `[contracts](./contracts/README.md)`: Machine-readable data models, check manifests, reason codes, capabilities, and promotion validation.
  - `[evidence](./evidence/README.md)`: Canonical RFC 8785 JSON evidence bundles, payload hashing, and SARIF v2.1.0 projection.
  - `[frontend](./frontend/README.md)`: Multi-language AST/CST frontends (Python, TypeScript) and VFIR lowering.
  - `[gate](./gate/README.md)`: Central gate orchestrator, target-base policy authority loading, CODEOWNERS gate integrity, and verdict aggregation.
  - `[index](./index/README.md)`: Fact extraction, reverse symbol indexing, and HMAC-authenticated CAS caching.
  - `[runtime](./runtime/README.md)`: Resource budget tracking, process isolation sandboxing, and deterministic scheduling.
  - `[scm](./scm/README.md)`: Hardened, read-only Git plumbing operations.
  - `[scope](./scope/README.md)`: Changed entity discovery, diff hunk correlation, and AST boundary mapping.

## Invariants
- `[cli.py:main]`: Strictly enforces the exit code ladder: `0` for `PASS`, `1` for `FAIL`, `2` for `INCONCLUSIVE`, `3` for `ERROR`, and `4` for `REVIEW`.
- `[__init__.py:__version__]`: Canonical version string identifying the tool release.

## Side Effects
- `[cli.py:main]`: Processes CLI arguments, invokes gate orchestration, outputs diagnostics and results to standard streams or output files, and terminates the process with `sys.exit`.

## Verification
- Run: `pytest`
