# VerifyCI v1 Remediation Design

Date: 2026-10-14
Source: `C:\Projects\Argon VerifyCI Output\Chat.md` (v1 sections only)
Scope: Everything planned for v1. v2 architecture is explicitly out of scope.

## 1. Shared Understanding

### Stated by user
- "First fix v1."
- Follow approach A (thin shims, formalize facades, minimal diff).
- Follow everything mentioned in Chat.md for v1.

### Assumptions (correct me if wrong)
- Goal is to eliminate v1 tech debt before any v2 clean-slate work.
- Frozen constraints from `AGENTS.md` apply: `v1.0-evidence-baseline` tag and
  artifacts are immutable, remediation commits stay separate from benchmark
  refresh commits, gates are fail-closed, and no frozen labels or snapshots
  are rewritten to force a pass.
- Success means zero regressions: full `uv run pytest` passes,
  `python scripts/validate_release.py` succeeds, and the capability
  adjudication harness (`scripts/adjudicate_cap.py`) shows no drift.

## 2. Audit Baseline (from Chat.md, verified by probes)

1. Repository bloat from committed artifacts. Large generated JSON files and
   `uv.lock` dominate the byte footprint and slow ephemeral CI clones.
2. Code duplication between core and benchmark fixtures. Files under
   `benchmarks/latency/fixture/` (`extractor.py`, `graph_store.py`,
   `intent_align.py`, `env.py`, `provider.py`, `workload.py`) mirror live
   `verifyci.*` modules. Probe result: `extractor.py` and `env.py` are
   identical; `graph_store.py`, `intent_align.py`, and `provider.py` have
   drifted (branch params, 5-tuple versus 3-tuple search returns, provider
   timeouts, cache validation); `workload.py` is a near-mirror except the
   `_emit` `type` to `event_type` rename. Fifteen shared symbols, ten drift
   sites.
3. Dual MCP server maintenance overhead. Chat.md lists
   `verifyci/interface/mcp_server.py` and `fastmcp_server.py` as parallel
   entry points. Probe result: there is no logic duplication. `mcp_server.py`
   owns the six tool implementations; `fastmcp_server.py` is a thin
   transport, authentication, and framing wrapper that delegates inward. Both
   share `limits.py` caps and `ingress.py` gates. Seven tests pin parity.
   The remediation therefore formalizes the existing layering rather than
   merging divergent logic.
4. Placeholder test stubs in benchmark base suites. Seventeen benchmark test
   files contain single-line no-op bodies, which is sufficient for static
   call-graph reachability but blocks mutation and execution-based oracle
   verification. This design does not add benchmark coverage; it only stops
   measuring stale fixture copies.
5. Unpinned base image digest. `benchmarks/patch_corpus/base/Dockerfile`
   uses `FROM python:3.12-slim` with no `@sha256:` digest, so upstream
   rebuilds can alter benchmark runtimes.

## 3. Section 1 — Deduplicate Latency Benchmark Fixtures

Objective: eliminate drift between `verifyci/` core modules and duplicated
files in `benchmarks/latency/fixture/`.

Target files:
- `benchmarks/latency/fixture/extractor.py`
- `benchmarks/latency/fixture/graph_store.py`
- `benchmarks/latency/fixture/intent_align.py`
- `benchmarks/latency/fixture/env.py`
- `benchmarks/latency/fixture/provider.py`
- `benchmarks/latency/fixture/workload.py`
- `benchmarks/latency/measure.py`

Design:
- Convert each fixture module except `workload.py` into a thin re-export
  shim that imports the public symbols from the corresponding live module
  (`verifyci.ingestion.extractor`, `verifyci.storage.graph_store`,
  `verifyci.verification.intent_align`, `verifyci.retrieval.provider`,
  `verifyci.env`). Preserve module paths so existing benchmark imports keep
  working.
- Keep synthetic workload generators in `workload.py`. Align the known drift:
  rename `_emit` payload key to `event_type` and widen helper annotations to
  `dict[str, Any]` to match `verifyci/orchestration/scheduler.py`.
- Update `benchmarks/latency/measure.py` (and `h3_measure.py` if present) to
  import directly from `verifyci.*` where it currently reaches into fixtures.

Verification gate:
- `uv run pytest tests/evaluation/test_latency_repro.py tests/evaluation/test_optimizations_equivalence.py -v`

## 4. Section 2 — Consolidate Dual MCP Server Implementations

Objective: unify `mcp_server.py` and `fastmcp_server.py` into a single
canonical implementation with a legacy compatibility shim.

Target files:
- `verifyci/interface/fastmcp_server.py` (canonical)
- `verifyci/interface/mcp_server.py` (deprecated facade)
- `verifyci/interface/ingress.py`
- `verifyci/interface/limits.py`
- `tests/integration/test_fastmcp.py`
- `tests/integration/test_fastmcp_transport.py`

Design:
- Audit tool registrations and budget wrappers across both servers. The probe
  found six tools registered in both layers with identical caps and gates,
  so no endpoint porting is expected; if the audit finds a gap, port the
  missing handler or middleware check into `fastmcp_server.py`.
- Keep `fastmcp_server.py` as the single source of truth for transport,
  authentication (loopback guard, bearer middleware), stdio versus HTTP
  dispatch, and input pre-validation.
- Replace the body of `mcp_server.py` with a deprecated compatibility facade
  that delegates to `fastmcp_server.py` so existing CLI and external callers
  do not break. Mark it deprecated in the module docstring.
- Preserve fail-closed behavior in `limits.py` (`ExecutionBudget`,
  deadlines) and `ingress.py` (diff complexity gates). Do not move budget
  enforcement outward; it currently runs deeper in `run_verify` and must
  stay there.

Verification gate:
- `uv run pytest tests/integration/test_fastmcp.py tests/integration/test_fastmcp_transport.py tests/interface/test_execution_budgets.py -v`

## 5. Section 3 — Benchmark Artifact Hygiene and Container Pinning

Objective: decouple multi-megabyte embedding caches from git tracking and pin
the container base digest.

Target files:
- `.gitattributes`
- `.gitignore`
- `benchmarks/beir/embedding_cache_nomic_embed_text.json` (1.26 MB tracked)
- `benchmarks/beir/eval_harness.py`
- `benchmarks/patch_corpus/base/Dockerfile`

Design:
- Configure `.gitattributes` for Git LFS tracking of `*.json` cache files.
  The primary resolution is LFS: remove the `.gitignore` negation exception
  and track `embedding_cache_nomic_embed_text.json` in LFS so fresh clones
  stay lightweight. If LFS is unavailable in a given runner, fall back to
  on-demand generation via the lazy loader below.
- Update `benchmarks/beir/eval_harness.py` (around line 181) to lazily
  generate or load the cache when missing instead of eagerly constructing
  `CachedEmbeddingProvider`. Fix `verifyci/retrieval/provider.py` whole-file
  `json.load` at startup to support the lazy path.
- Pin `FROM python:3.12-slim` in `benchmarks/patch_corpus/base/Dockerfile`
  to an explicit `@sha256:` digest for an immutable, distroless-compatible
  base.

Verification gate:
- `uv run pytest tests/evaluation/test_beir_harness.py -v`

## 6. Final Release and Adjudication Gate (Chat.md Phase 6)

Before concluding v1 remediation, run the full repository adjudication and
release validation pipeline:
1. `uv run pytest` (full unit, contract, adversarial, and integration suites).
2. `uv run pytest .opencode/skills/tests/test_vc_acceptance.py -v` if present.
3. `uv run python scripts/adjudicate_cap.py` and
   `uv run python scripts/adjudicate_performance_evidence.py` if present.
4. Build the evidence bundle and run `python scripts/validate_release.py`.

## 7. Out of Scope

- VerifyCI v2 clean-slate work (U-SSA, DuckDB/LanceDB store, egglog, Z3 SMT
  prover, BYO-AI protocols, Wasm sandbox, DSSE/Sigstore anchoring).
- New flagship features from Chat.md sections 3–4 (auto-repair synthesis,
  polyglot bridge, live secret verification, coverage-guided blast radius)
  except where Phase 1 shims touch the same files.
- Rewriting placeholder benchmark stubs into real tests.
- Mutating ground-truth corpus files or `*_SHA256` manifests.

## 8. Execution Constraints

- Contract-first: changes to shared schemas go through
  `verifyci/contracts/` with contract tests.
- Determinism: no unordered iteration or unpinned timestamps in canonical
  payloads.
- Separate commits for remediation versus benchmark refreshes.
- Each section lands only when its verification gate passes with zero
  regressions.
