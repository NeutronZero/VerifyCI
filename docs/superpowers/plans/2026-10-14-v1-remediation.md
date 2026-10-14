# v1 Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute the v1 remediation spec with thin shims, a formalized MCP facade, and artifact hygiene, ending with a green release gate.

**Architecture:** Keep all public import paths working while deleting duplicated logic: five latency fixtures become re-export shims, `measure.py` attributes live sources directly, `mcp_server.py` becomes a deprecated facade over `fastmcp_server.py`, and embedding caches move to LFS with lazy loading.

**Tech Stack:** Python 3.12, uv, pytest, Git LFS, Docker (digest pin only).

**Spec:** `docs/superpowers/specs/2026-10-14-v1-remediation-design.md`

## Global Constraints

- `v1.0-evidence-baseline` tag and artifacts are immutable; never rewrite them.
- Remediation commits and benchmark refresh commits stay separate.
- Gates are fail-closed; uncertainty never passes.
- No frozen-label, snapshot, workload, or oracle rewrites to force a pass.
- Contract-first: shared schema changes go through `verifyci/contracts/` with contract tests.
- Determinism: no unordered iteration or unpinned timestamps in canonical payloads.
- Test runner is `uv run pytest`; release check is `python scripts/validate_release.py`.

## Review Focus

- External scripts doing `from benchmarks.latency.fixture.<mod> import X` expect the same names to import after shimming; Task 1 adds a shim parity test.
- `benchmarks/latency/h3_profile.py` reads `(M.FIXTURE / "workload.py")` bytes for preflight shape and expects real generator source, not a 3-line shim; Task 1 keeps `workload.py` real and adds a non-empty-bytes test.
- Callers importing `create_mcp_server` from `verifyci.interface.mcp_server` with existing kwargs expect identical behavior plus a deprecation warning, not a break; Task 2 adds a signature-parity test.
- Air-gapped CI without LFS or network expects the `hash`/`zero-ai` path and a cache miss to rebuild silently, never hard-fail; Task 3 adds a missing-cache test.
- `CachedEmbeddingProvider(base, cache_path=None)` callers expect in-memory-only mode after the lazy refactor; Task 3 adds a `None`-path test.

---

### Task 1: Fixture shims with live-source attribution

**Files:**
- Modify: `benchmarks/latency/fixture/extractor.py`
- Modify: `benchmarks/latency/fixture/graph_store.py`
- Modify: `benchmarks/latency/fixture/intent_align.py`
- Modify: `benchmarks/latency/fixture/env.py`
- Modify: `benchmarks/latency/fixture/provider.py`
- Modify: `benchmarks/latency/fixture/workload.py` (keep real, align drift only)
- Modify: `benchmarks/latency/measure.py` (hash live sources, not fixture copies)
- Modify: `benchmarks/latency/h3_profile.py` only if it hashes fixtures (keep workload-bytes read)
- Modify: `tests/evaluation/test_latency_repro.py` (shim-parity gate, not method-body equality)
- Test: `tests/evaluation/test_latency_repro.py`
- Test: `tests/evaluation/test_optimizations_equivalence.py`
- Regenerate (separate benchmark commit): `benchmarks/latency/results.json`

**Interfaces:**
- Consumes: live `verifyci.ingestion.extractor`, `verifyci.storage.graph_store`, `verifyci.verification.intent_align`, `verifyci.retrieval.provider`, `verifyci.env`, `verifyci.orchestration.scheduler`.
- Produces: fixture shims exposing identical public names; `measure.py:FROZEN_SOURCES` mapping each name to its live file path; refreshed `results.json` with live-source hashes.

- [ ] **Step 1: Write failing shim-parity test in `tests/evaluation/test_latency_repro.py`**

```python
def test_fixture_shims_reexport_live_api():
    import importlib
    pairs = [
        ("benchmarks.latency.fixture.extractor", "verifyci.ingestion.extractor",
         ["extract_entities", "extract_edges"]),
        ("benchmarks.latency.fixture.env", "verifyci.env",
         ["env_name", "get_env"]),
        ("benchmarks.latency.fixture.provider", "verifyci.retrieval.provider",
         ["EmbeddingProvider", "HashEmbeddingProvider", "SentenceTransformerProvider",
          "OllamaEmbeddingProvider", "CachedEmbeddingProvider", "default_dense_provider"]),
        ("benchmarks.latency.fixture.graph_store", "verifyci.storage.graph_store",
         ["GraphStore", "latest_revision_id"]),
        ("benchmarks.latency.fixture.intent_align", "verifyci.verification.intent_align",
         ["evaluate_invariants", "score_labeled"]),
    ]
    for fix_name, live_name, symbols in pairs:
        fix, live = importlib.import_module(fix_name), importlib.import_module(live_name)
        for sym in symbols:
            assert getattr(fix, sym) is getattr(live, sym), (fix_name, sym)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/evaluation/test_latency_repro.py::test_fixture_shims_reexport_live_api -v`
Expected: FAIL (fixture modules are still full copies, not re-exports; `is` identity fails)

- [ ] **Step 3: Implement the five shims, each a re-export with `__all__`**

Exact pattern per file (names per Step 1 lists; `graph_store`/`intent_align` re-export the two listed symbols plus any other public name the executor finds imported from that fixture via repo grep — nothing in-repo imports them, so the listed sets are sufficient):

```python
"""Deprecated frozen copy. Thin re-export of the live module (v1 remediation)."""
from verifyci.ingestion.extractor import extract_edges, extract_entities

__all__ = ["extract_edges", "extract_entities"]
```

- [ ] **Step 4: Align `workload.py` drift, keep it real**

In `benchmarks/latency/fixture/workload.py`, rename the `_emit` payload key `type` to `event_type` and widen `_topo_order`/`_levels` annotations to `dict[str, Any]`, matching `verifyci/orchestration/scheduler.py`. Do not shim this file: `measure.py:116` and `h3_profile.py:24` read its bytes. Verify with:

Run: `uv run pytest tests/evaluation/test_latency_repro.py::test_fixture_shims_reexport_live_api -v`
Expected: PASS for the five shims (workload stays real, no parity assertion on it)

- [ ] **Step 5: Point `measure.py` attribution at live sources**

In `benchmarks/latency/measure.py`, replace `FIXTURE`-based `frozen_sources` hashing (line 298) with a name-to-live-path map for the five modules plus `workload.py` bytes, e.g. `LIVE_SOURCES = {"extractor.py": ROOT / "verifyci/ingestion/extractor.py", ...}` plus `workload.py` from `FIXTURE`. Keep the `results.json` key name `frozen_sources`. Update `test_frozen_sources_match_working_tree` accordingly: assert shim parity (Step 1 test) and assert the recorded hashes equal the live files, not fixture copies.

- [ ] **Step 6: Run the default gates (no rerun)**

Run: `uv run pytest tests/evaluation/test_latency_repro.py tests/evaluation/test_optimizations_equivalence.py -v`
Expected: PASS with `VERIFYCI_LATENCY_RERUN` unset (rerun test skips)

- [ ] **Step 7: Commit remediation (no baseline files)**

```bash
git add benchmarks/latency/fixture benchmarks/latency/measure.py benchmarks/latency/h3_profile.py tests/evaluation/test_latency_repro.py
git commit -m "Replace latency fixtures with live re-export shims"
```

- [ ] **Step 8: Refresh baseline in a separate benchmark commit**

Run: `set VERIFYCI_LATENCY_RERUN=1 && uv run pytest tests/evaluation/test_latency_repro.py -v` (regenerates `benchmarks/latency/results.json` via `measure.py` on this host), then:

```bash
git add benchmarks/latency/results.json
git commit -m "Refresh latency baseline hashes after fixture shim remediation"
```

---

### Task 2: MCP facade formalization

**Files:**
- Modify: `verifyci/interface/mcp_server.py` (deprecated facade)
- Modify: `verifyci/interface/fastmcp_server.py` (canonical; port gaps only if audit finds any)
- Test: `tests/integration/test_fastmcp.py`
- Test: `tests/integration/test_fastmcp_transport.py`
- Test: `tests/interface/test_execution_budgets.py`

**Interfaces:**
- Consumes: `verifyci.interface.ingress.validate_*_ingress`, `verifyci.interface.limits` caps and `ExecutionBudget`.
- Produces: `create_mcp_server(...)` with its existing signature preserved, emitting `DeprecationWarning` and delegating to `create_fastmcp_server`; the six tools (`code.search`, `code.definition`, `graph.query`, `verify.diff`, `task.run`, `task.status`) behave identically.

- [ ] **Step 1: Write failing signature-parity test**

```python
def test_mcp_server_facade_preserves_signature():
    import inspect
    import verifyci.interface.mcp_server as legacy
    assert "create_mcp_server" in legacy.__all__
    sig = inspect.signature(legacy.create_mcp_server)
    assert {"graph", "store", "node_map", "ledger", "entities"} <= set(sig.parameters)
```

(Executor: read the actual `create_mcp_server` definition at `mcp_server.py:426` first; if the parameter set differs, use the exact set found there.)

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/integration/test_fastmcp.py::test_mcp_server_facade_preserves_signature -v`
Expected: FAIL with an assertion error (facade not yet implemented)

- [ ] **Step 3: Implement `create_mcp_server` in `verifyci/interface/mcp_server.py` as a deprecated facade**

Exact requirements: keep the module path, `__all__` names, and `create_mcp_server` parameter list byte-identical; body emits `DeprecationWarning("use verifyci.interface.fastmcp_server.create_fastmcp_server")` and delegates to the canonical implementation. Port any tool handler the audit finds missing into `fastmcp_server.py` first (probe found none missing — same six tools, same caps/gates — so this is normally a no-op).

- [ ] **Step 4: Run the gates**

Run: `uv run pytest tests/integration/test_fastmcp.py tests/integration/test_fastmcp_transport.py tests/interface/test_execution_budgets.py -v`
Expected: PASS, including the new parity test

- [ ] **Step 5: Commit**

```bash
git add verifyci/interface/mcp_server.py verifyci/interface/fastmcp_server.py tests/integration/test_fastmcp.py
git commit -m "Deprecate mcp_server in favor of canonical fastmcp_server"
```

---

### Task 3: Artifact hygiene and container pin

**Files:**
- Modify: `.gitattributes` (LFS for `benchmarks/beir/embedding_cache_*.json`)
- Modify: `.gitignore` (remove the `!benchmarks/beir/embedding_cache_nomic_embed_text.json` exception)
- Modify: `benchmarks/beir/eval_harness.py` (`make_provider`, line ~172-181: lazy cache)
- Modify: `verifyci/retrieval/provider.py` (`CachedEmbeddingProvider.__init__`, line ~137-150: tolerate missing file)
- Modify: `benchmarks/patch_corpus/base/Dockerfile` (pin digest)
- Test: `tests/evaluation/test_beir_harness.py`

**Interfaces:**
- Consumes: `CachedEmbeddingProvider(base, cache_path)`.
- Produces: lazily-loaded cache that rebuilds silently on miss; LFS-tracked cache files; digest-pinned Dockerfile.

- [ ] **Step 1: Write failing missing-cache test**

```python
def test_make_provider_rebuilds_silently_on_cache_miss(tmp_path):
    from benchmarks.beir.eval_harness import make_provider
    missing = tmp_path / "no_cache_here"
    provider = make_provider("hash", missing)
    assert provider is not None
```

(Executor: check `make_provider`'s real signature at `eval_harness.py:172` first — it takes `(name, cache_dir)`; the `"hash"` branch must not touch the network. Adjust the call to match the exact signature found.)

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/evaluation/test_beir_harness.py -v -k cache_miss`
Expected: FAIL with an error or assertion (provider construction requires the cache file to exist)

- [ ] **Step 3: Implement lazy cache in `CachedEmbeddingProvider.__init__`**

Exact behavior: if `cache_path` is `None`, stay in-memory-only; if the file is missing or corrupt, start empty and rebuild silently (the current code already rebuilds silently per its docstring — preserve that, do not raise). In `eval_harness.make_provider`, do not construct the provider eagerly at import; construct on first use and pass the cache path without requiring the file to exist.

- [ ] **Step 4: Move caches to LFS**

Add to `.gitattributes`: `benchmarks/beir/embedding_cache_*.json filter=lfs diff=lfs merge=lfs -text`. Remove the `.gitignore:11` negation line. Run `git lfs track` equivalent by hand-editing (no new tooling dependency): `git add .gitattributes .gitignore benchmarks/beir/embedding_cache_nomic_embed_text.json`.

- [ ] **Step 5: Pin the Dockerfile digest**

Resolve the current `python:3.12-slim` digest (`docker buildx imagetools inspect python:3.12-slim --format '{{json .Manifest}}'` or the registry API), then change `Dockerfile:1` to `FROM python:3.12-slim@sha256:<resolved>`. Record the digest in the commit message body.

- [ ] **Step 6: Run the gate**

Run: `uv run pytest tests/evaluation/test_beir_harness.py -v`
Expected: PASS, including the new cache-miss test

- [ ] **Step 7: Commit**

```bash
git add .gitattributes .gitignore benchmarks/beir/eval_harness.py verifyci/retrieval/provider.py benchmarks/patch_corpus/base/Dockerfile tests/evaluation/test_beir_harness.py
git commit -m "Move embedding caches to LFS with lazy loading and pin base digest"
```

---

### Task 4: Full release gate

**Files:**
- None (verification only).

**Interfaces:**
- Consumes: Tasks 1–3 deliverables.
- Produces: green release evidence.

- [ ] **Step 1: Run the full suite**

Run: `uv run pytest`
Expected: PASS, zero regressions

- [ ] **Step 2: Run skill acceptance if present**

Run: `uv run pytest .opencode/skills/tests/test_vc_acceptance.py -v`
Expected: PASS or SKIP with reason if the path does not exist (do not create it)

- [ ] **Step 3: Adjudicate and validate**

Run: `uv run python scripts/adjudicate_cap.py`
Expected: PASS with no capability drift attributable to remediation
Run: `python scripts/validate_release.py`
Expected: PASS
