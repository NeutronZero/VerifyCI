# Changelog

## Unreleased — dense-arm diagnostic (no new subsystems)

Suite 148 → 155. Trigger: real-repo queries printed all-0.000 scores with a
genuine top-5 miss. Diagnosis first, per the review:

- Dense arm healthy (norms 1.0, cosine 0.36 on shared trigrams). The 0.000
  was the reranker's score passthrough — it sorted by overlap but returned
  input `score=0.0` objects. Rerank now attaches its own scores (both backends).
- Miss was candidate generation, twice: `LIMIT 5000` hid 1676/6676 entities;
  whitespace tokenization never matches `beam search` against
  `beam_search_paths`. Corpus uncapped + scoped to latest revision; shared
  identifier tokenizer (`retrieval/textnorm.py`) for BM25 and overlap scorer.
- Querying now scopes corpus and graph build to the latest revision
  (superseded rows are history, not answers).
- Per-arm ranks recorded in `benchmarks/real_repo.md` (dense 7/1/1, BM25
  1/1/4 — both arms contribute; fused rank 1 on all three).
- Regression fixture for the UTF-16 garbage diff; `get_entity_as_of` vs
  `get_current_entity` split with independent tests.

Target: Graph-RAG copy (920 files staged; 472 ingested). Full numbers in
`benchmarks/real_repo.md`; ground truth in `benchmarks/score_real_repo.py`.

- Ingest: 472 files → 6766 entities + 10026 edges in 51.1s (14.8 MB SQLite);
  DB rows match emitted counts 1:1. Incremental (1 file changed): 471
  skipped, 6641 carried, complete, parent linked, 5.9s.
- Extraction: TP=149 FP=0 FN=0 (P/R 1.00) over 149 hand-annotated entities.
- Queries: end-to-end with EvidencePack, but ranking is weak (score ties at
  0.000; 1/3 spot-checks relevant-first, one genuine top-5 miss). Recorded
  as the baseline to beat with real embeddings.
- Real 166-line refactor diff → `PASS` / `COMPLETED` (69 entities grounded).
- Measuring found and fixed same session: duplicate IMPORT collapse (~90
  rows), call-site edge collapse (~1355 rows), per-row commit cost
  (270s → 51s full, 454s → 5.9s incremental), deleted entities never
  closing, asOf queries hiding valid-time history behind `t_expired`.

Suite 137 → 146. All fixes reproduced by running code first.

```
$ python -m pytest tests/ -q
........................................................................ [ 98%]
..                                                                       [100%]
146 passed in 1.26s
```

### Fixed
- Policy FAIL vs INCONCLUSIVE: `require_deterministic_checker` no longer
  tests "a certificate verified" but "a deterministic checker executed"
  (`CheckResult.deterministic`, default True; LLM-opinion checks set False).
  Rejection vs inability is then separated: an *unverified certificate*
  means the checker couldn't establish anything (ungrounded diff), while a
  failed invariant verdict means rejection. Rejections → FAIL
  (`blocking_check_failed`); inability alone → INCONCLUSIVE
  (`checks_ran_but_nothing_established`); nothing executed → INCONCLUSIVE
  (`no_deterministic_checker_executed`). Ghost-file diffs stay INCONCLUSIVE;
  secret-bearing diffs FAIL even when the certificate doesn't verify.
- Dropped invariant `blocking` flags now propagate: `evaluate_invariants`
  ignored `Invariant.blocking`, so every invariant failure behaved as
  blocking (this alone turned ghost diffs into FAILs). Non-blocking
  invariant failures route to HUMAN_REVIEW as designed.
- Evidence cites source: entities store a `snippet` (source lines) in
  metadata at ingest; certificates cite it (truncated to 500 chars) instead
  of the bare symbol name. Working-tree independent by construction.
- Metrics honesty: `detection_recall/precision` compute against labeled
  ground truth (`score_labeled`, or `expected_violated=`); without labels
  both report 0.0 ("unmeasured"). Labeled gate test: 6 cases, recall 1.0,
  precision 1.0 (gates ≥ 0.90 / ≥ 0.85).
- Ingest benchmark covers C/Markdown: `benchmarks/ingest_repo.py` ingests
  all supported extensions; extraction ground truth gains `util.c`
  (TP=13 FP=0 FN=0, P/R 1.00). Fixed a real C bug found while doing so:
  return-type mistaken for function name; `typedef` now yields TYPE entities.
- Identity `scope` documented as a V1 correction in `contracts/README.md`
  (backward compatible; golden vectors unchanged).
- `ExecutionTrace.conditions` reserved for V1.1 CFG/DFG guards; producers
  leave it empty instead of storing traversal direction.
- Docs: `benchmarks/retrieval.md` (measured numbers + gate status),
  `extraction.md` raw outputs, top-level `README.md`, `pyproject.readme` →
  README.

## Unreleased — V1 completion pass (second external audit)

Closes the ten findings from the implementation-vs-plan audit. Suite 82 → 137.
Decisive loop reproduced on `samples/test-repo`: mapped clean diff → `PASS` /
`COMPLETED`, secrets diff → `FAIL` / `FAILED`, unknown-file diff →
`INCONCLUSIVE`; `aci query` returns a populated EvidencePack.

### Fixed
- Diff-aware verifier: reasoner premises/traces/evidence derive from
  `+++`-named files mapped onto graph entities (`verification/diffmap.py`).
  Gibberish, empty, and unknown-file diffs → `inconclusive`. Traces are
  call-flow paths (CALLS/REFERENCES/IMPORTS/INHERITS/DEPENDS_ON only) from
  changed entities — shared traversal in `graph/traverse.py`, also used by
  blast radius (CONTAINS/HAS_NAME no longer pollute callers; coverage-gap no
  longer counts the changed files themselves).
- Extraction: C `function_declarator` names + `type_identifier` structs,
  METHOD for class-enclosed functions (all languages), annotation-free params,
  optional parent `scope` in identity (backward compatible), Markdown/text
  ingest. Benchmark honestly 1.00/1.00 (TP=11 FP=0 FN=0, scored types
  documented); samples gain `src/util.c` + `README.md` (38 entities, 3 languages).
- Temporal closure: re-ingest links `parent_revision_id`, closes superseded
  entity versions *and* edges (logical-identity matching — endpoints embed the
  revision), writes anchors + parent→current deltas. Incremental ingest carries
  unchanged files forward (re-keyed) so new revisions stay complete; revision
  identity still covers the full manifest in both modes.
- SBOM reaches the graph: `GraphBuilder` materializes string endpoints as
  external nodes; DEPENDS_ON edges traversable; vuln impact matches packages
  from graph DEPENDS_ON edges; `aci vuln --import findings.json` populates the
  offline cache (never fetches).
- Wiring: `verify-diff`/`run`/`task.run` load the real graph and pass
  graph+node_map+entities+invariants+diff into every gate; `aci run --diff`;
  scheduler executes independent nodes concurrently per topological level and
  persists the ledger to the events table; `lower_to_dag` keeps
  config/pre-commit/depends_on. Real invariant checkers (`secrets_scan`,
  `provenance_check`, `forbid_call:`, `forbid_import:`), fail-closed.
- Retrieval: `aci query` runs real dense (deterministic offline hash
  embeddings via `VectorStore` contract) + BM25 + graph → RRF → rerank over
  real text, and returns EvidencePack counts. Retrieval micro-benchmark
  (`benchmarks/retrieval_eval.py`): recall@5 0.80, nDCG@10 0.866 vs
  dense-only 0.877 — parity band tested, paraphrase gap documented.
- Memory: 44 tests in `tests/memory` (equivalence matrix, tamper at every
  position, anchor+delta byte ratio < 50% measured, store round-trip);
  fixed `insert_event` placeholder count (event persistence never worked) and
  nearest-anchor resume.
- Contracts: `jsonio` (Enum-safe serialization + round-trips), pydantic
  `validate()` over frozen dataclasses, `Event.payload` typed Optional.
- MCP: real FastMCP transport (`src/interface/fastmcp_server.py`, 6 tools) +
  `aci serve` (stdio/http); OTel spans on `code.search`/`verify.diff`/
  `task.run`; dict-server dense path no longer copies BM25.
- Docs: top-level `README.md` (scope boundary stated), `extraction.md`
  corrected (METHOD emitted; scored-type scope), `pyproject.readme` → README.

### Honestly still pending (gates needing scale, models, or time)
- BEIR-scale nDCG gate (+5pts) and 50-query Recall@5: needs real embeddings
  + judgments; micro-benchmark is regression protection only.
- Learned cross-encoder (V1.1), SPLADE/HyDE (V1.1), temporal scheduler (V1.1).
- OSV online refresh opt-in (V1.1); Ed25519 attestation (V1.1).
- Rename detection, full CFG/DFG, LightGBM reranker, contract synthesis (V1.2).
- Comprehension gate, adversarial cross-model review (V1.1).

## 2026-09-28 — Semantic correctness fixes (external review)

Four issues found by independent review of the shipped archive; all fixed,
plus a follow-up incremental-parser wiring fix. Suite grows 39 → 64 → 77 → 82.
Per-dir: contracts 15, integration 28,
ingestion/retrieval/memory/verification/orchestration/storage/evaluation 39.

### Fixed
- Terminal-state conflation: gated runs reported `COMPLETED` with decision
  `INCONCLUSIVE`. `TaskStatus` gains terminal `HUMAN_REVIEW` / `INCONCLUSIVE`;
  scheduler ends gated-no-evidence runs `INCONCLUSIVE`, review-routed runs
  `HUMAN_REVIEW`. Execution status and `VerificationDecision` no longer conflate.
  `task.run` (CLI + MCP) polls all terminal states and returns the decision.
- Vacuous certificate: any non-None graph yielded a verified `pass` with
  `["entry","exit"]` traces and no evidence. Reasoner now runs 4 real
  deterministic checks (graph_structure, premise_grounded, trace_supported,
  evidence_coverage); traces enumerate graph node identities; evidence built
  from node file/hash metadata; `certificate_verified` requires all checks
  passed + traces + evidence + supported conclusion. Opaque/None graph and
  empty diff → `inconclusive`. Wrong-behavior test rewritten; 5 behavioral
  certificate tests added.
- Timestamp-derived revisions: `create_revision("repo")` twice gave different
  IDs. Identity is now `SHA256(canonical manifest {repository_id, commit_id,
  parent, sorted files[{path, source_hash}], ingestion_config_hash})`;
  timestamp is metadata only. Ingest (CLI + benchmark) is two-pass:
  collect → manifest → revision → parse/insert. Same state → same ID;
  one-byte change → new ID. 5 revision tests added.
- Reranker honesty: lexical overlap scorer renamed to `OfflineReranker`
  (explicit `backend == "offline"`); `CrossEncoderReranker` is now a provider
  that loads a local model only when explicitly named and resolvable without
  download, else delegates offline. MCP reports `rerank:<backend>`.
- Minor: `_row_to_edge` dropped `revision_id` (query path crashed);
  rustworkx neighbor normalization (payloads vs indices); OTel semconv
  offline fallback; Python `argument_list` inheritance; cargo/maven/go
  dependency parsers; SQLite-backed vulnerability cache.
- Follow-up: `IncrementalParser` reached into nonexistent
  `TreeSitterParser.parser` attribute (AttributeError on the incremental path).
  `TreeSitterParser.raw_parser(language)` now exposes the underlying parser
  explicitly; `IncrementalParser` passes `old_tree` through it. 5 wiring tests
  (fake-parser, no tree-sitter install needed). Also fixed `_collect()`
  return annotation (3-tuple).
- Tests upgraded from existence to behavioral: gated DAG ends INCONCLUSIVE
  (not COMPLETED), ungated DAG COMPLETED with no decision, budget breach
  FAILED, certificate trace/evidence identity assertions.

### Maturity (revised)
- Contracts 🟢, canonical hashing 🟢, identity 🟢, persistence 🟢
- Parser 🟡 (requires `tree_sitter_python` in env), extraction 🟢/🟡, CPG 🟢/🟡
- Temporal 🟡 (valid_until/t_expired filtered; full transaction-time audit pending)
- Vuln cache 🟢 (offline SQLite), retrieval 🟡, RRF 🟢, reranker 🟡 (offline backend)
- Replay 🟢/🟡, invariants 🟡, certificate 🟢/🟡 (rule stands; adversarial review V1.1)
- Policy 🟡, scheduler 🟢/🟡, executor 🟡, MCP 🟡, OTel 🟡 (compat layer, not every-span proof)
- End-to-end V1 loop 🟡 (skeleton runs; decisive real-repo → FAIL/PASS test pending)

### Not yet (unchanged scope, still deferred per PLAN.md)
- Learned cross-encoder weights, SPLADE-Code/HyDE (V1.1)
- Ed25519 attestation, OSV online refresh opt-in (V1.1)
- Rename detection, full CFG/DFG, LightGBM reranker (V1.2)
- Anchor+delta storage-ratio proof, nDCG benchmark vs dense-only

### Test output
```
$ python -m pytest tests/ -q
........................................................................ [ 87%]
..........                                                               [100%]
82 passed in 0.55s
```
Note: tree-sitter-dependent cases (ingestion) require `tree_sitter_python`;
in envs without it they error at fixture setup, unrelated to these changes.

## 2026-09-27 — Scaffold + Walking Skeleton

### Maturity
- Phase 0 contracts: implemented
- Phase 1 ingestion: working on sample repo
- Phase 2 retrieval: primitives implemented, not benchmarked end-to-end
- Phase 3 memory: prototype (replay traverses chains)
- Phase 4 verification: skeleton (semi-formal + blast radius wired, invariants execute queries)
- Phase 5 MCP/OTel: interface skeleton (MCP handlers call real subsystems)

### Present
- `src/contracts/` — Phase 0 schemas (entity, edge, event, canonical, identity, verification_ir, task_ir, evidence, config, scheduler, provenance, memory_types, graph_schema)
- `src/ingestion/` — parser (incremental with old_tree), extractor (CONTAINS, CALLS_DIRECT, IMPORTS, INHERITS), language, dependency
- `src/graph/` — builder with node_map
- `src/storage/` — graph_store (bitemporal asOf query), metadata, revision (parent_revision_id)
- `src/retrieval/` — provider, dense, sparse, fusion, blast_radius (node_map), evidence, graph_retriever (node_map)
- `src/memory/` — ledger, replay (chain traversal), snapshot, projections
- `src/verification/` — semi_formal_reason (real paths), policy (respects policy fields), intent_align (executes queries), verification_ir, evidence_verifier
- `src/orchestration/` — planner, scheduler, executor (real verify.diff), events, compiler
- `src/tools/` — registry, sandbox, shell, file_read, file_write, llm
- `src/interface/` — mcp_server (6 tools, real handlers), cli (partially wired), http
- `src/observability/` — genai_semconv, tracing, metrics, telemetry
- `tests/contracts/` — canonical + identity golden vectors (11 tests)
- `tests/integration/` — ingestion, retrieval, memory, verification, orchestration (28 tests)
- `benchmarks/` — extraction benchmark with real numbers
- `samples/test-repo/` — 3 Python files, 11 entities ground truth
- `pyproject.toml` — project config with `aci` CLI entry point

### Fixed since last review
- Incremental parser now uses old_tree for incremental re-parse
- Revision lineage: parent_revision_id parameter added
- Replay traverses delta chains (rev1→rev2→rev3→rev4)
- Semi-formal verifier constructs real paths through graph nodes
- Invariant checking executes real graph queries
- PolicyEvaluator respects on_failure, on_inconclusive, require_deterministic_checker
- Pre-commit hook calls real semi-formal + blast radius
- MCP handlers call real subsystems (graph, store, verification)
- Bitemporal asOf query uses valid_from <= asOf

### Not yet implemented
- Persistent vulnerability cache (still in-memory dict)
- Full bitemporal semantics (valid_until, t_created, t_expired in queries)
- Anchor+delta storage metrics
- OTel propagation proof on every span
- CLI fully wired to all subsystems
- Extraction benchmark on larger repo (current: 3 files, 11 entities)

### Test output
```
$ pytest -v tests/
============================= test session starts ==============================
collected 39 items

tests/contracts/test_canonical.py::test_canonical_event_bytes_matches_golden_vector PASSED
tests/contracts/test_canonical.py::test_event_hash_matches_golden_vector PASSED
tests/contracts/test_canonical.py::test_canonical_excludes_attestation PASSED
tests/contracts/test_canonical.py::test_canonical_sorted_keys PASSED
tests/contracts/test_identity.py::test_logical_entity_id_stable_across_revisions PASSED
tests/contracts/test_identity.py::test_logical_entity_id_changes_with_name PASSED
tests/contracts/test_identity.py::test_logical_entity_id_changes_with_file PASSED
tests/contracts/test_identity.py::test_logical_entity_id_changes_with_repository PASSED
tests/contracts/test_identity.py::test_logical_entity_id_no_collision_with_separator PASSED
tests/contracts/test_identity.py::test_revision_entity_id_changes_with_revision PASSED
tests/contracts/test_identity.py::test_revision_entity_id_stable PASSED
tests/integration/test_ingestion.py::test_detect_language PASSED
tests/integration/test_ingestion.py::test_compute_source_hash PASSED
tests/integration/test_ingestion.py::test_parser_creates_parsed_file PASSED
tests/integration/test_ingestion.py::test_extract_entities_python PASSED
tests/integration/test_ingestion.py::test_extract_edges_python PASSED
tests/integration/test_memory.py::test_event_ledger_append PASSED
tests/integration/test_memory.py::test_event_ledger_chain PASSED
tests/integration/test_memory.py::test_event_ledger_verify PASSED
tests/integration/test_memory.py::test_replay_engine PASSED
tests/integration/test_memory.py::test_snapshot_store PASSED
tests/integration/test_orchestration.py::test_planner PASSED
tests/integration/test_orchestration.py::test_validate_task_ir PASSED
tests/integration/test_orchestration.py::test_check_permission PASSED
tests/integration/test_orchestration.py::test_budget_manager PASSED
tests/integration/test_orchestration.py::test_lower_to_dag PASSED
tests/integration/test_orchestration.py::test_async_scheduler PASSED
tests/integration/test_orchestration.py::test_executor PASSED
tests/integration/test_orchestration.py::test_mcp_server PASSED
tests/integration/test_orchestration.py::test_tool_registry PASSED
tests/integration/test_retrieval.py::test_bm25_retriever PASSED
tests/integration/test_retrieval.py::test_rrf_fusion PASSED
tests/integration/test_verification.py::test_policy_evaluator_pass PASSED
tests/integration/test_verification.py::test_policy_evaluator_fail PASSED
tests/integration/test_verification.py::test_policy_evaluator_human_review PASSED
tests/integration/test_verification.py::test_semi_formal_reasoner PASSED
tests/integration/test_verification.py::test_semi_formal_reasoner_with_graph PASSED
tests/integration/test_verification.py::test_evaluate_invariants PASSED
tests/integration/test_verification.py::test_verify_evidence_coverage PASSED

============================= 39 passed in 0.29s ==============================
```

### Extraction benchmark
```
$ python benchmarks/run_extraction.py

Results: TP=11 FP=0 FN=0
Precision: 1.00
Recall: 1.00
```

### Ingestion
```
$ python benchmarks/ingest_repo.py
Revision: e87754d6722e8b67
  src\app.py: 1 entities, 0 edges
  src\auth.py: 5 entities, 2 edges
  src\database.py: 5 entities, 3 edges

Total: 11 entities, 5 edges
DB: storage/verifyci.db
```

### Freeze checklist
- [x] 01 contracts/
- [x] 02 canonical serialization
- [x] 03 SQLite schema
- [x] 04 Tree-sitter parser (incremental with old_tree)
- [x] 05 AST extractor (CONTAINS, CALLS_DIRECT, IMPORTS, INHERITS)
- [x] 06 minimal rustworkx graph (node_map exposed)
- [x] 07 ingest one Python repository
- [x] 08 extraction benchmark — precision 1.00, recall 1.00 (name+type matching)
- [x] 09 Dense + BM25 + Graph (node_map connected)
- [x] 10 RRF + cross-encoder
- [x] 11 EvidencePack
- [x] 12 blast radius (node_map connected)
- [x] 13 VerificationReport
- [x] 14 VerificationPolicy (respects policy fields)
- [x] 15 Planner → TaskIR → DAG
- [x] 16 pre_commit → verify.diff (real semi-formal + blast radius)
- [x] 17 MCP server (6 tools, real handlers)
- [ ] 18 OTel (conversation_id on agent spans, not proven on every span)
