# Changelog

## Unreleased — C3: latency protocol; temporal MET, incremental p95 NOT MET

- **Both PLAN latency gates measured** on a frozen 1000-sample protocol
  (`benchmarks/latency/`: config frozen before timing; the five
  measured-path sources sha-pinned in `fixture/`; environment recorded;
  `VERIFYCI_LATENCY=1` required so CI never silently loads grammars).
  No source under `verifyci/` changed.
- **Temporal query at 10K edges: MET.** 10,000 edges / 10,000 temporal
  entity rows / 5.6 MB SQLite, `get_entity_as_of`, hit_rate 1.0:
  median 0.044 ms, p95 0.073 ms, p99 0.151 ms vs a 200 ms limit
  (~3 orders of margin). Cross-machine establishment NOT claimed
  (host-specific; protocol + hashes + env are the portable artifacts).
- **Incremental parse: NOT MET at p95.** Median 33 μs passes (<0.2 ms) —
  and cold full-parse is 3.7 ms, so reparsing IS incremental — but p95
  ~3.8 ms fails the 1 ms limit on every run. Mechanism recorded:
  tree-sitter re-lexes from the mutation to the next change point, so
  early-file edit positions dominate cost (per-line medians 20 μs …
  4.3 ms); split-half shows mild cumulative growth (31→40 μs).
- **p99 instability recorded as evidence, not retuned:** three runs gave
  4.32 / 6.14 / 4.54 ms against the same 5 ms limit (verdict flips
  MET/MIS/MET). The guard pins only the stable claims (median MET, p95
  MIS, temporal MET) plus protocol/source-hash integrity; a 1000-sample
  protocol cannot establish a tail boundary the machine straddles.
  One-shot tree-shape preflight (incremental vs cold) keeps the timing
  honest. `test_latency_repro.py` (opt-in rerun) enforces this.
- Suite 515 (513 + this re-measure guard), ruff clean.

## Unreleased — C2: frozen blast-topology corpus; coverage 0.857, gap reproduced as data

- **Blast-radius coverage measured** against hand-frozen impacted sets
  (`benchmarks/blast_corpus/`: core.py+app.py CALLS topology with
  hub/mids/leaf/far/isolated + cross-file `remote` and method
  `Gateway.handle`; 9 cases covering direct, 2-hop transitive,
  multi-path, zero-impact, def-boundary, tail-insertion, seeding-can-fail,
  cross-file+method). `author.py` regenerates the corpus byte-identically;
  expected sets were derived from the topology + documented contract
  (2 hops, in+out along CALL_FLOW_TYPES, seed excluded) **before** any
  blast run. Traversal untouched — detection path is exactly the gate's.
- **Result:** coverage_all **6/7 = 0.857 → gate NOT MET**;
  coverage_seeded_only **1.000** — traversal is EXACT on every normally
  seeded hunk (direct/transitive/multi-path/cross-file/method/zero-impact,
  FN=0). The single miss is **B6, the pre-labeled tail-insertion gap**:
  pure insertion after `hub`'s last line seeds `changed_entities=[]` →
  risk 0.0 → 6/6 dependents missed. The C1 finding reproduced as frozen
  data; NOT repaired (measurement phase).
- **Disclosed precision artifact (B5, not tuned):** a def-line hunk's
  3 context lines bleed into the adjacent `far` def, seeding {hub, far};
  hub re-enters as far's callee → detected ⊃ expected (1 FP, recall 1.0).
  Root cause documented: hunk context window vs entity-span intersection.
- Zero contract-level FNs (no unannounced miss); regression guard +
  frozen-corpus sha pin the baseline; `VERIFYCI_BLAST_RERUN=1` reproduces
  the report exactly. Measured, not established (7 non-empty cases).
  Suite 513 (was 509), ruff clean.

## Unreleased — C1: frozen patch corpus; first measurement of equivalence + precision

- **Agent-patch equivalence and verification precision went from
  unmeasured to measured**, on a frozen 17-case corpus
  (`benchmarks/patch_corpus/`): `author.py` (difflib against `base/`,
  byte-valid hunks) + `cases.jsonl` with intent, ground truth
  (correct/wrong), category, and expected outcome fixed from the
  documented contract **before any run**. Synthetic stand-ins mimic agent
  failure modes (hallucinated removal, forbidden call/import, hardcoded
  secret, silent semantic drift) and valid maintenance (8 correct / 9
  wrong: 4 deterministic + 4 semantic + 1 decline). Verifier and gate
  frozen throughout; labels were not retuned after seeing results.
- **First measurement (single run, recorded in `results.json`):**
  - **Verification precision 1.00 MET** (4/4 FAILs truly-wrong, 0
    false-positive FAILs on correct patches). Too few FAILs to
    *establish*; deterministic-catch half (4/4) solid.
  - **Patch equivalence 0.875 < 0.90, target unmet** (7/8). The miss is
    the one case below.
  - **All 4 deterministic wrong patches caught** (forbid_call,
    forbid_import, secret, fabricated_removal).
  - **All 4 semantic wrong patches accepted** (false-accept 1.0):
    weakened validation, wrong variable, wrong return, wrong constant.
    This is the first *measured* confirmation of the V1 scope limit
    (proves provenance + impact, not intent) — previously only asserted.
- **C3 structural gap surfaced and reported, not tuned away:** a correct
  `send_email` change (8 callers → expected HUMAN_REVIEW via exposure)
  measured PASS. `run_verify` grounds files path-wise
  (`map_files_to_entity_ids`) but seeds blast hunk-line-wise
  (`seed_entities_for_diff`), so a tail-insertion after a function's last
  line yields `changed_entities=[]` → risk 0.0. Exposure contract never
  applies to that hunk shape. Label kept as HUMAN_REVIEW (frozen);
  divergence is the finding.
- **Reproducibility:** `test_patch_corpus.py` pins the recorded metrics +
  frozen-corpus sha; full re-measure under `VERIFYCI_PATCH_RERUN=1`
  reproduces the report exactly (bit-identical metrics).
- **Conclusion:** equivalence gate NOT met (0.875 < 0.90, and a 17-case
  synthetic corpus cannot establish it); precision measured-met but not
  established (small n). Next real evidence: a recorded-LLM patch corpus.
  509 (508 pass + the opt-in re-measure, skipped unless
  `VERIFYCI_PATCH_RERUN=1`); prior 504, ruff clean.

## Unreleased — B2: frozen BEIR-style retrieval gate, measured at +3.84 pts

- **Eval infrastructure only; retrieval behavior untouched** (no BM25,
  RRF, rerank, or embedding changes). `benchmarks/beir/`: frozen corpus
  (60 codebase docs in production `name file_path` form), graded qrels
  (62 queries), config pinning the protocol (gain 2^g−1 nDCG@10,
  grade≥2 Recall@5, RRF k=60, model `nomic-embed-text`), and a harness
  that reuses production `InMemoryVectorStore`/`rrf_fusion`/`BM25Retriever`
  — it adds no retrieval logic of its own.
- **Frozen before measurement:** corpus+qrels written from file-level
  knowledge before any embedding run; drift guards reject duplicate
  query ids, unknown/empty/unjudged docs, empty relevance sets, and
  condition or model mismatch; corpus/qrels/config sha256 recorded so
  reruns are bit-comparable (confirmed: identical delta on re-run).
- **Live result:** dense-only 0.6220 → hybrid 0.6603 = **+3.84 pts**,
  Recall@5 0.6465 → 0.6707. Below the +5 gate: **measured, target not
  met**. The `established` flag requires non-dry + frozen provider + ≥50
  queries + delta ≥ 0.05 — all recorded in `results.json`. The 5-query
  smoke (0.866 vs 0.877) stays historical, never evidence.
- **No tuning** against the judged set: whether to do retrieval work is
  now an evidence-based decision, not a knob turned to cross +5.
- Tests: `tests/evaluation/test_beir_harness.py` (11: metric formula,
  every drift guard, dry-run/non-frozen never establishes the gate).
  Suite 504 (was 493), ruff clean.

## Unreleased — B1: expanded labeled corpus for invariant recall

- Evaluation-only; scanner (`intent_align.py`) and the verification gate
  frozen — zero source lines changed. New `tests/evaluation/labels/`
  `invariants_v2.jsonl`: 26 cases, 18 expected-violated, labels frozen
  before the single scoring run, 11 distinct positive secret mechanisms
  and the audited triple-quoted pattern capped at exactly one instance.
- Measured once: **recall 16/18 = 0.889, precision 1.00** (v1 baseline
  6/9 reproduced separately and preserved). The only two misses are the
  pre-declared `known gap` cases (unquoted value below the 12-char floor;
  graph relative-import blindness), not post-hoc discoveries.
- Conclusion: 0.889 < 0.90 → **target unmet, and a 26-case corpus would
  not establish the gate even above 0.90** (measured, not established).
  Pinned by `test_v2_target_not_established_documented`.

## Unreleased — retrieval: stop rebuilding, honor edge semantics

Advisory-path only (`retrieval/*` + the MCP search cache). No file under
`verification/`, `graph/`, `memory/`, or `orchestration/` imports these
components; the gate matrix was re-run before/after and every verdict is
unchanged (forged removal → INCONCLUSIVE, secret → FAIL, etc.).

- **BM25 no longer rebuilds per query.** `search()` used to build a fresh
  `Counter(tokens)` for every document on every query (real corpus: 2149
  Counter builds/query → 0 now). Term frequencies are stored at `add()`;
  re-adding an id reconciles document frequency exactly (the old code
  double-counted df and left a stale tf). Ranking ties break on id for a
  deterministic order. Dropped the unused `BM25Index` dataclass.
- **GraphRetriever honors edge types.** It expanded `successors()`/
  `predecessors()` blindly, so a two-hop seed pulled its entire module
  via CONTAINS (and DOCUMENTS). Adjacency now comes from edge payloads
  filtered to semantic types (CALLS/IMPORTS/INHERITS/REFERENCES/USES/...);
  CONTAINS, DOCUMENTS, DEFINES and DEPENDS_ON are structural and pruned.
  Results are scored by hop distance (closer = higher) and deduped. A
  graph exposing only successor/predecessor callables still works via an
  unfiltered fallback. Real graph: `ndcg_at` 2-hop returns 5 semantic
  neighbors and 0 module files.
- **`code_search` reuses the search index.** The long-lived server
  rebuilt the whole BM25 index + texts map on every call (real server:
  4 describes/4 queries → 1). Now cached and keyed on a structural
  fingerprint (`num_nodes`/`num_edges`); an unchanged graph is reused
  (identical, still-correct hits) and any node/edge change busts the
  cache so no stale index is served.
- **Probes:** `tests/retrieval/test_sparse.py`,
  `tests/retrieval/test_graph_retriever.py`,
  `tests/integration/test_search_reuse.py` (14 tests; 7 fail against the
  pre-fix code). Fusion benchmark smoke scores stay a behavioral control,
  not a retrieval gate.
- Suite 490 (was 476), ruff clean.

## Unreleased — rename: `verifyci` primary, `aci` alias, `VERIFYCI_*` env

- **`verifyci` is the primary console script; `aci` stays installed as an
  alias to the same app** (`pyproject.toml`). The Typer prog name is no
  longer hard-coded to `aci`, so `verifyci --help` and `aci --help` each
  report how they were invoked.
- **Canonical env prefix `VERIFYCI_*`, legacy `ACI_*` fallback.** New
  `verifyci/env.py` `get_env()` is the single reader; `ACI_API_TOKEN`
  (http.py) and `ACI_EMBEDDINGS`/`ACI_OLLAMA_URL` (provider.py) route
  through it. Precedence is by presence, not truthiness: an explicit
  `VERIFYCI_API_TOKEN=""` reads as "unset" and is not shadowed by a
  stale `ACI_*` value. Live probe: `VERIFYCI_API_TOKEN`/`VERIFYCI_EMBEDDINGS`
  were ignored before, honored now; legacy `ACI_*` still honored.
- Suite 476 (was 469), ruff clean.

## Unreleased — one skip classifier for every discovery path

- **Skip rules unified.** New `verifyci/ingestion/ignore.py` is the
  single source of truth (`iter_repo_files`, `skipped_dir_names`).
  `aci deps` used to match *absolute* path parts and only skipped
  `.verifyci`, so `node_modules/`, `.venv/`, `build/`, `.git/` manifests
  leaked into deps output while ingest excluded them. Both paths now
  agree; live probe: 4 leaked manifests → 0.
- **Venvs detected by marker.** A `pyvenv.cfg` marks a virtualenv,
  pruned under any name; a directory merely named `venv` is ordinary
  source and ingested.
- **Ambiguous names no longer default-skipped.** `build`, `dist`,
  `target`, `env` are legitimate package names in some repos and were
  removed from `DEFAULT_SKIP_DIRS`. Projects re-skip them with a
  gitignore-style `.verifyciignore` at the repo root.
- **Skips reported.** `aci ingest` prints skipped top-level dirs, so a
  silent zero-file ingest is visible.
- Files moved into a skipped dir disappear from the incremental
  revision (probe); adding content under a skipped dir does not change
  revision identity (probe).
- Suite 469 (was 462), ruff clean.

## Unreleased — revision identity: content vs lineage

- **Content identity separated from lineage.** `revision_id` is now a
  pure function of repository + full file manifest + ingestion config;
  commit id and parent no longer feed the hash. Two ingests of the same
  tree at different commits share one revision (was: distinct ids).
- **Revision rows immutable.** `insert_revision` is `INSERT OR IGNORE`;
  re-ingest never rewrites a stored row's commit/parent.
- **Lineage moved to an append-only `ingests` chain.** New `Ingest`
  contract + `ingests` table + `insert_ingest`/`latest_ingest_id`;
  `latest_revision_id` reads the ingest chain (rowid tie-break), so a
  revert correctly reports the old revision as latest and can never
  create a parent cycle (was: `INSERT OR REPLACE` rewrote the old
  revision's parent → A.parent=B, B.parent=A on revert). Same-state
  re-ingest skips the self-delta and disappearance pass.
- Live chain verified ingest→revision→entity→verify on the real DB;
  cycle probe flips True→False.
- Suite 462 (was 450), ruff clean.

## Unreleased — planner gates once, not 3x

- **Verification runs once per task.** The planner stamped
  `pre_commit_hook_id` on all three steps, so every task ran the
  full reasoner+blast+removal+invariants pipeline 3x (measured live:
  3 `verify` calls per `run_task`, last decision winning by
  accident). Only `verify_change` is gated now; placeholders
  complete without checks. `validate_task_ir` requires at least one
  gated step instead of every step.
- Suite 450 (was 443), ruff clean.

## Unreleased — resolver: no guessed links, no suffix PASS

- **Intra-file resolution stops guessing.** Several same-named
  candidates with no scope match and no unique top-level fallback
  now emit `CALLS_UNRESOLVED` instead of linking `candidates[0]`;
  the post-build resolver links only globally-unique names.
  Single candidates and unique top-level fallbacks still resolve.
- **Suffix-only grounding declines.** `build_semi_check` reports
  `established=False` when a diff file grounds with no exact stored
  path (or several colliding ones), so policy routes to
  INCONCLUSIVE — suffix-grounded diffs never PASS. Exact-path
  grounding unchanged.
- Suite 443 (was 437), ruff clean.

## Unreleased — re-audit fixes: ingestion, evidence, tamper-evidence

- **Incremental carry-forward scoped.** `DEPENDS_ON` edges carry only
  when their source manifest is in the carried set; removed/bumped
  requirements no longer survive as ghosts. `close_deleted_file_version`
  deleted (proven cross-repo over-close; `close_disappeared` covers it
  repo-scoped). Unresolved edges keyed with callee name.
- **Extractor keyed by node span, not `id()`.** `parents` /
  `decorated_sites` use `(type, start_byte, end_byte)`; qualified
  lookup walks down pointer/reference declarators, so
  `Foo* Foo::create()` resolves. C/C++ link as one family.
- **Manifests hardened.** Cargo dotted subtables, Poetry tables,
  `name @ url` / egg fragments, URL/VCS skip, non-dict `package.json`
  tolerated, per-manifest never raises, `tomllib` top-level (3.12+).
- **Evidence you can trust.** Secret and forbid evidence carry real
  new-side line numbers; forbid cites only parser-matched lines
  (`evaluation` no longer cited for `eval`); JSON `"key": "value"`
  secrets detected. Fragment parse gaps (exceptions, ERROR nodes
  with zero refs) route to INCONCLUSIVE, never silent PASS or
  mislabeled FAIL. Diff parsed once per evaluation (lru_cache).
- **Tamper-evidence repaired.** `verify_task_subchain` checks
  internal links plus continuity against the global predecessor, so
  per-task verification is valid and first-event deletion breaks it.
  One ledger per submitted task (no interleave false-BROKEN, correct
  per-task heads). Anchor-file given but empty → fail closed.
  `get_events` ordered by rowid.
- **Named `asOf` works.** `graph_query` / `_resolve_symbol` consult
  time-filtered name lookup; revision-id shortcut only when asOf
  is None.
- **Prefix-agnostic diffs.** `---`/`+++` pairs before `@@` count as
  headers under `--no-prefix` / mnemonic prefixes / plain `-u`.
- **Portability.** Posix logical ids, LF-normalised identity hashing,
  UTF-8 stdin buffer reads.
- **HTTP/stats fail closed.** Bytes `hmac` compare, quoted `as_uri`
  read-only open, missing DB returns `error` (no zero-mask), no DB
  or directory creation on read paths, ingest rejects missing paths.
- **Scheduler.** Block/review outcomes take precedence over
  cancelled-sibling noise; cancel persists before pinning;
  thread-on-timeout limitation documented. `MetadataStore` commits
  owned connections.
- **Small items.** Query prints file:lines, ingest surfaces
  `parse_errors` count, MCP no longer echoes diffs, reported
  revision is the one loaded.
- Suite 437 (was 380), coverage 90% (was 89%), ruff clean.

## Unreleased — audit fixes: fail-closed verification, packaging, hardening

- **Removal provenance closes the outside-hunk bypass.** `-` lines
  outside any `@@` body (or under `@@@` combined headers, now parsed
  and marked approximate) count as unverified, never fabricated:
  before-hunk forged removals went PASS → INCONCLUSIVE. Verified in
  production path (`run_verify`), pinned by regression tests.
- **`secrets_scan` fails closed on multiline secrets.** Triple-quoted,
  backslash, and paren-continued values carrying string literals now
  FAIL; single-line env lookups still pass. Labeled recall 5/9 → 6/9.
  Fixture/test-dir demotion removed: allowlisted secrets FAIL.
- **Forbid rules fail closed on parser errors.** `_added_hits`
  returns None on exception; both call sites reject with
  "fragment parse failed (fail-closed)". `on_failure` restricted to
  `block` (the `warn`-to-PASS conversion is gone). Invariant hits
  carry `file:line:pattern` evidence.
- **Ledger scoped verification fixed.** New `verify_subchain`
  checks links within the task's subchain instead of demanding a
  global-first event, so `verify-chain --task-id` is valid for every
  task, not just the first. Anchor read errors other than missing
  file surface as HEAD_MISMATCH, not absence.
- **Orchestrator hardened.** Review decisions survive later `ok`
  outcomes; `validate_task_ir` rejects hook-less steps; executor
  floors to default invariants; unknown `depends_on` raises;
  per-node timeout (300s default); cancel no longer clobbers terminal
  status; ledger persists only new events in one batch; node work
  offloaded with `to_thread`.
- **HTTP fails closed off-loopback.** Tokenless access allowed only
  from loopback sources; anything else is 401. MCP `verify_diff` /
  `task_run` capped at 1M/100k chars like HTTP; MCP `anchor_file`
  arbitrary-path append removed (CLI-only now).
- **Packaging repaired.** `src/` → `verifyci/` (entry point was
  installing a top-level package named `src`); dropped unused deps
  (`aiosqlite`, `rank-bm25`, `ollama`, `uvicorn`,
  `opentelemetry-sdk/semconv` — semconv stays optional);
  `sentence-transformers` moved to `[embeddings]` extra; floors
  raised to tested versions; `storage/verifyci.db` untracked;
  CI workflow added (3.12–3.14, ruff + pytest); ruff excludes
  deliberate dirty fixture `samples/`.
- Suite 380 (was 334), coverage 89% (was 84%), ruff clean.

## Unreleased — remove revise; scope revisions by repository (B-1)

- **`aci revise` deleted.** A marker command inserting entity-free
  revisions poisoned every global latest-revision lookup. Commit
  recording moves to the authoritative path: `aci ingest --commit
  <sha>` persists `commit_id` on the revision row.
- **Latest-revision selection is repo-scoped.** `resolve_repository`
  derives the repo from `<repo>/.verifyci/*.db` (innermost wins);
  `latest_revision_id` filters by it across graph loads, queries,
  stats, vuln scans, and anchor revision lookup — falling back to
  global only for custom paths with no convention. A newer foreign
  revision in a shared file no longer hijacks another repo's
  commands (pinned with a two-repo single-DB test).
- Suite 334, ruff clean, extraction benchmarks hold (13/142).

## Unreleased — temporal disappearance closure (B-2)

- **Deleted code expires.** New `GraphStore.close_disappeared`
  runs last in ingest against the complete new revision: entities
  whose logical id has no current row get `valid_until`/`t_expired`
  stamped, as do live edges whose endpoint-pair no longer exists.
  `get_entity_by_name` and graph loads stop returning ghosts
  (verified end to end: deleted file + removed call → 2 entities and
  4 edges closed, ghost lookup None, history queryable via `asOf`).
- Supersession (re-observed facts) is untouched; disappearance covers
  only what vanished. Scoped per repository; skipped with no parent
  (fresh/same-state ingest). Carried unresolved references read as
  continuing — incremental graphs keep cross-file visibility, pinned.
  Also self-healing: pre-existing live ghost rows close on next
  ingest. Counts surface in ingest totals (`disappeared_entities`,
  `disappeared_edges`).
- Suite 324, ruff clean, extraction benchmarks hold.

## Unreleased — MCP audit trail and tool-return grounding (A-2)

- **Ledger attached to the served MCP path.** `create_fastmcp_server`
  constructs an `EventLedger` and threads it through, so `task.run`
  executions emit events, persist via the context store, and return a
  real `ledger_head` instead of `None`. One ledger accumulates across
  tasks on the long-lived server; `task_id` separates them and the L2
  subchain verifier reads them back per task.
- **Search → definition chaining works.** `code.search` hits now carry
  `name`, `file_path`, `line_start`, `line_end` (None when the id has
  no loaded entity); `code.definition` and `graph.query` resolve a
  `revision_entity_id` first, then logical id, then name — the id a
  search returns chains directly into definition with no re-derivation.
- Suite 324, ruff clean, extraction benchmarks hold (13/142).

## Unreleased — diff-aware forbid rules (added-line references)

- **Graph-blind spot closed.** `forbid_call` / `forbid_import`
  searched the base graph only, so `+    eval(user_input)` passed
  silently. New `src/verification/added_refs.py` parses each file's
  added lines as a fragment in that file's language (tree-sitter,
  error-tolerant) and collects bare call names plus imported modules;
  a forbidden target introduced by the diff rejects even when the
  graph side established nothing. Graph-side matching kept unchanged
  (pre-existing violations still fail — boy-scout gate, documented).
- **One-sided like secrets_scan, by necessity.** Fail on detection,
  pass otherwise, established always True. The alternative —
  inability when fragments parse with errors — would deflect every
  partial-line C hunk to INCONCLUSIVE and break the decisive matrix.
  Fragment recall gaps are documented in the module, not hidden.
- **Bare-name only, stricter than graph side.** `obj.eval(` carries a
  receiver the fragment cannot resolve, so it never flags; `def eval`
  defines rather than calls. The asymmetry is deliberate and
  documented. Markdown/prose files are never parsed.
- Verified end to end with a repo `invariants.yaml`: added `eval`
  FAILs, clean addition still PASSes. Suite 320, ruff clean,
  extraction benchmarks hold (13/142).

## Unreleased — external static audit fixes (batch 1: gate integrity)

An outside read-through (no execution) produced ~60 findings; every
Critical/High item was re-verified by execution before fixing. Two of
its items were already fixed at HEAD (anchor fail-open, unsurfaced
resolver stats); one was wrong (`deps.py` has no SKIP_DIRS matching).
The rest below, each probed first.

- **Ingest is atomic.** `batch()` rolled back nothing — commit in
  `finally` plus a per-file commit in `MetadataStore.upsert_file`
  left half-populated revisions that every command then loaded as
  "latest". Batch rolls back on exception; upsert no longer commits
  (sole caller runs inside the batch). Pinned.
- **Manifests route before suffixes.** `requirements.txt` matched
  `.txt` ingestible first, so the manifest branch was dead and Python
  dependencies never entered the graph. `SKIP_DIRS` matched absolute
  path parts, so repos under `/build/` (or `env`, `target`) ingested
  zero files silently — now relative directory parts only.
- **Secrets scanner: FPs closed, DoS bounded.** `self.password =
  user_provided_password` and `secret_key = config.SECRET_KEY_NAME`
  both FAILed merges (verified); dotted attribute access on either
  side now excludes the unquoted match (dotted real secrets stay
  covered by JWT/connection-string patterns). The affix repetitions
  are capped at 64 chars: the unbounded form was confirmed quadratic
  (hung past a 300s timeout at 100KB) behind a 1MB unauthenticated
  endpoint. Pinned with a timing test.
- **C/C++ extraction recovers dropped functions.** Pointer/reference
  returns (`char *f`, `T& f`), destructors (`~W`), and operators
  (`operator==`) emitted nothing — whole function sets vanished.
  Declarator descent extended (abstract declarators still silent, so
  function pointers stay out), including params. `struct` joins
  CLASS_NODES (methods, not functions); `typedef Bar Baz` names Baz;
  `import os, sys` emits both modules; `#include` emits IMPORTs
  (forbid_import works for C now); `.h` parses as C++ in production,
  matching what the firmware benchmark always assumed.
- **Call collection: once each, in the right scope.** Nested
  definitions double-attributed inner calls to the outer function;
  the body walk now prunes nested named scopes. Decorator calls
  (`@app.route`) were never captured — scanned via the parent
  decorated_definition. Module- and class-body calls (`if __name__ ==
  "__main__": main()`) attribute to module/class instead of silence.
- **Deferred resolution gated on language.** A Python `obj.add(x)`
  linked the C `add` (probed) — unique-name policy ignored language.
  Candidates must now match the caller's language (languageless test
  fakes still match anything).
- **Incremental carry keeps unresolved refs** (previously dropped:
  every incremental graph lost cross-file visibility), with the
  referenced name in the carried id so parallel refs don't collapse;
  plus the O(n²) set-in-comprehension. Parse errors recorded in
  ingest totals instead of silent. Revision indexes added
  (entities/edges by revision, path, name).
- **Dependency parsers:** pip options skipped (were packages `-r`),
  extras keep versions, cargo inline-table versions + `[dep.x]` /
  workspace sections, maven per-block versions (the lazy optional
  never captured — always "latest") + comment stripping, go `//`
  skipped, npm section in edge ids, corrupt cache reads as no-vulns,
  vuln scan scoped to latest revision with a `truncated` flag.
- **Wiring:** `verify-diff`/`run` exit 0/1/2 (PASS/FAIL/needs-human)
  with `--diff-file`/`-` stdin; `hmac.compare_digest` on the token;
  policy rejects unknown `on_failure`/`on_inconclusive` instead of
  falling through to PASS; `generated_by` defaults to the
  deterministic producer, not `llama3.1`; `aci stats` is read-only
  (no mkdir/schema at client paths); embedding cache gitignored.
- **Line splitting aligned to tree-sitter/git** (`\n`-only) in
  snippets and removal matching; form feeds no longer misalign into
  false "fabricated" verdicts. Pinned.
- Numbers: suite 314, ruff clean (incl. benchmarks), extraction
  TP=13 FP=0 FN=0 (39 raw entities now — the 39th is the new
  `stdlib.h` import), Flask TP=142. Firmware C++ benchmark unrunnable
  (staged checkout gone); its paths are covered by new unit tests.
- Deliberately deferred with reasons: diff-aware forbid rules (needs
  added-line call analysis design, not a regex); MCP audit trail and
  graph refresh (feature surface); `revise` semantics (what an empty
  revision means is a product decision); temporal closure of removed
  calls/files (valid-time redesign); intra-file `candidates[0]`
  fallback and receiver-awareness (precision work, same-file stakes);
  suffix-grounding veto and certificate/docstring labels (charter
  decisions); version-aware vuln matching (semver feature); benchmark
  scoring overhaul and `ingest_repo` dedup (measurement hygiene).

## Unreleased — resolver coverage surfaced; anchor reads fail loud

- **`aci stats` reports deferred-resolution coverage.** `run_stats`
  builds the latest revision's graph and reports
  resolved/ambiguous/missing plus stored unresolved edges — the
  resolver ran but established little must say so, or edge counts
  read as coverage. Build failures surface as an `error` note, never
  a zero-mask. CLI prints one `resolution:` line.
- **`read_anchors` counts damage; `verify-chain` fails on any.**
  Returns `(records, malformed)`; blank lines stay benign, everything
  else without a `head_hash` counts. Any malformed line in play is
  HEAD_MISMATCH (`anchor_file_corrupt`), even when surviving records
  would confirm — a truncated log never verifies against its prefix.
  Missing file stays ([], 0): absence and damage fail through
  different errors. Suite 291, ruff clean.

## Unreleased — opt-in Ollama embeddings with content-addressed cache

- **`ACI_EMBEDDINGS=ollama[:model]`** selects local Ollama embeddings
  for `aci query` / MCP `code.search` (default stays offline hash:
  deterministic, no server, tests untouched). Single selection helper;
  unknown specs raise instead of silently grading wrong results.
- **Batched transport + persistent cache.** The old per-text POST loop
  (500 calls per 500-doc query) now uses chunked `/api/embed`; a
  `CachedEmbeddingProvider` wraps any provider with a sha256-keyed
  JSON cache beside the DB — no invalidation logic, changed text
  simply misses; corrupt files rebuild. Unreachable server degrades
  to hash with an honest `hash-fallback` methods label, never a failed
  query.
- Measured (`benchmarks/embedding_eval.py`, live server, small 5+5
  sample — directional): ollama beats hash on dense and hybrid, lexical
  and paraphrase (recall +0.10 throughout, ndcg +0.02–0.06). CPU
  inference here is ~50ms/doc, so first queries are slow and the cache
  carries repeat cost. Suite 289, ruff clean.

## Unreleased — ledger head pinning, L1 surfaced + L2 anchor file

- **L1: every terminal task pins its ledger head.** The scheduler sets
  `ledger_head` in a `finally`, so completed, failed, cancelled, and
  review-stopped runs all leave one behind. Surfaced uniformly:
  `run_task` / CLI `aci run` JSON, MCP `task.run` / `task.status`,
  HTTP via `run_task`. New public accessor `scheduler.ledger_head()`.
- **L2: JSONL anchor log + `aci verify-chain`.** `--anchor-file` on
  `aci run` (also `run_task` / MCP `task_run` params) appends
  `{task_id, revision_id, head_hash, timestamp}` per terminal run.
  `aci verify-chain --db X --anchor-file Y [--task-id T]` scopes to
  one task's subchain (the events table interleaves runs, so global
  links are broken by construction — never verified as one chain) and
  reports CHAIN_VALID (exit 0) / CHAIN_BROKEN / HEAD_MISMATCH /
  NO_EVENTS (exit 1). No anchor for the target, or an empty DB, fails
  closed — a wrong `--db` never reads as clean.
- Pinned end to end: anchor a run, rewrite the last event's payload in
  SQLite, links-only still passes (the known flaw, demonstrated not
  asserted), anchored check returns HEAD_MISMATCH.
- Integrity note: the anchor file must live in a different fault
  domain than the DB it vouches for; hash excludes `attestation`
  (canonical contract), so reload reproduces heads bit-for-bit, with a
  `rowid` tiebreak for same-tick appends. Suite 280, ruff clean.

## Unreleased — blast demoted to advisory (exposure is not violation)

- **Blast no longer blocks.** `blast_radius_check` sets `blocking=False`:
  risk at or above threshold routes to HUMAN_REVIEW through the existing
  policy fall-through instead of FAIL. Invariants reject, inability
  deflects to INCONCLUSIVE, exposure alerts humans — the check that
  conflated reach with defect now honors that separation. No policy-code
  change; the fail-closed checkers (`secrets_scan`, `forbid_*`,
  fabricated removals) keep blocking, and violation-plus-high-blast
  still resolves FAIL (rejections filter first — pinned).
- Validated end to end on the Flask docstring commit that motivated it:
  `d73fa1cd` routes HUMAN_REVIEW / `non_blocking_failures` on both
  `verify` and `run` paths (was FAIL), with the 41-caller risk still
  measured and named — deferred resolution's visibility kept, the
  rejection dropped.
- Suite 271, ruff clean, extraction benchmarks hold (13/81).

## Unreleased — removal provenance (fail on fabricated `-` lines)

- **New blocking check `removal_provenance`** (`src/verification/removal.py`,
  wired into CLI/MCP/scheduler paths alongside blast): every `-` line is
  matched against the stored base-revision snippet at the hunk's old-side
  offset, exact content. A removal contradicting the stored record is
  FAIL (stale, hallucinated, or forged diff). Verified removals of known
  code stay with the deletion tripwire (INCONCLUSIVE); removals outside
  entity spans, inside truncated snippets, or in ungrounded files are
  inability (INCONCLUSIVE) — absence of record is not contradiction.
  Comment-only edits therefore decline rather than verify (README
  grounding rules say so explicitly).
- Validated on real history: a one-character-off removal on the sample
  repo FAILs while the true deletion stays INCONCLUSIVE; the same
  discrimination the unit tests pin. Suite 269, ruff clean, extraction
  benchmarks hold (13/81).
- **Known consequence, not caused here, surfaced during validation:**
  a 2-line docstring fix to a 41-caller function (`d73fa1cd`) now FAILs
  on blast where it previously PASSED. Proved causal: same diff+DB
  scores risk 0.35 with deferred resolution stripped, 1.0 with it
  (1,122 links resolved on the Flask base). Deferred resolution works
  as designed; the blast weights/threshold saturate fast once the
  graph actually sees cross-file callers, and hunk anchors seed
  enclosing code entities even for comment-only hunks. Recalibrating
  blast (weights, threshold shape, comment-awareness, or non-blocking
  blast) is a separate scoped change — deliberately not smuggled in.

## Unreleased — qualified scope resolution (`ns::Base`)

- **Qualified bases resolve canonically.** `base_class_clause` now
  emits `INHERITS_UNRESOLVED` with the raw qualified token sequence
  (`ns::Base`, `::Global`); the builder matches it against canonical
  `metadata["qualified_name"]` instead of flat `by_name`. A leading
  `::` anchors to top level only. `Base<T>` template arguments still
  emit nothing (pinned — the direct-children filter, not a walk).
  Bare refs keep the flat path, unchanged.
- **Namespace-aware naming without identity migration.** `namespace`
  blocks push `("ns", name)` onto the scope stack for matching and
  `qualified_name` recording, but logical ids still use the
  namespace-free scope: wrapping code in a namespace renames nothing
  already stored (pinned by id-equality test — no duplicate live rows
  on re-ingest). Python untouched (no namespace node type exists
  there); `qualified_name` is C/C++ only.
- Ambiguity policy unchanged: zero or 2+ canonical matches stay
  unlinked (`missing`/`ambiguous`), exact qualified match links even
  where flat lookup would give up.
- Benchmarks hold: extraction TP=13, Flask TP=142, firmware C++ TP=81,
  all FP=0 FN=0. Suite 259, ruff clean.

## Unreleased — extractor: cross-file references, C++ inheritance, out-of-class methods

Dogfooding on meshtastic/firmware (1,557 files, 10,428 entities) showed
cross-file `CALLS` at exactly 0 and `INHERITS` at exactly 0: the
extractor resolved everything against the current file only, so blast
radius was intra-file by construction no matter what the policy layer
did with it.

- **Deferred call resolution.** Extraction emits `CALLS_UNRESOLVED`
  (callee name + caller scope in metadata, empty dst) for calls with no
  intra-file target instead of silence; `GraphBuilder` links them
  post-build when exactly one eligible entity bears the name. Zero
  candidates (builtins, libc) and ambiguous names stay unlinked — a
  wrong link invents impact, a missing one merely undercounts it.
  Resolution is deterministic per revision and in-memory only; the
  store keeps the observed reference. Same shape for
  `INHERITS_UNRESOLVED` bases. Semantic change, named: `forbid_call`
  now sees cross-file calls with a unique callee name (they resolve
  into real edges), so a rule that previously fired only same-file now
  fires repo-wide. Strictly more coverage, but a diff that passed
  before can fail now — that is the check seeing the whole call graph,
  not a regression. Forbidden calls to ambiguous or undefined names
  stay invisible (qualified call resolution is a different scope).
- **C++ inheritance clauses.** `base_class_clause` parents
  (`class App : public Base`) now emit `INHERITS` (same file) or
  `INHERITS_UNRESOLVED`, instead of nothing — the old code looked for
  `argument_list`, a node type this grammar never emits there. Direct
  children only, so `Base<T>` template arguments don't become bogus
  parents; qualified bases (`ns::Base`) stay out of scope.
- **Out-of-class definitions are methods.** `void App::run() {}` was
  dropped entirely (no entity); it is now a METHOD with scope `App`,
  and calls inside it resolve against that scope. In-class
  declarations still emit nothing; free functions are untouched.
- Benchmarks hold: extraction TP=13, Flask TP=142, Graph-RAG TP=149,
  firmware C++ TP=81, all FP=0 FN=0. Suite 254, ruff clean.

## Unreleased — external audit fixes (2026-09-29)

An outside audit executed three reproducible false-PASS paths and a set
of silent-failure / dead-control findings. All confirmed by re-execution
before fixing; every fix below is pinned by a regression test.

- **C1 — deletion tripwire bypassed by one `+` line.** `find_deletion_hunks`
  treated any hunk containing a `+` line as a modification. Deleting a
  whole function plus one blank line verified as PASS. Net-removal rule
  now: a hunk with more `-` lines than `+` lines is a deletion.
  Balanced pairs still pass. Residual, stated: adding at least as many
  junk lines as removed lines still evades; content-level removal
  verification stays V1.1.
- **C2 — clean `.py` hunk laundered arbitrary content into PASS.**
  Non-ingestible files were exempt from the ungrounded veto, so
  `src/auth.py` + malicious `Dockerfile` / CI workflow / new `.env`
  verified as PASS. Every named-but-ungrounded file now vetoes,
  regardless of extension (reverses the `real_repo.md` decision, with
  the reversal recorded there). Flask 5-commit distribution moves
  4 PASS / 1 INCONCLUSIVE → 3 PASS / 2 INCONCLUSIVE / 0 FAIL; the
  changelog commit is declined (human review), not blocked.
- **C3 — secrets scanner required quotes; real secrets are unquoted.**
  Now flags long unquoted values (`DB_PASSWORD=...`), AWS keys, PEM
  blocks, JWTs, and credentialed URLs, with affix-tolerant keywords
  (`DB_PASSWORD`, `AWS_SECRET_ACCESS_KEY`). Unquoted values may end on
  `;`/`,` (C-style `DB_PASSWORD=s3cr3tPr0dValue;`, caught dogfooding on
  meshtastic/firmware). Env-lookups
  (`os.environ.get(...)`) and calls (`get_password()`) still do not
  match. Added lines outside `@@` regions (preamble, header-only
  sections) are scanned too — previously bypassed entirely. Labeled
  recall 4/9 → 5/9 (`near-unquoted-env`), precision stays 1.00;
  baseline constants updated with the review note the test protocol
  requires.
- **Hunk-aware header parsing.** A removed `-- comment` line renders as
  `--- comment` and an added `++ i` as `+++ i`; both were parsed as
  file headers, hallucinating phantom files. Only `---`/`+++` outside
  hunk bodies name files now. `normalize_path` also stopped using
  `str.lstrip("./")`, which ate dotfiles (`.verifyci/x` → `verifyci/x`)
  and parents (`../etc/passwd` → `etc/passwd`).
- **run_task / verify split closed.** `intent.py` hardcoded
  `blocking=True` on a `provenance_check` duplicate, so `run_task`
  FAILED diffs `run_verify` called INCONCLUSIVE (contradicted the
  decisive matrix). Intent now reuses `default_invariants()`; both
  paths dedupe repo rules. Decisive matrix re-verified end to end:
  clean → PASS/COMPLETED, secret → FAIL/FAILED, unknown →
  INCONCLUSIVE/INCONCLUSIVE.
- **Scheduler: failures persist, siblings cancel, cancel works.**
  `_persist` is now called on the budget-breach, block, error, and
  exception paths (the events table previously held only successes);
  persist/emit failures print to stderr and land on the task record
  instead of `except: pass`. Unexpected node errors are attributed
  (`step_id: ExcType: msg`). A faulting level cancels still-running
  siblings. `cancel()` cancels the tracked task handle; `resume()`
  refuses to fork a second `_execute`; `CancelledError` lands
  CANCELLED with a terminal event instead of vanishing.
- **Budget default is None (unlimited); 0 is a real zero budget.**
  The old `0` default was falsy and silently disabled the guard.
- **Ledger head-hash pinning.** `verify_chain()` alone never detects a
  rewritten last event (verified: tamper → True, plus self-heal on next
  append). New `head_hash()` + `verify_chain(expected_head)`; pin the
  head externally or the last event is unanchored — documented on the
  method.
- **Blast radius measures again.** Removed the same-file
  `difference_update` (with zero cross-file CALLS edges it deleted
  every relative: risk 0.00 always) and stopped counting unknown test
  coverage as gaps.   Blast seeds are now hunk-anchored entities
  (`seed_entities_for_diff`) instead of all 600 entities of a touched
  file — 89992954 narrowed 621 → 12 seeds. This is a semantic shift,
  not just a number: an entity in the same file as the edit but outside
  the touched line ranges no longer contributes to blast measurement,
  so pre-fix and post-fix risk scores are not comparable. Unreadable
  graphs yield `established=False` (INCONCLUSIVE), not a clean bill of
  health (`NodeMapError`, surfaced, not swallowed).
- **`forbid_call` / `forbid_import` fail closed for real.** Graph
  traversal exceptions used to return "no violation"; now unevaluable
  is a rejection, matching the documented contract.
- **HTTP: optional bearer token + body caps.** `ACI_API_TOKEN` guards
  all but `/health` when set; diffs capped at 1M chars, `k` at 1000.
  Trust model documented on the module. No rate limiting — stated, not
  solved.
- **No more silent empty reports.** `run_vuln` returns `error` on
  unreadable DBs instead of `findings: []`; dense-channel failure
  reports `dense-unavailable` instead of doubling sparse scores;
  BM25 drops zero-score non-matches; MCP dense/sparse share one
  500-doc universe. Measured effect on `benchmarks/retrieval_eval.py`:
  ndcg@10 0.86631 → 0.87737 (non-matching docs no longer earn RRF
  credit); recall@5 and dense-only ndcg unchanged.
- **Dead code deleted.** `config/default.yaml` (never read by anything;
  policy is hardcoded in three places — now stated in one),
  `contracts/config.py`, `graph/{serializer,stats,temporal}.py`,
  `observability/{telemetry,metrics}.py`, `codeintel/`, `tools/`,
  `memory/projections/`, `compiler/{permissions,budget,strategy}.py`,
  and the tests that pinned them. Controls that looked wired but
  weren't (`check_permission`, `BudgetManager`) are gone rather than
  decorative.
- Suite 246, ruff clean. `test_labeled_set_meets_plan_gates`
  (by-construction 1.00/1.00 on six self-authored cases) deleted;
  `test_blast_wrapper` tautology (`or risk_score >= 0.0`) replaced with
  strict assertions.

## Unreleased — deletion-hunk classifier, v1.1 scoping recorded

- **Loop closed on the platform itself.** Five probes against
  stock_intelligence, one false PASS (delete_function), real bug identified,
  fix applied, probes re-run. The tool used as a tool, finding a failure in
  the tool, with a mechanism for the finding to become a decision.
- **Cheap fix (this commit):** diffs containing a hunk that removes lines
  without adding any now return INCONCLUSIVE with
  `diff_contains_deletion_hunks; content-level removal verification is
  V1.1`. Correction to the first version of this fix: the initial
  implementation flagged every `-` line, which made every modification
  INCONCLUSIVE — broader than the stated spec ("a `-` line with no paired
  `+`"). Per-hunk pairing now; modifications pass, pure removals don't.
  Pinned by a unit test asserting a modification-only diff yields no
  deletion hunks — the class of bug targeted unit tests close and
  integration probes don't.
- **Suggestion-sweep triage (9 of 35 applied, rest rejected or deferred):**
  deleted dead `_graph_calls` and `_extract_name` (no callers); added
  `__all__` to genai_semconv (imports are re-exports via tracing.py, not
  unused); batched vuln-cache inserts via executemany; new fusion tests
  (incl. empty-input edge case), stats empty-DB test, vuln invalid-JSON
  test. Rejected: ingest N+1 (loop is over distinct old revisions, usually
  one, incremental-only), metadata path traversal (db_path is operator
  config, not untrusted input). Deferred as architectural: scoped
  retrieval, true sandboxing, long-function splits, batched vuln lookup,
  and the remaining missing-test files.
- **V1.1 scoping (recorded, not implemented):** parse diff hunks, compute
  affected line ranges, intersect with entity line ranges. Seeds become
  only affected entities, blast radius runs only from affected entities, and
  a deletion of a public function with callers becomes visible as a
  blast-radius hit rather than a swallowed one. New parser, new arithmetic,
  new semantics for what "affected" means when the diff isn't yet applied.
- **SKIP_DIRS exclusion:** ingest no longer walks into venv/node_modules/
  __pycache__/.pytest_cache/etc. Found by timing out on stock_intelligence
  (venv had 5,898 Python files; the project has 27).

- tree-sitter-c parses `enum class X {}` as `function_definition` with no
  declarator; C/C++ names now require the declarator path (Python keeps
  direct identifiers). The enum false-PASS is now measured for real
  against a fresh DB: INCONCLUSIVE, `module_only` in rationale.
- Wipes verified by assert: a silently failed wipe plus deterministic
  revision ids preserves stale rows from older extractor versions
  indefinitely — found because the "fixed" verdict reproduced on a stale
  DB. Same-state re-ingest is idempotent, which cuts both ways.
- Overload fixture: two `write` defs share one logical id (first-wins
  documented, not blessed).

- Elaborated type references (`struct Foo` in type position, forward
  declarations) no longer emit CLASS entities; only bodied
  struct/class-specifiers do. The duplicate-key scan that motivated this
  found references, not overloads, as the dominant collision source.
- Enum-only (or otherwise MODULE-only) diffs are INCONCLUSIVE, not PASS:
  seeds exclude MODULE rows, `module_only` travels in the rationale. The
  predicted enum false-confidence path, closed with its own test.

## Unreleased — blind C++ annotation round (firmware)

Suite 211, no product-code change. `benchmarks/score_cpp.py`: 81
hand-read entities (static/inline, ISRs, header/source split, template,
forward decls) → TP=81 FP=0 FN=0. Three initial FPs were listing-regex
misses, truth corrected. `enum class` excluded as documented gap (no ENUM
mapping) — firmware grounding rests on functions/structs.

- `NodeResult.decision` carries passing gate decisions so the ledger's
  `TASK_COMPLETED`/`TASK_FAILED` events include decision + rationale;
  pinned by one test per channel (CLI result, MCP result, HTTP response,
  ledger event).
- Suffix-ambiguity tripwire: `find_ambiguous_files` flags diff paths
  matching entities under several stored paths; shared `build_semi_check`
  constructor appends the note in executor, MCP, and CLI alike.
- Dogfood on SmartEnergyMeter_3ph (539 files, C/Python/C++): real UART
  firmware diff → PASS with the qualifier visible. Details in
  `benchmarks/real_repo.md`.

## Unreleased — discrimination evidence: reverts, mutants, qualified PASS

- Reverted commits (`c935eace`, `5c127217`) and the judged-bad commit they
  revert (`12c49c75`): all PASS. Gate cannot distinguish judged-wrong from
  fix. Recorded as discrimination gap (2016 paths ground via suffix match).
- Mutation matrix, 5 single defects on real lines, all PASS: rename/dangling
  is a gap not scope (candidate `no_dangling_calls` checker, not built);
  deleted call, default, dropped return, swapped comparison are outside
  stated scope — boundary now a table, not prose.
- PASS rationale is `all_checks_passed_behavior_not_verified`: scope
  qualifier travels with the decision, not just the README.

## Unreleased — agent-regen stability run (0/20 divergence)

20 Flask commits regenerated from messages; human vs regen verdicts all
PASS/PASS. Stability under reformulation proven (including one structural
variant); discrimination not tested — nothing in the set is wrong. The
`a411a243` variant (property access sets `accessed`, human helper does
not) is behavior-different and still PASS: the documented scope boundary
doing exactly what it says. Methodology traps recorded: silent empty
`git show` on 5 commits, UTF-16 redirect encoding.

Suite 183 → 205. No new subsystems.

- Secrets allowlist: hits confined to `tests|test|fixtures|fixture|
  examples|example|e2e` or `*.example` demote to pass-with-
  `established=False` (→ INCONCLUSIVE) instead of FAIL. Base rule still
  labels the Flask fixture violated=True; the demotion is a second,
  separately tested mechanism. Precision stays honest two ways.
- Labeled ground truth moves to `tests/evaluation/labels/invariants.jsonl`
  (12 cases with `source`: synthetic, flask-history, adversarial) under a
  blind-labeling protocol. Measured: recall 4/9, precision 4/4; gates pin
  baseline-minus-epsilon, not fixed 0.90 (which the old 6-case set met by
  construction). Near-misses included and failing: unquoted env secret,
  aliased call, relative-import naming, split literal.
- Unmeasured is now null: `detection_recall/precision` are Optional, None
  without labels. Updated the two tests that asserted 0.0.
- Decision table as data (`test_policy_table.py`, 6 rows) with the
  circularity caveat stated in-file: table-correctness evidence is the
  real-repo distributions, not the suite.

## Unreleased — review economics: measuring the reviewer

Separate section deliberately: this measures a reviewer, not a checker
(the `0ec7f713` round measured one checked rule against forty asserted
ones; stacking them would flatten a useful distinction).

An automated review batch produced 45 findings against this repo: 19 valid
(12 dead imports + 7 more found by ruff, 9 units genuinely untested),
26 rejected with evidence. The rejections break down as 9 false
test-coverage claims (every one checkable with `pytest --collect-only -q
| grep <name>` — tested units in unadvertised filenames, or tested via
integration: `detect_language`, `compute_source_hash`, `check_permission`,
`tokenize`, `evidence_verifier`, `SnapshotStore`, `BudgetManager`,
`ToolRegistry`, plus three "no test file" claims for files with test
files), 4 security claims mistaking tools for trust boundaries, 6 length
complaints that would scatter decision logic, 2 already-tracked TODOs.

The shared shape: filename-level review asserting what filenames can't
establish. The two-minute fix for the reviewer class is grounding
(`pytest --collect-only`), same failure shape as asserting without
checking. Recorded so the next automated batch can be scored, not trusted.

Trust-model conditional recorded in `src/tools/__init__.py`: the path
rejections hold for user-privileged runs against user-authored content.
If untrusted content ever arrives (prompt injection, webhooks, PR
triggers), revisit allowlists here and real sandboxing for `shell_tool`
(V1.1+ decision, named now so it's not discovered then).

## Unreleased — decided explicitly, recorded the same way

Suite 173 → 183. No new subsystems.

- Policy: pass-on-zero-edges is now a different verdict from pass-on-500.
  `CheckResult.established` marks checks that ran against nothing;
  blocking-but-unestablished routes to INCONCLUSIVE (rejection vs inability,
  completed). Decided, not inherited.
- Config audit: malformed YAML raises (loud), absent file falls back
  (quiet), empty file means no repo rules (quiet), typo'd rules fail closed
  and say so in the explanation. All four pinned by tests.
- `from . import thing` records `"."` (pinned, not resolved); relative
  imports record the module, never the symbol.

## Unreleased — invariant config surface + coverage-visible verdicts

- Reranker default-off implemented (fused-only default in CLI/MCP/FastMCP;
  `--rerank` / `rerank=true` opt-in; fused results carry real RRF scores).
- Repo-local `invariants.yaml` next to the DB, loaded by default in
  `run_verify`/`run_task`/MCP, extending built-ins. Proven: a repo
  `forbid_import:typing` rule flips a clean diff to FAIL with no flags.
- Every `forbid_*` verdict reports examined edge counts; zero-edge graphs
  say vacuous explicitly. Precision note (13 hits, one commit) and
  sharpened denominator (crypto/auth warning) recorded.

- Layering sweep over 1,011 Flask commits: rule A (src→tests) 0 hits;
  rule B 13 hits, all in `0ec7f713` (sansio split carrying sync imports,
  later cleaned). Worktree ingest at that commit + `forbid_import:..config`
  / `:..ctx` → both FAIL. Two checkers, two real inputs.
- Doing that exposed relative imports recording the symbol instead of the
  module (every `forbid_import` would miss them); fixed with pinning test.
- Gap forced open: `run_verify` still PASSes that diff — project invariants
  have no config surface (`_default_invariants` hardcoded). Recorded as the
  next honest feature, not built.
- Denominator note: the 1/1011 secrets rate is checker × repo-test-density,
  not checker quality; fixture-blindness stays the precision boundary.

Suite 169 → 173. Measurements only, plus one same-session fix the run forced.

- Flask @ d73fa1c (depth-10 clone to temp): 99 files → 4119 entities +
  7672 edges in 4.0s (parse+extract 0.8s; DB writes dominate small-scale).
  Type split healthy (METHOD 376, IMPORTS 526, INHERITS 36).
- Extraction TP=142 FP=0 FN=0 over 142 hand-read entities (decorators,
  overloads, nesting, docstring traps). First pass read 0.95 — all 8 misses
  were docstring `code-block` examples the regex listing counted and the AST
  correctly ignores; truth corrected, pinned by test. Duplicate-identity
  rate at scale: 87/4103 (2.1%), all same-name redefinitions.
- Queries: reranker demotes fused top-1/top-2 off-page twice more (route,
  class-view). Neither dense provider dominates (1 st win, 2 hash wins,
  2 ties).
- Commits: 4 PASS / 1 INCONCLUSIVE (merge, empty diff) / 0 FAIL.
- Full-history sweep (1011 commits, every added line through
  `secrets_scan`): exactly one hit, `025589ee` fixture
  `password="test"` → FAIL. Real FAIL exercise; reveals fixture-blindness
  as the precision boundary. No fix — tradeoff recorded, not decided.
- Found by measuring: uningestible files (CHANGES.rst) vetoed whole diffs;
  only ingestible-but-absent files veto now (`INGESTIBLE_EXTENSIONS`
  single-sourced, shared by ingest and grounding). Details + histograms in
  `benchmarks/real_repo.md`; truth in `benchmarks/score_flask.py`.

## Unreleased — dense-embedding run executed (queue now empty)

- `SentenceTransformerProvider` (lazy, local weights only) + per-arm table
  on the five queries, hash vs st: beam 3/1/1→1/1/1, dma 1/1/1→1/1/1,
  incremental 1/1/2→5/2/2, weighted 292/7/2→2/2/2, register 6/2/9→29/7/9
  (dense/fused/reranked). Neither provider dominates; both fusions are
  complementary. No architecture change justified — tabled as baseline.
  Details in `benchmarks/real_repo.md`.

- Ran `ms-marco-MiniLM-L-6-v2` locally (cached weights, CPU torch, no
  download/daemon) over the five queries at top-50 depth: beam 1/1/1, dma
  1/1/1, incremental 1/2/5, weighted 7/2/2, register 2/8/6
  (fused / off-rerank / ce-rerank). The learned model reproduces the offline
  pattern instead of a different one — swapping rerankers does not fix the
  shape problem. Recorded decision (not yet implemented): offline reranker
  defaults off, re-enable-able per shape.
- Duplicate-definition finding reframed and confirmed: stored row holds
  lines 815–856 (last write wins), resolver returns the line-371 object —
  same id, unioned edges, disagreeing line numbers. Incorrect aggregation,
  not loss. Open option recorded, not adopted.
- Scaling stated as non-finding (0.067s/file at 2120 files vs 0.108s/file
  at 472). Ollama refined: box lacks the daemon but holds the weights, so
  a daemonless dense run via `sentence-transformers` is possible and still
  open. Details in `benchmarks/real_repo.md`.

## Unreleased — mid-pack reranker verdict + Relay scaling run

Suite 162 → 169. No new subsystems.

- Mid-pack queries (fusion rank 3–10, same repo): reranker lifts 7→2 on
  `weighted shortest path`, demotes 2→9 and 2→off-page on two others.
  Balanced verdict with lifts and demotions both measured; three-column
  reporting stays mandatory. `---`-side diff files now ground verification
  (pure deletions of graphed files verify; unknown files stay inconclusive),
  with adversarial fixtures (truncated, deletions-only, `.git/` path,
  unicode path, mixed prefixes).
- Relay scaling: 2120 files → 19,263 entities + 29,760 edges in 142.4s
  (0.067s/file vs 0.108s/file at smaller scale — no cliff; parsing
  dominates, one bulk transaction). One row per table lost, diagnosed:
  duplicate module-level `get_recommendations` in the target repo collapses
  to first-wins; recorded as known residual (occurrence indexing is edit-
  unstable — tradeoff, not oversight).

Suite 155 → 162. No new subsystems (Principle 6).

- Corpus and graph build scoped to latest revision (superseded rows are
  history, not answers); `get_entity_by_name` without revision answers
  latest-live deterministically (revision-scoping audit clean).
- Reranker isolation measured on latest-rev corpus: fused-only 1/1/1 vs
  reranked 1/1/2 — the offline reranker demotes one correct fused answer.
  Three-column reporting (fused / reranked / no-rerank) is now the procedure
  for the Ollama run, so a flat result can be attributed.
- Tokenizer edge tests (digits, acronyms, dotted paths); rerank ordering +
  no-invention tests; scaling TODO for the uncapped corpus.
- Ollama provider-swap run blocked here (no binary, no server); framed and
  recorded in `benchmarks/real_repo.md`.

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
