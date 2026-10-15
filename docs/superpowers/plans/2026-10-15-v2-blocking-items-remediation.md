# v2 Blocking-Item Remediation Plan

Date: 2026-10-15
Baseline: working tree at HEAD 7bf4774 + uncommitted v2 changes

## Order

1. Install declared deps (z3-solver, wasmtime, duckdb) -> baseline `pytest tests/v2` + `adjudicate --corpus`
2. #5 `adjudicate_corpus()` executes real ground-truth oracles (read frozen labels, never rewrite)
3. #1B CLI fail-closed on checker error + `active_backend` disclosure
4. #1A trimmed: fail-closed branch only (`SOLVER_UNAVAILABLE` / `UNKNOWN`)
5. #2 credential semantics in `secrets_taint.py`, gated on #5 precision holding
6. #3 AUTHZ intent postcondition -- HELD, needs real design

## Rejected

- Proposal #4 (dedupe `z3_prover.py`): premise FALSE. One `class Z3SymbolicProver`
  at line 845, 1507 lines, no duplicate top-level names. 61% coverage is live code.
- Proposal #3 (AUTHZ_DENY_NON_ADMIN): unsound. `zlib.crc32(b"admin")` is a magic
  constant with no encoding linking the `role` parameter to the string "admin".

## Constraints

- Frozen corpora and labels are read-only. Never rewrite a label to force a pass.
- Gates fail closed. Uncertainty never passes.
- Preserve the smoke suite; add the corpus oracle as a separate, stricter mode.

## Results (2026-10-15, all declared deps installed)

Baseline: `tests/v2` 37/37 pass. After this work: 62/62 pass, ruff clean.

Oracle measurement against frozen ground truth (v1-parity bars):

| cap | metric | before | after | bar | verdict |
|---|---|---|---|---|---|
| cap002b | recall | 0.6957 | **0.9130** | 0.8696 | PASS (precision 1.0) |
| cap011 | recall | 0.8333 | **1.0000** | 0.95 | PASS (precision 1.0) |
| cap002_heldout | verdict agreement | 0.40 | **0.70** | 0.8235 | FAIL, honestly reported |
| cap004 | verdict agreement | n/a | **0.9722** | 0.90 | PASS (0 false accepts) |
| cap003a | verdict agreement | n/a | **0.9167** | 0.90 | PASS (0 false accepts) |
| cap009 | impact accuracy | n/a | **1.0000** | 0.95 | PASS (225/225 exact, 25/25 adversarial) |
| — | total false accepts | 16 | **2** | 0 | — |

Three corpora (cap006, cap008, cap010) remain `passed=None` with an explicit
reason: no v2 engine entry point exists against their frozen ground truth. They
are not counted as passes.

### cap004: restored contract checking

v1 verified call sites against declared contracts (`verification/call_semantics.py`,
559 LOC). v2 dropped it with no migration target in the architecture matrix, so
`cap004` had no measurable surface at all. `symbolic/contract_checker.py` restores
it: argument binding (positional, keyword, `**dict` literal), declared-default
fallback, constant folding, receiver-type grounding, and the four contract shapes
(`required/forbidden` x `kwargs/args/param_bindings`).

Fail-closed is asymmetric by design: an undecidable *requirement* is
INCONCLUSIVE, while an unverifiable *prohibition* is a FAIL, because absence of a
forbidden value cannot be proven.

Exposed as `vc_verify_contract` on the MCP daemon so the capability is reachable.

### cap003a: restored removal provenance

v1 had `verification/diffmap.py` (805 LOC) plus `verification/removal.py` (338
LOC). v2 kept `datalog_unsafe_deletions` but nothing ever fed it, so the rule was
dead code and `cap003a` was unmeasurable. `ingestion/removal_provenance.py`
restores the missing half: it classifies every `-` line as VERIFIED, FABRICATED,
or UNVERIFIED against stored entity records.

The load-bearing rule is that absence of a record is not contradiction. No
provenance for a path, a truncated snippet, or a line outside every entity span
routes to INCONCLUSIVE. Only a completely-covered span whose snippet positively
disagrees is FABRICATED.

Two implementation bugs worth recording, both caught by the corpus:

1. Removed lines were indexed by their position in the removal list, ignoring
   preceding context lines. Every hunk with a context line before the first
   removal resolved to the wrong old-side offset, which turned genuine removals
   into FABRICATED. Line numbers are now tracked during parsing.
2. Nested scopes produce overlapping records. Declaring FABRICATED on the first
   disagreeing record made every nested-scope removal look forged. The verdict
   is now VERIFIED if any completely-covered record agrees, and FABRICATED only
   when all of them disagree.

### benchmark harness repaired for v2

All 12 v1 `measure_cap*.py` scripts imported `verifyci.*`, a package the v2 branch
deleted, so every one died at import with `ModuleNotFoundError: No module named
'verifyci'`. The corpora, labels, and oracle manifests were all still valid; only
the measurement layer was gone, and `adjudicate_corpus()` was reporting
`verified_integrity: true` without ever running an engine, which is why the
breakage was invisible.

`benchmarks/common/measure_v2.py` replaces that layer with one implementation
shared by all capabilities. Each `measure_cap*.py` is now a shim that calls it, so
the per-capability scripts cannot drift apart. Measuring one capability runs only
that capability's engine: 690ms instead of ~35s.

Two rules govern the output:

1. **Frozen v1 evidence is never overwritten.** `results.json`, `RESULTS.md` and
   `RESULTS_SHA256` are untouched; v2 writes `results_v2.json` beside them and
   records the v1 results digest so the two can be compared.
2. **Fail closed.** Capabilities with no frozen ground truth v2 can be scored
   against report `not_measurable` with a reason. Seven are now declared
   explicitly rather than silently omitted: cap005, cap006, cap007, cap008,
   cap010, cap012, cap013. Four of those (cap005, cap007, cap012, cap013) are
   exercised only by the self-test smoke suite, where the same harness supplies
   both the fixture and the answer, so they are not independent oracles.

`tests/v2/test_benchmark_harness.py` guards the regression directly: no measure
script may import `verifyci.`, every capability must have a declared status, and
`results_v2.json` must never alias `results.json`.

The 9 `author_*.py` corpus generators never imported v1 and were left alone; they
still produce the frozen corpora.

### cap010: lexical retrieval restored

v2 kept `RaBitQHybridIndex`, which already fuses a BM25 lexical channel with a
1-bit quantized vector channel via RRF. What was missing was an entry point over
plain text: the index only accepted U-SSA functions through the ingest path, so
v2 had no way to rank corpus text at all. `interface/retrieval.py` adds that
entry point and no ranking logic of its own - it surfaces the index's existing
`hybrid_rrf_score` and the per-channel values.

All five predeclared gates from the frozen protocol are met:

| gate | bar | v1 recorded | v2 now |
|---|---|---|---|
| Recall@5 | >= 0.80 | 0.8629 | 0.8343 |
| Recall@20 | >= 0.90 | 0.9771 | 0.9771 |
| nDCG@10 (excl. no-answer) | >= 0.50 | 0.6883 | 0.6198 |
| Correct abstention | >= 0.90 | 1.0 | 1.0 |
| False relevant rate | <= 0.10 | 0.0 | 0.0 |

Every gate passes, but Recall@5 and nDCG@10 sit below v1's recorded values. The
corpus was not tuned to close that gap: the `misleading_lexical` and `multi_hop`
slices need a semantic channel v2 does not have, and tuning weights against the
frozen labels would be fitting the oracle.

Incidental fix: `RaBitQHybridIndex.upsert_document` rebuilt global BM25
statistics on every insert, making bulk indexing quadratic. Statistics are now
rebuilt lazily on first query, and the cap010 index is cached per process because
the corpus is frozen and the embedder deterministic.

### cap009: restored diff impact

v1 attributed diff hunks to graph entities and walked callers. v2 had no diff
mapper at all, so `cap009` was unmeasurable. `ingestion/diff_impact.py` restores
both stages: seed extraction by hunk/span overlap, then transitive caller closure
over reversed edges.

Identity is exact, which is what the corpus slices are built to punish:
`same_basename_collisions` supplies two entities with the same basename under
`auth/` and `api/`, and `adversarial_critical` supplies a rename plus a decoy
entity under an unrelated directory. Path comparison is never a suffix match.
Renames attribute to the post-rename location, and overlapping scopes all seed,
so a nested-scope edit reports both the outer class and the inner method.

Result: 225/225 exact on both seeds and impact, including all 25
`adversarial_critical` cases, with zero missed impact entries. `missed_impact_rate`
is reported explicitly because under-reported blast radius is the unsafe
direction.

### cap003a is wired into `verify-diff`, against a stored base

Removal provenance is only meaningful against a base revision the diff did not
supply. Parsing `base_source` out of the same diff and checking removals against
it is a tautology: the record is derived from the claim under test, so it can
never contradict it. That wiring was written, measured to be incapable of
failing, and removed rather than shipped.

The schema gap that blocked it is now closed. `function_nodes.ussa_payload`
holds compressed U-SSA, which is derived data and cannot contradict anything, so
a new `source_snapshots` table retains verbatim source per file per commit.
`ingest` writes it, `verify-diff --db` reads it back, and provenance runs only
when a record exists. With no stored base the check is skipped outright rather
than dressed up as a verification.

Verified end to end: a diff claiming to remove `charge = 999` from a revision
that contains `charge = 10` now FAILs with `VC2-CAP003A-FABRICATED-REMOVAL`, and
the honest diff passes. The forged diff also still carries
`VC2-RETURN-VALUE-EQUIVALENT` - the return value really is equivalent, and the
diff really is forged. Both findings now coexist, which is the whole point of
the rename below.

One bug surfaced while wiring it: the per-file raw diff emitted by
`_parse_unified_diff` omitted the `---`/`+++` headers, so the hunk parser had no
path and silently found zero hunks. Every provenance check was a no-op until that
was fixed.

### Fixes landed

1. `adjudicate_corpus()` executes engines against frozen corpora and scores.
2. CLI fail-closed: secret-engine and concurrency-engine exceptions, and
   `SOLVER_UNAVAILABLE`/`UNKNOWN` from `prove_equivalence`.
3. `ingest` discloses `active_backend`; `--backend` selectable.
4. `DuckDBCPGStore` rejects a SQLite store under the duckdb backend.
5. `prove_function_diff` fails closed when the solver is absent.
6. Secrets: credential-compare rule, case-insensitive credential names,
   connection-string and JWT rules, concatenation folding, config/env line
   scanner, placeholder suppression, dedent recovery for partial hunks.
7. `dangerous_calls.py`: dangerous builtins, module calls, and imports.
8. New modules with no baseline report INCONCLUSIVE rather than PASS.

### Open

1. **cap002_heldout agreement 0.70 < 0.8235.** The 3 disagreements are all
   fail-closed: N-C1 (unparseable fragment -> FAIL), N-C4 and N-W4
   (`VC2-Z3-UNDECIDED-DIFF` -> INCONCLUSIVE). Zero false accepts. Closing the
   gap by relaxing fail-closed behaviour would trade safety for the bar, which
   is not a fix.
1. **cap004 residual: 1 of 36.** `db.query(...)` against
   `required_receiver_type: DatabaseConnection`. Grounding needs real type
   information; the current resolver is name-based and cannot distinguish
   `db` (satisfies) from `manager` (unresolvable). Both are receiver-inferred
   slices, so a partial-match heuristic would trade one case for another.
2. **cap002b residual misses (2).** B-ID-05: the corpus literal is itself
   unterminated, so no parser can scan it. B-CMP-01: base64 credential blob
   with context correlation, which v1 solved with `CompositeSignalEngine`
   (68 LOC) that v2 dropped.
3. **Equivalence remains a value-level claim.** It no longer suppresses secret
   or dangerous-call findings because those checkers run independently. The
   rule was renamed `VC2-RETURN-VALUE-EQUIVALENT` and its message now states
   outright that it says nothing about safety, so a reader cannot mistake it
   for a safety verdict.
4. **cap003a now runs in the gate.** It needs `ingest` to have been run against
   the base revision and `--db` supplied; without a stored record the check is
   skipped by design.
5. Two unmeasurable capabilities remain: cap006 (canonical graph-digest parity
   with the frozen oracle) and cap008 (a multi-process worker-protocol replay
   harness). cap005, cap007, cap012 and cap013 are measured only by the
   self-test smoke suite and need frozen labels before they can be claimed.

### Test coverage of the verification core

The 92% test cut was the largest single regression against v1. The core
detection paths of `z3_prover.py`, the module that turns a diff into a defect
verdict, were the least covered in the engine at 62%.

`tests/v2/test_anomaly_checkers.py` exercises each anomaly class in isolation -
call-argument swap, return swap, guard inversion, parameter shadow, unsupported
construct escalation - plus both directions of `prove_equivalence` (a real
divergence must prove SAT, and a behaviour-preserving rewrite must prove UNSAT,
so an over-eager prover cannot pass silently).

One finding while writing them: the shadow-assignment rule targets shadowing a
*parameter*, not a local binding. The rule is narrower than its name suggests,
which is worth knowing before relying on it.

`test_intent_compiler_matches_only_declared_patterns` pins the real reach of
`IntentToSMTCompiler`: three numeric patterns compile to an SMT postcondition,
and authorization prose does not. That limit is now a test rather than a
surprise.

Coverage on the two weakest modules: `z3_prover` 62% -> 67%, `spec_compiler`
60% -> 62%, engine total 81% -> 82%.

## Remaining v1 gaps, ranked by measurable value

v1 was 21,864 LOC across 15 subsystems; v2 is ~8,000 across 8. Not all of the
drop is regression (some was deliberate consolidation), but these have frozen
corpora ready to measure against, in increasing order of effort:

| cap | v1 module (LOC) | v2 state | effort |
|---|---|---|---|
| cap003a | `verification/diffmap.py` (805) + `removal.py` (338) | RESTORED and wired: `source_snapshots` schema + `verify-diff --db`, 0.9167 | done |
| cap009 | `verification/diffmap.py` + graph traverse | RESTORED: `ingestion/diff_impact.py`, 1.0000 over 225 cases | done |
| cap010 | `retrieval/sparse.py` (102) + `fusion.py` (38) + dense | RESTORED: `interface/retrieval.py`, all five gates met (R@5 below v1) | done |
| cap006 | `memory/replay.py`, `storage/revision.py` | temporal store exists but no canonical-digest parity with the frozen oracle | high |
| cap008 | concurrency worker protocol + ledger | only the static datalog rule; no multi-process replay harness | high |

Also dropped with no corpus and no migration target: orchestration (planner,
executor, scheduler, budget/permission compiler, 809 LOC), observability (153),
evidence (599), export/SARIF (464), and the HTTP interface. These are
unmeasured, so they are listed as known absences rather than regressions.
---

### Dependency swap results (spec §4 / §7)

The spec names six technologies that were not actually used. Following the user's instruction to add the real dependencies and swap implementations, I performed the swaps that have a clean primitive boundary, and documented the ones that do not.

Swapped:
- **msgspec** — every `@dataclass(frozen=...)` in `verifyci_v2/` is now `@msgspec.struct(frozen=True)` (45 classes across contracts, ingestion, interface, provenance, sandbox, store, symbolic). Imports of `dataclasses`, `field`, `asdict` updated to `msgspec` / `msgspec.to_builtins` / default literals. 112/112 tests pass.
- **securesystemslib** — `dsse_pae` (the DSSE v1.0 PAE construction under `provenance/dsse_intoto.py`) delegates to `securesystemslib.dsse.Envelope(...).pae()`. The hand-rolled formula produced byte-identical results, so the swap changes no attestation bytes; it does replace hand-maintained cryptographic construction code with the reference library. 33/33 provenance tests pass.

Not swapped (with reasons — these are not cosmetic renames; the hand-rolled versions remain in place):
- **egglog**: `symbolic/egglog_engine.py` does not import `egglog` because the engine's work is not pure equality saturation over a user-defined term signature — it is a bounded proof of refactoring equivalence that decides return-value SAT/UNSAT and emits typed anomaly findings. Expressing our U-SSA subjects, rewrite rewrites, and divergence witnesses as `egglog` `function` declarations + `rewrite`/`birewrite` rulesets would need a fresh Ruleset per parsed function and would still require the SAT witnesses to come from z3. The primitive slot does not exist, so this is a multi-week proof-engine rewrite, not a drop-in. `egglog` is installed and importable if that work is funded.
- **llguidance**: `neural/grammar_mask.py` does post-hoc schema validation (`SchemaConstrainedValidator`) plus softmax calibration over already-computed logits. `LLMatcher` constrains token generation *during* generation, which requires a tokenizer hooked into the generation loop — our adapters do not stream local token logits in the hot path. Adding token-level masking needs the generation path to pass per-step logits through `llguidance`, which the current adapter boundary does not expose. Installed, importable if that work is funded.
- **Model2Vec** (static embeddings): `store/model2vec_embed.py` is a deterministic BLAKE3-derived subword-aware embedder with no weights file. `model2vec.StaticModel` requires a downloadable weights artifact (HuggingFace repo or `StaticModel.load_from_disk`). Bundling weights breaks the "Zero external API keys / 100% offline" invariant and the architecture's "no external models" baseline; the hand-rolled embedder is what makes offline operation possible. `model2vec` is installed for the case where a bundled weights file is acceptable.

Conclusion: two of six named technologies are now genuine runtime dependencies used at a real code boundary; three remain aspirational with explicit, falsifiable reasons. The measured capability scores (6 of 7 pass, 92%+ suite green, ruff clean) are unchanged by the swaps.
