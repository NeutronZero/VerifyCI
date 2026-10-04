# VerifyCI

**Every agent action verified before human review.**

VerifyCI is a verification-first code intelligence platform: project code is
parsed into a bitemporal code-property graph, agent diffs are mapped onto that
graph, and a deterministic policy decides `PASS` / `FAIL` / `HUMAN_REVIEW` /
`INCONCLUSIVE`. LLMs may propose — only deterministic checks establish
verification.

## Quickstart

```bash
pip install -e ".[dev]"
verifyci init ./repo
verifyci ingest ./repo
verifyci stats
verifyci query "where is auth?"
verifyci verify-diff "$(git diff)" --db ./repo/.verifyci/verifyci.db
verifyci run "ship it" --diff "$(git diff)" --db ./repo/.verifyci/verifyci.db
verifyci serve --db ./repo/.verifyci/verifyci.db   # MCP over stdio (or http)
```

`verifyci` is the primary command; the legacy `aci` console script is a
kept alias for the same app, and environment variables read
`VERIFYCI_*` first with `ACI_*` as fallback.

## How verification works

```
diff --git a/src/app.py ...
  ↓  parse_unified_diff (canonical) → files/hunks/status → map onto graph entities (diffmap)
premises (per changed file) → traces (call-flow paths from changed entities)
  → evidence (file + lines + source hash) → deterministic checks
  → Certificate → PolicyEvaluator → Decision
```

Grounding rules (no exceptions):

- A diff naming no files, or only CODE_CORE files absent from the graph, is
  `INCONCLUSIVE` — never `PASS`. Every CODE_CORE file must ground,
  regardless of extension: a clean `.py` hunk does not launder
  unverified content (`Dockerfile`, CI workflows, `.env`) in the same
  diff into a `PASS`.
- Diffs with no CODE_CORE files take partition fast paths (docs-only,
  valid-config-only, test-only): the certificate passes, but the
  end-to-end verdict is still `HUMAN_REVIEW` — never CLI `PASS`. The
  provenance check requires non-empty evidence, which fast paths carry
  none of by construction. Stated plainly: CLI `PASS` means grounded
  code entities plus evidence, so routine commits touching docs or
  config alongside code read `HUMAN_REVIEW`/`INCONCLUSIVE`
  (declined, routed to human review — not blocked, exit 2) rather than `PASS`.
- A change whose **content the diff does not carry** (a binary file, or
  a mode-only change) is never hidden and never laundered: it is
  named, classified, and forces `INCONCLUSIVE` — a mixed text+binary
  commit cannot PASS on its text half alone.
- **Every changed line must land inside a code entity span:** an edit outside
  every entity span (module-level constants, flags, stray statements)
  forces `INCONCLUSIVE` (inability, `established=False`) rather than laundering
  into `PASS` on unrelated entity grounding in the same file.
- **Infrastructure is not a verdict.** A missing, locked, or corrupt
  database — or a requested revision that does not exist — is reported
  as `INFRA_ERROR` (CLI exit 3), distinct from the four verification
  states (PASS 0, FAIL 1, HUMAN_REVIEW/INCONCLUSIVE 2). Diff-intrinsic
  detections (a secret or forbidden call the patch itself adds) still
  FAIL even when storage is broken: fail-closed outranks the
  bookkeeping. The store runs in SQLite WAL mode so a concurrent
  reader sees the last committed graph instead of failing.
- Every `-` line must have existed where claimed: removed lines are
  checked against stored base-revision snippets at the hunk's old-side
  offsets. A removal contradicting the stored record is `FAIL`
  (stale, hallucinated, or forged diff). Verified removals of known
  code stay `INCONCLUSIVE` (behavior not verified); removals outside
  entity spans or inside truncated snippets are inability
  (`INCONCLUSIVE`), never `PASS` — so comment-only edits decline
  rather than verify.
- `certificate_verified` requires every deterministic check passed, plus
  non-empty traces and evidence.
- Invariant checkers fail closed: `secrets_scan`, `provenance_check`,
  `forbid_call:<name>`, `forbid_import:<module>`. Unknown queries fail.
  A `forbid_*` graph violation is attributed only when it lies in a file
  the diff touches: a call that already existed in the base is a
  pre-existing condition, not a new one, and does not fail an unrelated
  diff (it is named in the explanation, not hidden). A diff that names
  no files keeps whole-graph semantics. These are deterministic
  invariant/lint checks, not a security boundary — `e = eval; e(x)`
  aliases evade them by design.
  `secrets_scan` covers quoted assignments, long unquoted values, AWS
  keys, PEM blocks, JWTs, credentialed URLs, JSON-colon values, and
  multiline/continuation literals. Labeled-set recall: **6/9 (0.67)** on
  the v1 set, **16/18 (0.89, precision 1.00)** on the 26-case expanded v2
  set spanning 11 positive secret mechanisms; the ≥0.90 gate is **not
  met** and neither corpus establishes it. Misses are two documented
  residuals (unquoted value below the 12-char floor; graph-relative-import
  blindness). Not a general leak detector.
- V1 proves **provenance and impact**, not semantic intent: a mapped,
  secret-free diff verifies structurally. Intent judgment stays with policy
  reviewers and project-specific invariants. A PASS means "grounds in known
  entities and trips no invariant" — not "correct". Ordinary human code
  rarely trips the gate (3 PASS / 2 INCONCLUSIVE / 0 FAIL on the last 5
  Flask commits; the two INCONCLUSIVE are an empty merge and a mixed
  changelog diff, both honestly ungroundable);
  subtly-wrong agent patches — the population this exists for — are now
  measured on a frozen 17-case corpus (`benchmarks/patch_corpus/`, labels
  fixed before the run): every *deterministic* wrong patch (forbidden
  call/import, hardcoded secret, fabricated removal) was caught (4/4, FAIL),
  but all 4 *semantic* wrong patches (weakened validation, wrong variable,
  wrong return, wrong constant) were accepted — false-accept 1.0 — confirming
  the scope limit above is real, not just asserted. Verification precision
  1.0 (all FAILs were truly-wrong); patch equivalence 7/8 = 0.875 (the one
  miss is a blast-exposure hunk-shape gap, reported not retuned). Synthetic
  stand-ins for agent output; a real recorded-LLM corpus remains the
  follow-on.
  *(Post-baseline correctness repair: the one C1 miss — the blast-exposure
  tail-insertion hunk-shape gap — is a fixed **seeding defect** (A2), not
  a retuned threshold; re-measured on the identical frozen cases
  patch equivalence 8/8 = 1.0, precision unchanged 1.0. The 8-correct-
  patch synthetic set still does not **establish** the >0.90 gate. See
  V1_EVIDENCE.md addendum.)*
- Blast-radius coverage measured on a frozen topology corpus
  (`benchmarks/blast_corpus/`, expected sets hand-derived before
  detection): traversal is **exact (1.0)** on every seeded hunk — direct,
  transitive 2-hop, multi-path, cross-file, method callee, zero-impact.
  The one miss is the **tail-insertion gap** reproduced as a labeled case
  (a pure insertion after a function's last line seeds `changed_entities=[]`
  → risk 0 → dependents missed): the C1 finding, kept as evidence, not
  repaired. One disclosed precision artifact (a def-line hunk's diff
  context bleeds into the neighbouring function, so the seed re-enters via
  a real caller — detected set stays a superset of expected). Coverage
  6/7 = **0.857** (the 7th being the pre-labeled gap); the corpus is too
  small to *establish* the >0.90 gate, and no traversal defect was found
  on any normally-seeded change.
  *(Post-baseline correctness repair: that gap was a **seeding defect**
  (A2 insertion-anchor grounding), not a traversal one — exactly as
  diagnosed here. Re-measured on the identical frozen cases, coverage is
  7/7 = 1.0 and the labeled gap closes; the disclosed B5 context-bleed FP
  is unchanged. Still not **established**: same 9-case corpus. See
  V1_EVIDENCE.md addendum.)*
- Latency measured on a frozen 1000-sample protocol
  (`benchmarks/latency/`, sources sha-pinned, environment recorded).
  **Temporal query: MET** at the PLAN's 10K-edge scale — median 0.044ms,
  p99 0.151ms against a 200ms limit (~3 orders of margin). **Incremental
  parse: NOT MET at p95** — median 33μs passes (<0.2ms) proving reparse is
  genuinely incremental (cold full-parse is 3.7ms), but p95 ~3.8ms fails
  the 1ms limit on every run. The p99 verdict itself flips across runs
  (4.32/6.14/4.54ms at a 5ms limit) — recorded as evidence that a
  1000-sample protocol cannot *establish* that boundary on this host.
  Mechanism: cost tracks edit position (tree-sitter re-lexes to the next
  change point, so early-file edits re-lex long tails). Thresholds were
  not retuned and no source changed.

## Architecture

```
interface (MCP / CLI / HTTP) → verification (semi-formal, blast, invariants, policy)
→ orchestration (planner → TaskIR → AsyncDAGScheduler, pre-commit gates)
→ retrieval (dense + BM25 + graph → RRF → [rerank: experimental, default off] → EvidencePack)
→ graph (AST CPG, bitemporal, anchor+delta) → storage (SQLite)
```

Rerank is marked experimental until it beats fused ranking on a held-out
set (measured 2 lifts / 4 demotions so far). Dense defaults to offline
hash embeddings (deterministic, no server); `VERIFYCI_EMBEDDINGS=ollama[:model]` (legacy `ACI_EMBEDDINGS`)
opts into local Ollama embeddings behind a content-addressed cache, with
honest fallback to hash when the server is unreachable. Measured on a
small 5+5 query set (`benchmarks/embedding_eval.py`, needs a live server):
ollama beats hash on all four cells (recall +0.10, ndcg +0.02–0.06),
directional not gating; CPU inference runs ~50ms/doc, so the cache —
not the model — is what makes it usable. The retrieval gate itself is
measured on a frozen BEIR-style set (`benchmarks/beir/`, 62 graded queries,
60 docs, judgments frozen before any embedding; drift-guarded harness):
**hybrid nDCG@10 0.6603 vs dense-only 0.6220 = +3.84 points — below the
+5 gate; measured, target not met.** `benchmarks/retrieval_eval.py` stays
historical smoke, never the evidence set.

## Status

V1 walking skeleton. `PLAN.md` is the full plan; `CHANGELOG.md` records what
each revision proved, including measured numbers and known gaps. 760 tests
collected on the v1.1 branch: default `python -m pytest tests/ -q` is 757 passed / 3 skipped;
with all three re-measure guards it is 760 passed / 0 skipped
(`VERIFYCI_PATCH_RERUN=1` / `VERIFYCI_BLAST_RERUN=1` / `VERIFYCI_LATENCY_RERUN=1`).
Locked release endpoint: `v1.0.2-correctness` (618 tests there).

## Known limits

Measured on Linux v6.6 (`LINUX_TEST.md`): extraction and query work at
intra-file scale up to ~50K LOC / ~40 files (`kernel/sched/`), but the stored
call graph has no cross-file CALLS edges and resolution falls below usability
(5.7%) by ~110K LOC (`net/ipv4/`) — treat cross-file reasoning as unsupported,
and any PASS on a large codebase as intra-file evidence only. On 10 real
kernel patches the gate reached a verdict on 4 and escalated 6 (five on
saturated blast radius); per-patch parent-revision ingest is required for
honest verdicts. On C, `has_error` is not parse-health signal (macro idiom
fires it on nearly every file); macro invocations with braces
(`for_each_x(y) {`) additionally extract as phantom FUNCTION entities.

**TypeScript/JavaScript scope (Phase 2)**: TS/JS extraction is verified against `vercel/swr` (20/20) and `sindresorhus/got` (5/5) with explicit relative ES6 imports and unique symbol targets within a package. Complex `tsconfig.json` path mappings, ambient `.d.ts` declarations, namespace merging, and third-party `node_modules` resolution are not covered. Halt floor and acceptance bars are frozen in `tests/evaluation/test_ts_reference_eval.py`.

