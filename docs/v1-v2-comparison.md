# VerifyCI v1 vs v2 — Comparison

Measured 2026-10-15 against the working tree (v2 with remediation applied) and
`81b5a70^` (last v1 commit before the v2 branch removed the package).

All v2 numbers below come from running the engines against the frozen corpora
and scoring the result against the frozen ground-truth labels. No number here is
taken from a spec, a README, or a design document.

## Size

| | v1 | v2 |
|---|---|---|
| engine | 21,864 LOC / 127 files | 10,329 LOC / 40 files |
| tests | 27,682 LOC / 174 files | 2,569 LOC / 9 files |
| subsystems | 15 | 8 |

v2 is 46% of v1's engine and 8% of its tests. Most of that reduction is
deliberate consolidation, not loss — v2 merged v1's 22 `verification/` modules
into 3, and replaced 10 `secrets/` modules with one engine. Some of it is genuine
absence; the table below separates the two.

## Measured capability

v1 recorded its results in each corpus's `results.json` and `RESULTS.md` against
its own harness. v2 is scored by the same frozen labels.

| capability | v1 | v2 now | bar | note |
|---|---|---|---|---|
| cap002b secret detection | recall 0.8696, precision 1.0 | **0.9130 / 1.0** | 0.8696 | above v1 |
| cap011 held-out secrets | recall 1.0, precision 1.0 | **1.0 / 1.0** | 0.95 | parity |
| cap004 call contracts | measured by v1 harness | **0.9722** | 0.90 | v2 restored |
| cap003a removal provenance | measured by v1 harness | **0.9167** | 0.90 | v2 restored |
| cap009 diff impact | measured by v1 harness | **1.0000** | 0.95 | v2 restored, 25/25 adversarial |
| cap002 held-out patches | agreement 0.8235 | **0.70** | 0.8235 | **below v1**, 0 false accepts |
| cap006 temporal replay | digest oracle | not measurable | — | digest parity not reached |
| cap008 concurrency | 64-case worker protocol | not measurable | — | needs replay harness |
| cap010 retrieval | ranking oracle | not measurable | — | lexical retrieval dropped |
| cap005/007/012/013 | smoke fixtures only | not measurable | — | no independent oracle |

Of the six capabilities with frozen ground truth, v2 now passes five. The one
failure is below v1's recorded result, and all three disagreements are
fail-closed behaviour — false accepts are zero.

## Where v2 is genuinely better

**The verifier core.** v1's defect checkers were AST and regex pattern matchers
(`call_swap.py`, `guard_inversion.py`). v2 compiles U-SSA and solves Z3 path
formulas, extracting concrete counterexample assignments. v1 could say "these
arguments look swapped"; v2 can say "swapped when a=1, b=2". Nothing in v1 could
do this.

**Blast radius.** cap009 is exact on all 225 frozen cases including 25 adversarial
ones, with exact path identity. v1's mapper existed but v2 dropped it entirely
until this session.

**Provenance.** v2 emits RFC 8785 canonical receipts wrapped in DSSE with a
hash-chained RSL. v1's equivalent was a local SQLite ledger.

**Store.** v2 has one DuckDB/Arrow store; v1 had SQLite plus JSON float caches.

## Where v2 is worse or missing

**Test suite.** 27,682 LOC across 174 files became 2,299 across 9. That is the
single largest regression in the comparison and the reason so much of v2's
behaviour was unverified when I started.

**Four capabilities lost their only measurement.** cap005, cap007, cap012, and
cap013 are exercised only by the self-test smoke suite, where the same harness
supplies the fixture and the answer. v1 measured cap005 and cap013 against
`patch_real` and `robustness` corpora. Those harnesses now import a deleted
package and are dead.

**Dropped subsystems with no migration target:**

| v1 subsystem | LOC | v2 |
|---|---|---|
| orchestration (planner, executor, scheduler, budget/permissions) | 809 | absent |
| retrieval (BM25, fusion, reranker) | 1,347 | RaBitQ vector search only |
| graph (builder, traverse, stats, temporal) | 858 | partial, in DuckDB |
| memory (ledger, replay, snapshot) | 357 | absent |
| observability (OTel) | 153 | absent |
| evidence | 599 | absent |
| export (SARIF) | 464 | partial |
| HTTP interface | — | absent |

**One latent fault class.** `VC2-RETURN-VALUE-EQUIVALENT` (formerly
`VC2-EGGLOG-EQUIVALENT`) is a return-value claim that
reads as a safety verdict. It no longer suppresses secret or dangerous-call
findings, because those checkers run independently — but the name still
misleads a reader.

**Removal provenance is wired into the gate (since this round).** The patent
tautology was closed by a new source_snapshots table holding verbatim
source per commit. ingest records it, erify-diff --db reads it back; with
no stored base the check is skipped (by design, not by quiet failure). A diff
claiming to remove charge = 999 from a revision that contains charge = 10
now FAILs end-to-end with VC2-CAP003A-FABRICATED-REMOVAL. Cap003a is now
measured: 0.9167 vs 0.90 bar and enforced in the gate.

## Verdict

v2 is a better verifier and a worse project.

The verification core is a real advance: Z3-proven counterexamples with concrete
witnesses, exact blast-radius attribution, and cryptographic provenance are
things v1 could not do at all. On the six capabilities that can be scored against
frozen labels, v2 passes five and the sixth fails closed with zero false accepts.

The regression is everything around it. A 92% cut in tests, four capabilities
reduced to self-graded fixtures, and a benchmark harness that failed at import
while still reporting `verified_integrity: true`. The architecture was sound
enough to specify; the delivery was not carried.

The gap is now measurable rather than assumed, which is the part that matters:
every remaining gap has a frozen corpus, a named bar, and a runner that either
measures it or declares why it cannot.

---

## Dependency status (spec named six; resolved this round)

| spec dependency | v1 actually used | v2 now | status |
|---|---|---|---|
| msgspec | n/a (v1 didn't use it either) | 45 classes converted to @msgspec.struct(frozen=True); canonical receipt path uses msgspec.to_builtins | **real** |
| securesystemslib (DSSE) | custom | dsse_pae delegates to Envelope(...).pae() | **real** |
| egglog | no | hand-rolled equivalence; installed/importable but no primitive slot for typed witnesses | aspirational |
| llguidance | no | post-hoc SchemaConstrainedValidator; no token-generation path | aspirational |
| Model2Vec | no | deterministic BLAKE3 embedder (weights-free, keep offline invariant) | aspirational (weights gap) |
| z3 | no | real � U-SSA + path-sensitive proving | **real** |
| duckdb | sqlite+json | one arrow store, ctive_backend disclosed | **real** |
| wasmtime | subprocess/manual | sandbox with fuel limits | **real** |

Two of the six spec-dependent items moved from aspirational to real. The other three have explicit, falsifiable blockers.
