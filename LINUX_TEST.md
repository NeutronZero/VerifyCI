# VerifyCI on Linux Kernel v6.6 — Boundary Probe Results

Date: 2026-10-03. Tool: VerifyCI `v1.1` @ `9be1fb4`, unmodified during test
(foreign worktree edits from a concurrent process stashed to
`stash@{0} "foreign-session-WIP-do-not-lose"`, never committed; Tier 1 totals
re-ingested on the clean tree reproduce byte-identically: 5649 entities,
13724 edges, same 29-file parse-error list, same content-addressed revision).
Base: torvalds/linux `v6.6` (`ffc2532`), shallow partial clone + per-blob export
(Windows reserved path `drivers/gpu/drm/nouveau/nvkm/subdev/i2c/aux.c` breaks
`sparse-checkout`/`archive` on Windows; environmental, not a VerifyCI finding).

**Zero tracebacks in any tier.** Every ingest, query, and verify-diff completed
without an infrastructure error. That is the strongest positive in this run.

## Per-tier ingest metrics

| Metric | Tier 1 `kernel/sched/` | Tier 2 `net/ipv4/` | Tier 3 `drivers/gpio/` |
|---|---|---|---|
| Files exported / ingested | 39 / 38 (1× Makefile) | 138 / 132 (6× Kconfig/Makefile/.asn1) | 198 / 195 (Kconfig/Makefile/TODO) |
| LOC (wc -l sum) | 49,356 | 108,707 | 79,224 |
| Ingest wall time | 5 s | 10 s | 8 s |
| DB size | 15.9 MB | 36.7 MB | 27.0 MB |
| Entities (ingest out / stats) | 5649 / 5062 | 12456 / 12364 | 10155 / 10110 |
| Edges (ingest out / stats) | 13724 / 13446 | 31956 / 31910 | 22104 / 22070 |
| Parse errors (files w/ ERROR nodes) | 29/38 | 116/132 | 146/195 |
| Manifest errors | 0 | 0 | 0 |
| Resolution resolved/ambiguous/missing | 1376 / 68 / 5316 | 1174 / 3 / 19342 | 1264 / 18 / 11866 |
| Resolved fraction | 20.4% | **5.7% — Tier 2 FAIL** | 9.6% (marginal fail) |
| Incremental re-ingest (Tier 1) | 0.2 s, 0 files re-parsed | — | — |

Tier 1 mix: 1787 FUNCTION, 51 CLASS, 2920 PARAMETER, 266 IMPORT, 38 MODULE.
Stored CALLS are 2206 intra-file / **0 cross-file** in every tier; cross-file links
exist only via load-time deferred resolution, never persisted. Stored edge types
Tier 1: 6760 CALLS_UNRESOLVED, 2206 CALLS, 2199 REFERENCES, 2015 CONTAINS, 266 IMPORTS.

Spot queries: "context switch" → `core.c:5108`; `schedule`, `pick_next_task`,
`update_rq_clock`, `sched_setscheduler`, `enqueue/dequeue_task_fair` grounded.
Bare `task_tick` correctly absent (per-class dispatch: `task_tick_fair/rt/dl/idle`,
all present). Tier 2: `tcp_sendmsg` at `tcp.c:1335`. Tier 3: `gpiochip_add`
absent from v6.6 (renamed `gpiochip_add_data_with_key`, `gpiolib.c:737`) —
tool correct, probe name stale. `sock_net` (Tier 2 miss): declared in
`include/net/sock.h`, outside the ingested subtree — Case A, not a bug.

`core.c` ERROR nodes (195): ~all kernel macro idiom, expected and boring —
53 preproc-split declarations (`const_debug`/`__read_mostly` + `#include`
mid-declaration), declaration macros (`DEFINE_PER_CPU…`, `DECLARE_WORK`),
call-site macros (`for_each_*`, `WARN_ON_ONCE`, `READ_ONCE`), lock annotations
(`__acquires`, `__maybe_unused`), plus 1 stray at the SPDX line. Not grammar
collapse; extraction still yields 426 functions with 19/20 sampled spans exact.

## Tier 4 — real patches, per-patch parent revision (corrected procedure)

One DB per patch, ingested at `<sha>^`, so removal verification compares against
the true base. (An earlier single-shared-DB variant was discarded as mis-set-up:
its base postdated the patches. Its numbers are not reported here.)
Result: **4 PASS / 5 HUMAN_REVIEW / 1 INCONCLUSIVE / 0 FAIL** — the gate reached
a verdict on **4 of 10** and declined on 6 (criterion: ≥ 3 decisive — clears,
but the 6 declines are the finding, not the 4 verdicts). Verify 0.4–0.6 s
per patch, ~5 s parent ingest each. Zero false rejections of merged upstream fixes.

| Patch | Type | Verdict | Mechanism |
|---|---|---|---|
| 2f2fc17bab00 EEVDF slice on placement | bug-fix | PASS | deterministic checks pass |
| 450e749707bc SMT4 group_smt_balance | bug-fix | PASS | deterministic checks pass |
| b01db23d pick_eevdf fix (rename) | bug-fix | PASS | removal verified vs true parent |
| fc09027786c9 RT livelock | bug-fix | PASS | deterministic checks pass |
| 650cad561cce avg_vruntime | bug-fix | HUMAN_REVIEW | blast saturated (non-blocking) |
| 8dafa9d0 min_deadline heap integrity | bug-fix | HUMAN_REVIEW | blast saturated (non-blocking) |
| 9e0bc36ab07c cpufreq next_freq | bug-fix | HUMAN_REVIEW | blast saturated (non-blocking) |
| cff9b2332ab7 boot task idle setup | refactor | HUMAN_REVIEW | blast saturated (non-blocking) |
| d2929762 EEVDF heap corruption | bug-fix | HUMAN_REVIEW | reasoner pass + removal pass (1 line verified), 9 affected callers → score 0.0 |
| f8858d96061f should_we_balance opt | perf | INCONCLUSIVE | unestablished blocking checks — honest decline on an optimization with no witness |

H1/H5 shape confirmed end to end: the reasoner passes real fixes, removal
verification works against a true parent, and saturated blast radius (H5)
routes to a human rather than failing — but HUMAN_REVIEW is an escalation,
not a verdict. On 10 historical kernel patches the gate concluded on 4 and
declined on 6, five of the six on blast saturation alone. That ratio is the
Tier 4 finding: verdict capacity is narrow, escalation capacity is doing the
work. The lone INCONCLUSIVE is the CLASS_2 pattern:
a behavior-preserving-ish optimization the tool cannot establish without an
execution witness. The `pick_eevdf`→`__pick_eevdf` rename passes against its
parent; renames decline only when the base has moved underneath them.

## Tier 5 — precision/recall on `kernel/sched/core.c` (20+20 samples)

- Recall 19/20 strict (20/20 allowing the miss: `#ifdef`-duplicated
  `uclamp_update_root_tg` — sampler picked the `#else` stub at `core.c:1793`,
  entity correctly at `core.c:1779`).
- Precision 19/20. The one false positive is the real finding (next section).

## Finding: macro-invocation entities (`for_each_clamp_id(clamp_id) {`)

Not H1's "unknown macro in declaration position". A statement-position macro
with braces is promoted by tree-sitter's C grammar to `function_definition`,
the extractor trusts the node type, and the loop variable becomes the entity
name. Scale in Tier 1: **73 `macro(arg) {` sites** (`for_each_*`, `for_each_class`,
`for_each_online_cpu`, …), **43 phantom FUNCTION entities** (`clamp_id`, `i`,
`cpu`, `node`, `pgdat`, `class`), sourcing **204 phantom edges** (34 resolved
CALLS misattributed from the real enclosing function, 134 CALLS_UNRESOLVED,
34 REFERENCES) plus forced ambiguity (34 entities share 3 names). ~2.4% entity
pollution with downstream blast-radius inflation on any nearby patch.

Distinguishable without heuristics. Real definition:
`function_definition → primitive_type + function_declarator → parameter_list`.
Macro promotion:
`function_definition → type_identifier + parenthesized_declarator`, **no
`function_declarator` anywhere**. Recommended fix (not implemented here per
the plan's non-goal): require a `function_declarator` descendant outside any
nested body for C/C++ `function_definition` entities. Node-shape filter, cheap,
precise — V1-worthy.

## Hypotheses / criteria

- H1 extractor: MIXED — attributes fine, macro idiom degrades spans/edges, not counts.
- H2 resolution: STRONGER THAN EXPECTED — stored cross-file CALLS = 0 at all tiers.
- H3 scale: PASS with margin (109K LOC in 10 s, 36.7 MB vs 30 min / 500 MB budget).
- H4 verification: PASS on count (4/10 decisive ≥ 3; 0 false FAILs), but the
  substantive result is 6/10 declined — verdict capacity narrow, escalation
  carrying the load.
- H5 blast saturation: CONFIRMED (5/10 HUMAN_REVIEW via saturated blast).
- Tier 1: 3/4 (fails only "no parse_errors on core.c"). Tier 2: FAIL (5.7% < 10%).
  Tier 3: no crash ✓, fails floor 9.6% < 10%. Tier 4: PASS.

## Boundary statement

VerifyCI is usable for C codebases up to `kernel/sched` scale (~50K LOC / ~40 files)
for extraction and interactive query on an intra-file graph. `net/ipv4` at ~109K LOC
resolves 5.7% — its cross-file graph is effectively single-file for verification
purposes, and Linux kernel networking is outside the tool's usable envelope for
cross-file reasoning. **Cross-file call-graph claims are not supported at any
tested tier** (no persisted cross-file CALLS; resolution is load-time only).
The verification gate is decisive on small real patches (4 verdicts in 10,
0 false FAILs) iff the DB predates the patch; saturated blast radius routes to
HUMAN_REVIEW rather than failing; renames and optimizations without witnesses
decline.
On C, `has_error` is not a parse-health signal. 194 of 195 ERROR nodes in
`kernel/sched/core.c` are one macro-boilerplate idiom (storage-class/section
macros, declaration macros, call-site macros, lock annotations,
preprocessor-split declarations); the flag fires on essentially every real
kernel file. Extraction accuracy is unaffected (19/20 recall on hand-checked
functions in a file carrying a whole-file ERROR span). Treat `has_error` as
raw debug data, not as a per-file health flag — the "76% of files with ERRORs"
number above is not a defect. (A C-tolerant gating change —
`has_error AND zero_entities` — exists as unmerged WIP on branch
`wip/c-tolerant-parse-errors` (created 2026-10-03, based at `9be1fb4`),
with tests; this report's numbers use the
unmodified `9be1fb4` behavior.)
Macro-invocation entities (~2.4% pollution, 204 phantom edges in Tier 1) are the
largest known extraction defect and are filterable by node shape.
