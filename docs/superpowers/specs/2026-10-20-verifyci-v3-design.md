# VerifyCI v3 — Demand-Driven Pre-Merge Verification Gate

**Status:** Frozen design (2026-10-20); implementation not started.
**Date:** 2026-10-20
**Supersedes:** `docs/architecture_v2.md`, all v1 and v2 architectural claims.
**Audience:** implementers, reviewers, release engineers.
**Basis:** Frozen design Sections A–D, incorporating all contract corrections.

---

## 0. Document status and evidence boundary

This document is a design specification. It defines the product contract, boundaries,
failure semantics, and release gates for VerifyCI v3. It is not implementation evidence.

Freezing this design does **not** establish that latency, precision, recall, frontend
fidelity, cache parity, or performance targets have been met. Those claims are established
only by release-validation artifacts:

- per-check corpus reports against frozen, hand-authored labels;
- frontend conformance and differential-fidelity reports;
- deterministic evidence-bundle and cache-parity runs;
- cold/warm latency and memory measurements on the reference workload;
- the published `CheckSpec` manifest and its hashes.

Until those artifacts exist and are reviewed, every capability in this document is a
design target, not a measured result.

---

## 1. Product contract

VerifyCI v3 is a local-first, deterministic **pre-merge CI gate for AI-authored diffs**.
It verifies the diff between the merge base and the pull-request head against the policy
of the target branch, then emits:

- a structured verdict and exit code;
- a canonical, reproducible evidence bundle;
- SARIF v2.1.0 for CI and code-scanning surfaces.

The only supported surfaces are a CLI and a composite GitHub Action. There is no daemon,
server, database, network dependency, or model call.

### 1.1 What VerifyCI blocks

The blocking core covers five declared defect families:

1. **Semantic regressions** in modified functions: removed or weakened protected guards,
   inverted guards, swapped argument/return bindings, and removed protected error paths.
2. **Provenance and grounding failures**: integrity failures such as inconsistent Git
   identity (`ERROR`), unmapped changes (`INCONCLUSIVE`), and changes prohibited by an
   explicit `deny_changes` rule (`FAIL`).
3. **Security regressions**: validated secrets, taint flows to dangerous sinks, and exact
   policy-forbidden calls.
4. **Caller and contract breakage**: incompatible signatures, exports, visibility, async
   status, or call sites.
5. **Unsafe deletion**: removed symbols that remain reachable, dangling references, or
   proven dynamic references to removed symbols.

### 1.2 What VerifyCI does not claim

VerifyCI does not prove general program correctness, whole-program equivalence, or full
language semantics. It does not execute repository code. It does not determine whether a
diff is "good"; it establishes whether a declared defect was found with evidence within a
declared scope.

### 1.3 The PASS contract

The following text is normative and must appear in the README, the specification, and the
SARIF `properties`:

> PASS means every applicable blocking check completed with COMPLETE coverage over its
> declared scope and no unwaived declared defect was established. PASS is not a claim that
> the code is correct or that the diff is safe in general. The evidence bundle states what
> was checked, the applicable assumptions, the excluded scope, and any waived findings.

---

## 2. Goals and non-goals

### 2.1 Goals

- Run on every pull request without becoming a CI bottleneck: p95 ≤10 seconds warm
  and ≤60 seconds cold on a 100k LOC reference repository.
- Verify only changed functions and the affected caller/reference closure.
- Require no persistent database and no ingest step for a correct verdict.
- Make every blocking decision reproducible, evidence-backed, and fail-closed.
- Treat unsupported semantics and incomplete candidate discovery as incomplete coverage,
  never as PASS.
- Support Python and TypeScript/JavaScript as first-class languages.
- Keep the trusted computing base and dependency surface small.

### 2.2 Non-goals for v3.0

- General behavioral equivalence or formal soundness for all programs.
- Full-repository semantic indexing or a code-property-graph database.
- LLM judges, conformal prediction, retrieval, reranking, or auto-repair.
- FastMCP daemons, agent servers, or long-lived processes.
- DuckDB, egglog, RaBitQ, WASM plugins, DSSE, in-toto, gittuf, or a hash-chained ledger.
- Executing repository code, including during witness validation.
- Patch-file input mode. v3.0 verifies commit ranges only.
- Full first-class semantics for Go, Rust, C/C++, JVM, or .NET languages.
- Repository-specific checker code or a rule DSL.

---

## 3. Normative invariants

1. No PASS with incomplete relevant coverage.
2. No blocking finding without validated evidence of its declared kind.
3. Advisory findings never change the verdict or exit code.
4. No persistent state is required for correctness.
5. Completed executions with identical logical inputs, policy, toolchain, and deterministic
   analysis budgets produce byte-identical canonical payloads. Resource exhaustion may
   produce INCONCLUSIVE and must never produce PASS.
6. Analysis work is bounded; exhaustion cannot produce PASS.
7. Policy is validated declarative data and never executes code.
8. Unsupported languages never receive unsubstantiated semantic PASS results.
9. Cache is optional, content-addressed acceleration only, and lives outside the
   PR-controlled working tree.
10. Git objects are the sole authority for merge-base, target-base, head, and file contents;
    the working tree is never authoritative.
11. Every registered blocking check produces a `CheckResult`, including not-executed,
    not-applicable, and error results.
12. Checks never call Git, read the working tree, access the network, or share mutable
    semantic state.
13. The policy used for a run is loaded from the target-base commit, never from the head.
14. A validated finding is preserved when its check also faults; the check outcome is `ERROR`
    and the aggregate verdict is `ERROR`.
15. A release manifest exists only after every blocking check has passed its frozen corpus
    and the full invariant, fidelity, and performance gates.

---

## 4. Definitions

| Term | Meaning |
|---|---|
| `target_base_commit` | Current tip of the target branch. Its policy is authoritative. |
| `merge_base_commit` | Verified common ancestor used to define the PR diff. |
| `head_commit` | Exact PR revision being verified. |
| Authoritative policy | Policy blob read from `target_base_commit`. |
| Proposed policy | Policy blob at `head_commit` when the PR changes the policy path; validated for review but never authoritative for the same run. |
| Relevant scope | The entities, files, references, and taint paths a check is required to examine for its declared defect set. |
| Capability | A frontend guarantee such as `signature`, `cfg`, `ssa`, `calls`, `exceptions`, `types`, or `taint`. |
| Candidate | A potential defect instance produced by a check's declared discovery rules. |
| Coverage | `COMPLETE`, `PARTIAL`, or `UNKNOWN`, as defined in §6. |
| Witness | Concrete evidence that demonstrates a divergence or violation within a declared semantics. |
| Waiver | An authoritative policy record that changes a finding's disposition to `WAIVED` without erasing it. |
| `CheckSpec` | Immutable registry record: check ID, version, tier, capabilities, corpus ID/hash, thresholds, toolchain fingerprint. |
| Check manifest | The release-approved set of `CheckSpec` records. |
| Toolchain fingerprint | Versions and configuration of the interpreter, frontends, analyzers, solver, and canonicalizer that can affect results. |

---

## 5. Verdict algebra

### 5.1 Verdicts and exit codes

| Verdict | Exit | Condition |
|---|---:|---|
| `PASS` | 0 | Every registered blocking check has `COMPLETE` coverage and outcome `PASS`, `NOT_APPLICABLE`, or `FAIL` whose findings are all `WAIVED`; no unwaived blocking finding exists; no check is `INCONCLUSIVE` or `ERROR`; no policy/waiver review condition exists. |
| `FAIL` | 1 | At least one independently validated, unwaived blocking finding exists, and no blocking check outcome is `ERROR`. Other checks may be incomplete. |
| `INCONCLUSIVE` | 2 | No unwaived blocking finding and no blocking check outcome `ERROR`, but at least one blocking check is `INCONCLUSIVE`, has `PARTIAL`/`UNKNOWN` coverage, or exhausted its deterministic budget/watchdog. |
| `REVIEW` | 2 | No higher-precedence condition, but a valid proposed policy/waiver change requires designated review, or a waiver fails authorization/scope/expiry requirements. |
| `ERROR` | 3 | Invalid authoritative policy, invalid proposed policy, missing/corrupt required Git objects, manifest mismatch, invalid cache location, any blocking check outcome `ERROR`, internal fault, or invalid check result. |

Precedence: `ERROR > FAIL > INCONCLUSIVE > REVIEW > PASS`.

### 5.2 Verdict rules

- A proven blocking defect establishes a blocking finding. Absent a higher-precedence
  `ERROR`, the aggregate verdict is `FAIL`, even when other relevant scope is unsupported or
  later exhausts its budget. Incompleteness never erases the finding.
- A check that establishes a finding and then faults records outcome `ERROR`, keeps the
  finding and its evidence in `findings[]`, and records the fault in `diagnostics[]`. The
  aggregate verdict is `ERROR`; the finding remains visible and blocking. Any check outcome
  `ERROR` outranks a `FAIL` elsewhere and is never hidden by it.
- A check that has `PASS` with `PARTIAL` or `UNKNOWN` coverage is an invalid result; the
  orchestrator records `ERROR` with reason `invalid_check_result` and preserves any validated
  findings.
- `NOT_APPLICABLE` requires positive applicability evidence. It is never a substitute for
  unsupported analysis.
- Budget exhaustion, a timeout, or a watchdog interruption leaves coverage `PARTIAL` or
  `UNKNOWN` and is `INCONCLUSIVE` (`budget_exhausted` or `watchdog_interrupted`) when no
  finding is established. After a finding, the finding survives and the check outcome is
  `FAIL`. It is never `PASS` and never by itself evidence of a defect.
- Advisory findings are annotations. They do not affect verdict, exit code, or coverage.

### 5.3 Waivers

A waiver changes a finding's `disposition` from `OPEN` to `WAIVED`. It does not remove the
finding, the check result, or the witness. The check retains its highest-precedence outcome:
`FAIL` when the finding is the highest result, or `ERROR` when the check also faulted.
Aggregation asks whether any **unwaived** blocking finding remains, but an `ERROR` outcome
still outranks `FAIL`. Aggregate `PASS` is therefore possible with a `FAIL` check result only
when every blocking check has `COMPLETE` coverage and every blocking finding is `WAIVED`; a
check with outcome `ERROR` never permits `PASS`.

A waiver cannot override:

- `ERROR`;
- incomplete coverage or a `PARTIAL`/`UNKNOWN` check result;
- budget or watchdog exhaustion;
- a `REVIEW` condition;
- missing evidence.

An expired, unauthorized, mismatched, or structurally invalid waiver does not waive
anything. Structural invalidity is a policy validation `ERROR`; expired, unauthorized, or
scope-mismatched waivers are `REVIEW`.

---

## 6. Coverage, check results, and evidence

### 6.1 Coverage definition

> COMPLETE coverage means that scope enumeration and candidate discovery are complete for
> the check's declared defect set within its explicitly supported subset; every relevant
> entity has the required capabilities, and every candidate has been proven, refuted, or
> otherwise accounted for under the check's evidence contract.

`COMPLETE` does not require general program equivalence or a formal soundness proof for every
analyzer. Each check must define:

- its supported syntax and facts;
- its relevant scope;
- its candidate-generation rules;
- how unsupported cases are identified and reported.

A candidate that is never discovered cannot be counted as resolved. Frozen corpora validate
these claims empirically; they do not establish soundness for unseen programs.

Operationally, `coverage = COMPLETE` requires both `scope_enumeration.complete = true` and
`candidate_discovery.complete = true`. If either is false, coverage is `PARTIAL` or `UNKNOWN`,
and the check cannot return `PASS`.

### 6.2 CheckResult

Every registered blocking check receives exactly one top-level record:

```text
CheckResult
  check_id
  check_version
  tier: blocking | advisory
  outcome: PASS | FAIL | NOT_APPLICABLE | INCONCLUSIVE | ERROR
  coverage: COMPLETE | PARTIAL | UNKNOWN
  evaluated_scope
  scope_enumeration { method, version, complete }
  candidate_discovery { method, version, complete }
  applicability_evidence
  method
  method_version
  reason_codes[]
  findings[]           # validated findings; allowed with FAIL or ERROR
  diagnostics[]        # fault detail, expected/actual IDs; required for ERROR
  sub_results[]        # security sub-analyses and other composite checks
  toolchain_fingerprint
```

`outcome` and `coverage` are independent. `FAIL` with `PARTIAL` or `UNKNOWN` coverage is valid
and blocking. `PASS` with anything other than `COMPLETE` is invalid. `NOT_APPLICABLE` requires
`COMPLETE` coverage of the applicability question.

`FAIL` requires at least one finding. `PASS`, `NOT_APPLICABLE`, and `INCONCLUSIVE` carry no
findings; a validated finding makes the outcome `FAIL` unless the check also faults, in which
case it is `ERROR`. `ERROR` requires at least one diagnostic or reason-code entry identifying
the fault, and may carry zero or more validated findings when findings and a fault coexist
(for example, a fault after a defect is proven). `diagnostics[]` records the fault and its
expected/actual evidence. A validated finding is never discarded. If the check that
established it also faults, the outcome is `ERROR`, the finding remains in `findings[]` with
its evidence, and the aggregate verdict is `ERROR`. If no higher-precedence error exists, the
outcome is `FAIL`. A proven finding is never downgraded to `PASS` or `INCONCLUSIVE`.

A fault that prevents analysis of relevant scope must reduce coverage to `PARTIAL` or
`UNKNOWN`; `ERROR` does not by itself redefine coverage. A check may have `ERROR` with
`COMPLETE` coverage only when the fault does not prevent the declared relevant scope from
being analyzed, and it still never yields `PASS`.

Every check record is emitted even when:

- the check is not applicable, with applicability evidence;
- an upstream failure prevents execution, with `ERROR` and reason `not_executed`;
- the check itself faults, with `ERROR` and a contained reason code.

No successful or not-applicable result is fabricated to complete the bundle.

### 6.3 Findings

```text
Finding
  tier: blocking | advisory
  defect_id
  subject { file, entity, base_span, head_span }
  premises { target_base_commit, merge_base_commit, head_commit,
             base_blob, head_blob, authoritative_policy_hash, check_version,
             toolchain_fingerprint }
  evidence:
    kind: solver | provenance | reference | call_site | taint_path | secret_validation
    payload
  witness_level: ir | source | none
  message
  remediation (optional)
  disposition: OPEN | WAIVED
```

A blocking finding requires validated evidence of its declared kind: a solver witness, exact
provenance, an exact reference, a call-site mismatch, a taint path, or a validated secret.
Heuristic suspicion cannot block. Secret evidence is redacted; it must be sufficient to
reproduce the finding without exposing the credential. A finding's canonical identity is the
waiver fingerprint defined in §8.4; it is stable across rebases and excludes line numbers.

### 6.4 Evidence bundle

The bundle has two layers:

**Payload** — deterministic and canonical (RFC 8785 JCS):

```text
schema
tool { name, version, toolchain_fingerprint }
inputs { target_base_commit, merge_base_commit, head_commit,
         policy { authoritative_blob_hash, pr_changed, proposed_blob_hash },
         files[] { path, base_blob, head_blob, mode } }
manifest { check_specs[], manifest_hash }
scope { per-check evaluated_scope }
check_results[]
findings[]
waivers[]
verdict { status, exit_code, reason_codes[] }
assumptions[]
excluded_scope[]
```

**Envelope** — non-semantic metadata:

```text
payload_hash
generated_at
timings
environment
cache_stats
signature (optional)
```

Timestamps, durations, worker counts, cache hits, and environment never enter the canonical
payload. Same logical inputs, policy, toolchain, and deterministic budgets ⇒ byte-identical
payload for completed executions.

The bundle must contain a record for every blocking check, including `NOT_APPLICABLE`
decisions and the evidence supporting applicability. A bug in scope selection must not be
able to turn skipped analysis into PASS.

Findings preserved under an `ERROR` check result remain in `check_results[].findings[]` and
in the top-level `findings[]`; the fault appears in `diagnostics[]`, and the aggregate verdict
remains `ERROR`. Composite sub-results may repeat findings for attribution; the top-level
`findings[]` rollup is deduplicated by canonical finding identity.

SARIF is a derived rendering of the same result: one result per `Finding`, including findings
preserved under `ERROR`, waived findings marked suppressed, check failures as tool
notifications, and the aggregate verdict in run properties. The canonical payload remains
authoritative.

### 6.5 Witness trust boundary for semantic findings

A semantic blocking finding requires all three contracts:

1. **Solver witness** — an input/state assignment demonstrating divergence within the
   declared VFIR semantics.
2. **Replay validation** — the VFIR evaluator independently reproduces the solver's result.
3. **Frontend fidelity** — the source constructs used by the witness are covered by the
   frontend's conformance and differential-fidelity contract.

v3.0 never executes repository code. Its semantic evidence is therefore labelled
`witness_level: ir`, not source-level replay. Source-level runtime replay is out of scope
because executing untrusted repository code violates the gate's security boundary.

Frontend fidelity is established at release time by trusted fixtures in VerifyCI's isolated
CI. A fidelity mismatch invalidates the affected frontend capability and prevents the
semantic check from being released as blocking.

---

## 7. Pipeline

### 7.1 Required initialization order

1. Validate CLI arguments and resolve the requested commit identities.
2. Verify required Git objects and determine the merge base.
3. Load and validate the authoritative policy from `target_base_commit`.
4. Build the authoritative `DiffModel`, resolve changed scope, and detect PR-authored policy
   changes from the merge-base..head path set. Validate the proposed head policy only when
   that path set includes the policy file.
5. Execute checks, aggregate results, and serialize evidence.

Policy loading cannot precede commit/object validation because the policy blob must be read
from an identified, verified commit. Target-base policy remains authoritative; the diff is
used only to determine whether the PR itself changed the policy.

### 7.2 Stages

```text
CLI
 │
 ├─ [0] argument and commit-identity validation
 ├─ [1] Git object verification + merge-base resolution
 ├─ [2] target-base policy load + validation
 ├─ [3] DiffModel construction (merge-base..head)
 ├─ [4] scope resolution (cheap entity spans, hunk mapping)
 ├─ [4b] PR policy-change detection + proposed head policy validation
 ├─ [5] demand-driven facts (VFIR, symbols, callers, summaries)
 ├─ [6] checks: grounding, deletion, contract, semantic, security
 ├─ [7] aggregation + waivers
 └─ [8] canonical bundle + SARIF + exit code
```

After successful initialization, all five checks run. Grounding runs first and its result is
retained, but it is not a short-circuit. Absent a higher-precedence `ERROR`, a proven security
or semantic defect still establishes aggregate `FAIL` when grounding elsewhere is
inconclusive. `ERROR` retains highest precedence.

If an upstream failure prevents a check from executing, that check still receives a record:

- prerequisites remain trustworthy ⇒ continue with other checks and preserve diagnostics;
- prerequisite is untrustworthy ⇒ record `ERROR` with `not_executed` and the reason code.

If initialization fails before any check can execute, every registered blocking check
receives `ERROR` with `not_executed`, the initialization error is preserved, and the aggregate
verdict is `ERROR`. No PASS is emitted.

### 7.3 FactProvider boundary

`verifyci/index/provider.py` owns demand resolution:

- authoritative blob reads through `scm.git`;
- cache lookup, validation, and fallback;
- deterministic production of entity spans, file symbol facts, VFIR, summaries, and solver
  results;
- propagation of capability and coverage reasons.

`verifyci/index/symbol_index.py` owns symbol indexing and reverse lookups only. It does not
become an implicit owner of every fact source or of Git access.

Checks receive a `DiffContext` and a `FactProvider` interface. They never import `scm`,
`cli`, or storage modules.

---

## 8. Git truth and policy binding

### 8.1 Git authority

`verifyci/scm/git.py` is the only module authorized to access Git. It exposes a read-only,
commit-pinned object interface. The pipeline and `FactProvider` use it; checks do not.

The working tree is never authoritative. All base, merge-base, and head content is read from
Git objects. The gate requires a real repository; it does not trust files on disk.

### 8.2 Commit identities and merge base

- CLI accepts the target base and head revisions.
- The gate computes the merge base internally and verifies it is a common ancestor.
- The PR change set is `merge_base_commit..head_commit`.
- The policy is read from `target_base_commit`.
- The diff is never computed against the target tip unless the target tip is also the merge
  base.

If multiple merge bases exist, the gate returns `ERROR` (`ambiguous_merge_base`) unless an
explicit merge-base revision is supplied and verified as a common ancestor of both sides.

The GitHub Action must fetch the target base, head, and enough history to establish the merge
base. A shallow checkout that cannot establish a unique merge base yields `ERROR`; it does not
fall back to the target tip or the working tree.

### 8.3 Policy cases

| Condition | Result |
|---|---|
| Invalid authoritative policy at target base | `ERROR` |
| PR-authored policy change: `.verifyci/policy.toml` appears in merge-base..head | `REVIEW`; head policy validated but not used |
| Head policy differs from target base only because the target branch advanced | No policy-change `REVIEW`; target-base policy remains authoritative |
| Invalid proposed policy schema when the PR changes it | `ERROR` |
| Proposed deletion: PR removes the policy file | `REVIEW` when the authoritative policy is valid |
| Structurally valid waiver with invalid authorization, scope, or expiry | `REVIEW` |
| Valid active waiver from authoritative policy | Finding disposition `WAIVED`; all other gate requirements still apply |
| New waiver added in the PR | Cannot neutralize a finding in that PR; PR policy change is `REVIEW` |
| Head policy used to govern the same PR | Forbidden |

Policy-change detection uses the merge-base..head change set, not a direct comparison between
head and target base. The path set is unfiltered by policy path classes; a PR cannot hide a
policy change by excluding its own path. Target-branch advancement can make the head policy
older than the target policy without the PR changing it; that difference alone does not
trigger `REVIEW`.

The detection sequence is:

1. Read and validate the authoritative policy from `target_base_commit`.
2. From the `DiffModel`, check whether `.verifyci/policy.toml` is in merge-base..head.
3. If it is not changed, do not validate the head policy for change detection and do not emit
   a policy-change `REVIEW`. The run uses the authoritative policy.
4. If it is changed, read the head blob:
   - missing ⇒ proposed deletion ⇒ `REVIEW`;
   - malformed ⇒ `ERROR`;
   - valid ⇒ `REVIEW`, record the proposed policy hash, and never use it for this run.
5. Waivers are part of the policy blob. A waiver added or changed in the PR is a PR-authored
   policy change and cannot neutralize the PR's findings. A waiver in the authoritative
   policy remains effective.

The evidence records `policy.pr_changed` and the proposed hash when one exists. A PR must not
be able to silence its own findings by modifying policy or waivers. A missing authoritative
policy is `ERROR`.

### 8.4 Policy format and safety

Policy is TOML at `.verifyci/policy.toml`, schema-validated. It contains:

- path classes: generated, vendored, tests, binary rules;
- entrypoints and public API symbols;
- protected guards, sources, sinks, forbidden calls;
- `deny_changes` constraints over protected paths and exact symbols;
- secret allowlists by path and placeholder form;
- waivers with check ID, defect ID, finding fingerprint, reason, approver, expiry;
- review requirements for policy changes.

Policy uses globs and exact qualified names only. Symbol strings use dot-separated qualified
names; `*` is permitted only in fields documented as accepting symbol globs, such as public
API declarations and sink patterns. It does not support user-supplied regular expressions,
code, templates, or includes. This avoids ReDoS and code-execution hazards. All paths are
normalized and confined to the repository; path traversal is an `ERROR`.

`deny_changes` is the only general change-prohibition mechanism. Each entry has a table key
used as its `id`, optional `paths` globs, optional `symbols` exact qualified names, and a
`reason`. At least one of `paths` or `symbols` is required. Path rules match any changed
path whose base or head path matches; symbol rules match only an exactly mapped changed
entity. There is no regex, code, or allow-override inside a rule. `deny_changes` rules apply
regardless of path-class exclusions; a denied path or symbol cannot be excluded from
grounding. Rules are evaluated in canonical table-key order. A change matching multiple rules
yields one finding with the first matching rule ID as primary and all matched rule IDs recorded
in evidence. Excluding a non-denied path requires a separate path-class change and the same
review.

The gate ships versioned built-in patterns for secrets, dangerous calls, taint sources, and
sinks. Policy may extend these and add scoped allowlists; it cannot disable a blocking check
or globally suppress a defect family. Path-class exclusions and waivers are the only
scoped suppression mechanisms; `deny_changes` adds prohibitions. Changing any of them is a
reviewable policy change.

A waiver is authorized for v3.0 when it is present in the authoritative target-base policy
and carries a non-empty approver and reason. VerifyCI does not authenticate human identity;
that is the target branch's review process. Missing or empty authorization fields yield
`REVIEW`; malformed waiver structure is `ERROR`.

A waiver is matched by a fingerprint: SHA-256 over canonical `{check_id, check_version,
defect_id, repository-relative path, stable symbol identity when available, normalized
evidence identity}`. Evidence identity is redacted where applicable. Commit IDs and line
numbers are excluded so a waiver survives rebases; a waiver cannot match a different defect
or a different check version. Without a stable symbol identity, the waiver matches the
normalized span and is expected to expire quickly.

### 8.5 CLI contract

```text
vc gate --repo <dir> --base <target-base-rev> --head <head-rev>
        [--merge-base <rev>] [--format json|sarif] [--output <path>]
        [--cache-dir <dir> | --no-cache] [--jobs <n>]
```

- `--base` is the target-branch revision whose policy is authoritative; it is not the merge
  base.
- `--head` defaults to `HEAD`; CI passes the exact PR commit.
- `--merge-base` is accepted only when verified as a common ancestor; otherwise `ERROR`.
- `--format json` emits the canonical evidence bundle; `sarif` emits CI output.
- `--jobs` affects only fact-computation parallelism and never semantics.
- There is no patch-file input, network access, or repository execution.
- Exit codes: `0` PASS, `1` FAIL, `2` INCONCLUSIVE or REVIEW, `3` ERROR.

---

## 9. Scope and grounding

### 9.1 Entity mapping

Entity spans are extracted cheaply in Stage 4, before full lowering. Stage 5 lowers VFIR only
for changed entities and affected callers.

| Change | Required mapping |
|---|---|
| Modified entity | Exactly one base entity and exactly one head entity |
| Added entity | No base entity and exactly one head entity |
| Removed entity | Exactly one base entity and no head entity |
| Supported module-level edit | Exactly one recognized module-level construct |
| Ambiguous or unsupported mapping | Explicit unresolved scope with coverage/reason codes |

Ambiguity is not itself a defect. It produces unresolved scope and `INCONCLUSIVE` unless
another proven blocking defect establishes `FAIL`.

### 9.2 Grounding check contract

| Field | Definition |
|---|---|
| Declared defect | `GRD-UNGROUNDED-EDIT`: a changed path or exactly mapped entity matches an active `deny_changes` rule. Path matches are established from the base/head path and changed span or blob identity; symbol matches require exact entity mapping. A mapping failure alone is not this defect. |
| Integrity errors | Deleted bytes disagree with the pinned base blob; commit/tree/blob/merge-base identity contradicts pinned inputs; internally generated diff is inconsistent. These are recorded as `ERROR` diagnostics, not findings. |
| Unmapped changes | A hunk with no supported mapping is unresolved scope (`mapping_unresolved`) and yields `INCONCLUSIVE` unless a `deny_changes` path rule independently establishes a violation. |
| Relevant scope | Every changed path in merge-base..head and every active `deny_changes` rule. Text hunks are mapped to entities; binary changes are path/provenance-only but are still evaluated by path rules. Policy-excluded files receive explicit not-applicable results with exclusion evidence unless a `deny_changes` path or symbol rule applies. |
| Applicability evidence | At least one changed file or hunk not excluded by authoritative policy, or at least one `deny_changes` rule applicable to the change set. No changes, or all changes excluded with no applicable deny rule, ⇒ `NOT_APPLICABLE` with exclusion evidence. |
| Supported subset | Language-independent byte/line/path mapping and exact symbol matching. Path rules apply to text and binary; symbol rules require exact entity spans and apply only to text. Symbol rules in unsupported languages are `UNKNOWN`, never `NOT_APPLICABLE`; path rules still apply. Binary changes use exact blob identity; path-only changes use exact path/mode identity. |
| Required evidence | Exact `deny_changes` rule IDs (primary and all matches), matched path or exact symbol, changed span or path/blob/mode identity, base/head blob IDs, and authoritative policy hash. Integrity errors cite expected/actual object IDs in `diagnostics`. |
| Coverage | `COMPLETE` when every in-scope changed path is classified as modified entity, added entity, removed entity, supported module-level edit, binary, or path-only; excluded paths have exclusion evidence; every active `deny_changes` rule is evaluated; and all provenance checks agree. `PARTIAL` when a symbol rule cannot be resolved because mapping is ambiguous. Path rules are always resolvable from paths. Missing policy or objects are `ERROR`. |
| Failure conditions | Path or exact symbol match ⇒ `FAIL`. Integrity mismatch ⇒ `ERROR`. Ambiguous symbol rule alone ⇒ `INCONCLUSIVE`. |
| Frozen corpus | Modified/added/removed entities, module-level edits, boundary hunks, duplicate lines, CRLF/LF, Unicode, renames, path-only/mode-only changes, generated/vendored paths, policy exclusions, protected-path modification/addition/deletion/rename, protected binary path, protected-symbol modification/deletion, ambiguous protected symbol, path-glob boundaries, no `deny_changes` rules, tampered diff models, stale base, wrong merge-base, missing blobs. |
| Oracle bar | Precision 1.0, provenance outcomes 100%, coverage classification 100%, zero false `FAIL`. |

Fabricated-removal detection is an integrity error in commit mode. If a future patch-input
mode is added, the same evidence machinery may classify it as a blocking provenance defect
under a new `CheckSpec`; v3.0 does not include that mode.

A `deny_changes` path rule can establish a violation without entity mapping: the prohibition
is on the path and the changed span is exact. A symbol rule cannot: a protected symbol that
cannot be mapped is unresolved scope and yields `INCONCLUSIVE`. A general rule requiring all
changes to map to an entity is not a `deny_changes` rule and cannot turn mapping failure into
`FAIL`.

---

## 10. Frontend and VFIR

### 10.1 Frontends

- Python: standard-library `ast`.
- TypeScript/JavaScript: tree-sitter with pinned grammar versions.

Both lower supported constructs into one Verified Function IR (VFIR). VFIR contains entities,
CFG, SSA values, guards, calls, returns, effects, exceptions, and capability annotations.

### 10.2 Capabilities

A frontend declares per-entity capabilities:

```text
entity_spans
signature
cfg
ssa
calls
effects
exceptions
types
taint
```

A check declares the capabilities it requires. Missing capabilities downgrade coverage and
produce explicit reason codes; they never silently skip analysis.

### 10.3 Supported subset and fidelity

Every supported construct must have:

- a frontend conformance test (source → expected VFIR facts);
- a differential-fidelity test against CPython or Node for trusted, controlled fixtures.

Differential tests run only in VerifyCI's isolated CI. They never execute arbitrary
repository code during PR verification. They compare return values, exceptions, evaluation
order, and modeled effects for constructs within the declared subset.

A fidelity mismatch invalidates the affected capability and prevents semantic release as
blocking. Runtime evidence cites the frontend version, capability set, and fidelity corpus
hash.

A parse error in a changed file produces `OPAQUE` with a reason code; it never crashes the
gate. Grounding may still establish provenance. Semantic, contract, and taint coverage for the
affected entity becomes `PARTIAL` or `UNKNOWN`.

Known assumptions are explicit:

- unknown decorators are opaque wrapper effects; if they can change argument binding or
  control flow, the function is `PARTIAL`;
- async scheduling and external concurrency are outside intraprocedural semantics;
- closures are supported only where capture and mutation are in the declared subset;
- Python and JS evaluation order is modeled only for supported expressions;
- dynamic imports, `eval`, proxies, and computed dispatch are `PARTIAL` or `OPAQUE`.

---

## 11. Blocking checks

### 11.1 Common rules

- `PASS` requires `COMPLETE` coverage.
- `FAIL` may coexist with `PARTIAL` or `UNKNOWN` coverage.
- `NOT_APPLICABLE` requires positive applicability evidence.
- No blocking finding without validated evidence of its declared kind.
- Budget exhaustion without a witness ⇒ `INCONCLUSIVE`; after a witness, the finding
  survives.
- Unsupported relevant language/capability ⇒ `UNKNOWN`, never `NOT_APPLICABLE`.
- Internal inconsistency or an execution fault, other than deterministic budget exhaustion
  or a watchdog interruption, ⇒ `ERROR`. An `ERROR` may carry validated findings; preserve
  them and apply aggregate precedence. The failure conditions below describe finding
  establishment; if the same check also faults, `ERROR` takes precedence and the finding is
  preserved per §6.2.
- Each check has a frozen corpus, per-defect thresholds, and replayable witness tests.
- A blocking check cannot enter the registry without a `CheckSpec` and passing corpus.

### 11.2 `grounding`

Defined in §9.2. It runs first, its result is retained, and it does not suppress other checks.

### 11.3 `deletion`

| Field | Definition |
|---|---|
| Declared defects | `DEL-REACHABLE-SYMBOL`: removed symbol remains reachable from an entrypoint, export, public API, or live reference. `DEL-DANGLING-REFERENCE`: head references a symbol with no definition. `DEL-DYNAMIC-REFERENCE`: a dynamic reference is proven to target a removed symbol. |
| Coverage limitation | An unresolved dynamic target is `dynamic_target_unresolved`, yielding `INCONCLUSIVE` when relevant. It is not a defect ID. |
| Relevant scope | Removed or renamed symbols at module, class, and export level; references from imports, `__all__`, barrel files, call sites, entrypoints, and tests. |
| Applicability evidence | At least one removed symbol in a non-excluded path. No removals ⇒ `NOT_APPLICABLE`; all removals excluded ⇒ `NOT_APPLICABLE` with path evidence. |
| Supported subset | Python and TS/JS symbol facts from bounded syntax-only parsing. Requires `symbols` and `references` capabilities. Other languages ⇒ `UNKNOWN` when removal is relevant. |
| Required witness | Symbol identity, base definition span, and a live reference path; or a head reference with no definition; or a dynamic dispatch site proven to resolve to the removed symbol. |
| Coverage | `COMPLETE` when every removed symbol and its reference closure is resolved. `PARTIAL` when dynamic dispatch exists in importing modules. `UNKNOWN` for unsupported language scope. |
| Failure conditions | Proven live reference, dangling reference, or proven dynamic reference ⇒ `FAIL`. Unresolved dynamic target alone ⇒ `INCONCLUSIVE`. Index inconsistency ⇒ `ERROR`. |
| Frozen corpus | Unused private symbol; used export; re-export through `__init__`/barrel; rename with all refs updated; rename with a missed ref; test-only reference; `__all__`; TS default export; deleted module; dynamic `getattr`; computed property; string dispatch; generated-path exclusion; multi-file package. |
| Oracle bar | Precision 1.0, recall ≥0.95 overall with per-defect thresholds, coverage agreement 1.0. Test references count as live by default. |

### 11.4 `contract`

| Field | Definition |
|---|---|
| Declared defects | `CTR-SIGNATURE-BREAK`: parameter, return, async, or visibility change incompatible with a resolved caller or declared public API. `CTR-EXPORT-BREAK`: removed/renamed export still imported or declared public. `CTR-CALL-INCOMPATIBLE`: changed call site disagrees with an unchanged callee. |
| Relevant scope | Changed, added, or removed exported/called symbols; repo-internal call sites; policy-declared public API. External consumers are an explicit excluded assumption unless declared public. |
| Applicability evidence | At least one signature, export, or call-site change in scope. Otherwise `NOT_APPLICABLE` with inspected scope. |
| Supported subset | Python and TS/JS declared signatures, arity, parameter kinds, defaults, keyword names, return annotations, export/visibility, async/sync. Lightweight type compatibility only. Requires `signature`, `calls`, `types`. |
| Required witness | Base/head signature diff plus a call site whose argument binding fails; or a head import with no matching export; or a public-API policy declaration with the breaking change. |
| Coverage | `COMPLETE` when all relevant callers are resolved and type facts are sufficient. `PARTIAL` on dynamic calls, `*args`/`**kwargs`, unresolved imports, computed properties, or unknown types. `UNKNOWN` for unsupported language scope. |
| Failure conditions | Proven incompatibility ⇒ `FAIL`. Unresolved relevant callers/types ⇒ `INCONCLUSIVE`. Internal inconsistency ⇒ `ERROR`. |
| Frozen corpus | Optional parameter addition; removed used parameter; positional reorder; keyword rename; default changes; positional-only parameters; overloads; TS union/structural types; `**kwargs`; dynamic import; public API break; async-to-sync change; caller-only break; external-only consumer. |
| Oracle bar | Precision 1.0, recall ≥0.95 overall with per-defect thresholds, coverage agreement 1.0. Every blocking finding cites a concrete call site or public-API policy. |

### 11.5 `semantic`

| Field | Definition |
|---|---|
| Declared defects | `SEM-GUARD-REMOVED`: protected guard removed while its protected effect remains reachable. `SEM-GUARD-WEAKENED`: boundary relaxed so the effect becomes reachable for previously rejected inputs. `SEM-GUARD-INVERTED`: polarity reverses, changing which branch protects the effect. `SEM-BINDING-SWAP`: call arguments or returned tuple elements swapped while the callee/return contract is unchanged. `SEM-EXCEPTION-REMOVED`: policy-protected error path removed while its trigger remains reachable. |
| Relevant scope | Modified functions with body changes; direct callees needed to model calls; direct callers needed to judge return swaps. Added and removed entities are out of scope. |
| Applicability evidence | At least one modified entity whose normalized body digest changed. No body change, or comment/whitespace-only change ⇒ `NOT_APPLICABLE` with digest evidence. |
| Supported subset | Python and TS/JS structured control flow, assignments, direct calls, returns, raises/throws, try/except, boolean/comparison expressions, simple containers. Requires `cfg`, `ssa`, `calls`, `exceptions`, `types`. Unknown decorators are assumptions; dynamic calls, proxies, `eval`, computed property calls, unresolved closures ⇒ `PARTIAL`. |
| Method | Candidate detection from VFIR diff → bounded symbolic path formulas → deterministic Z3 `rlimit` → model → VFIR replay → finding only if replay confirms divergence. Solver `UNKNOWN` is not a defect. |
| Required witness | Concrete input/state, base path, head path, and observable divergence. Evidence includes solver result, replay result, frontend fidelity corpus hash, and `witness_level: ir`. |
| Coverage | `COMPLETE` when every modified entity has required capabilities, candidate discovery is complete for the declared patterns, and every candidate is proven or refuted. `PARTIAL` when any relevant entity is partial/opaque or any candidate is `UNKNOWN`. `UNKNOWN` for unsupported language scope. |
| Failure conditions | SAT + successful replay + fidelity coverage ⇒ `FAIL`. UNSAT ⇒ no defect for that candidate. `UNKNOWN`, unsupported construct, or budget exhaustion without witness ⇒ `INCONCLUSIVE`. Replay mismatch or evaluator inconsistency ⇒ `ERROR`. |
| Frozen corpus | Protected guard removed with sink reachable; guard and effect moved; guard strengthened; guard inverted; boundary weakened/strengthened; dead guard removal (UNSAT); argument swap with unchanged callee; swap with callee also swapped; return swap with caller adapted; return swap in public API; protected exception removed; equivalent refactor; decorator opacity; dynamic call; nested guards; short-circuit; try/except; async; solver `UNKNOWN`; budget exhaustion. |
| Oracle bar | Precision 1.0 on blocking findings, recall ≥0.95 overall with per-defect thresholds, witness replay 1.0, coverage agreement 1.0. |

The semantic check does not claim general equivalence. It claims a declared regression
pattern was disproved, proven with a replayable IR-level witness, or left unresolved.

### 11.6 `security`

| Field | Definition |
|---|---|
| Declared defects | `SEC-SECRET`: validated credential material introduced in changed text. `SEC-SECRET-TO-SINK`: validated secret flows to a log, network, serialization, or persistence sink. `SEC-TAINT-TO-SINK`: untrusted input reaches a policy-defined dangerous sink. `SEC-DANGEROUS-CALL`: exact policy-forbidden call introduced. |
| Sub-analyses | Secrets, taint, dangerous calls. Each has its own `CheckResult` record with independent outcome, coverage, findings, diagnostics, and applicability. Secret scanning applies to every changed textual file. |
| Relevant scope | Changed lines, enclosing entities, forward taint closure to sinks, and direct caller/callee summaries needed to connect sources and sinks. |
| Applicability evidence | Secret scan: every changed text file. If at least one changed text file exists, a clean complete scan is `PASS`; if no changed text exists, the secret sub-analysis is `NOT_APPLICABLE` with evidence. Taint: may be `NOT_APPLICABLE` only when no relevant constructs exist and this is positively established. Dangerous calls: candidates from changed lines. |
| Supported subset | Python and TS/JS taint through assignments, arguments, returns, string/template construction, simple containers, and common stdlib sinks. Secret scanning is language-independent. Requires `taint`, `calls`, `types` for taint. Dynamic dispatch, reflection, `eval`, encoded blobs, or unknown calls on a relevant path ⇒ `PARTIAL`. Other languages ⇒ `UNKNOWN` for taint; text secrets still scan. |
| Required witness | Exact source/sink spans; redacted secret with pattern/entropy evidence; taint path with per-edge justification; policy rule ID. Dangerous call: exact span and resolved callee. |
| Coverage | `COMPLETE` when changed text is fully scanned and taint candidates are resolved. `PARTIAL` for unknown calls on relevant paths, dynamic dispatch, unresolved aliases, or unclassifiable encoded content. `UNKNOWN` for unsupported taint language scope. |
| Failure conditions | Validated secret, resolved taint path, or exact forbidden call ⇒ `FAIL`. Ambiguous encoded secret or unresolved relevant taint path ⇒ `INCONCLUSIVE`. Unknown call ⇒ `INCONCLUSIVE` only when it can affect a relevant source-to-sink path. Internal scanner fault ⇒ `ERROR`. |
| Candidate dropping | An ambiguous candidate cannot be dropped merely because it is hard to classify. Dropping requires positive evidence that it is outside the declared defect set or a supported benign case. |
| Frozen corpus | Provider keys, private keys, JWTs, generic high entropy, base64/hex, placeholders, environment references, test fixtures, allowlisted paths; request→SQL/log/subprocess/file; parameterized query (PASS); sanitizer (PASS); cross-file taint; TS `innerHTML`/`child_process`; dynamic alias; unknown call; budget exhaustion. |
| Oracle bar | Precision 1.0 on blocking findings, recall ≥0.95 overall with per-defect thresholds, coverage agreement 1.0, redaction 1.0. Allowlists are authoritative only from target-base policy. |

Security sub-result aggregation: each sub-analysis has its own outcome, coverage, findings,
and diagnostics. The top-level outcome is the highest-precedence sub-outcome using
`ERROR > FAIL > INCONCLUSIVE > PASS > NOT_APPLICABLE`. The top-level `findings[]` contains
every sub-analysis finding exactly once, keyed by the canonical finding identity used for
waiver fingerprints; the sub-results retain the same findings for attribution, so no finding
is discarded. The top-level `diagnostics[]`, `reason_codes[]`, and `evaluated_scope` include
the sub-analysis values and any aggregation-added entries. If one sub-analysis establishes a
defect and another encounters an internal error, the top-level outcome is `ERROR` and the
validated finding remains present in both the sub-result and the top-level findings; the
aggregate verdict is `ERROR`. An invalid sub-result (for example, `PASS` with `PARTIAL`
coverage or `FAIL` without a finding) is treated as `ERROR` (`invalid_check_result`).
Top-level coverage is the weakest coverage among applicable
sub-analyses (`UNKNOWN` weaker than `PARTIAL`, `PARTIAL` weaker than `COMPLETE`); if no
sub-analysis is applicable, coverage is `COMPLETE` for the not-applicable decision.

### 11.7 Advisory tier

The schema and registry support advisory checks, but v3.0 ships none. Concurrency, complexity,
and coverage heuristics are deferred until the five blocking checks pass their corpora. This
keeps the first release's trust claim narrow and testable.

### 11.8 Registry gate

A blocking check cannot be registered unless its `CheckSpec` includes:

```text
id, version, corpus_id, corpus_hash,
precision_threshold, recall_threshold,
per_defect_thresholds,
coverage_threshold, witness_replay_threshold,
required_capabilities, toolchain_fingerprint
```

CI verifies the corpus hash, thresholds, and toolchain fingerprint on every release run. A
behavior change without a corpus update is a release failure.

---

## 12. Repository layout and ownership

```text
verifyci/
  contracts/
    model.py              # DiffModel, ChangedScope, CheckResult, Finding, Verdict, Bundle
    reason_codes.py       # closed reason-code catalog
    manifest.py           # CheckSpec, corpus/toolchain fingerprints
  scm/
    git.py                # sole Git authority; commit-pinned object API
  scope/
    classify.py           # path classes, language detection
    entities.py           # hunk→entity mapping, deny_changes matching support
  frontend/
    protocol.py           # LanguageFrontend, EntitySpan, FileFacts, capabilities
    vfir.py               # normalized IR
    python_frontend.py    # stdlib ast → VFIR
    ts_frontend.py        # tree-sitter TS/JS → VFIR
    fidelity.py           # supported-construct matrix, conformance hooks
  index/
    provider.py           # FactProvider: demand resolution, Git reads, cache validation
    symbol_index.py       # symbol indexing and reverse lookups only
    facts.py              # definitions/imports/exports/call sites
    cache.py              # CAS storage, sharding, integrity validation
  analysis/
    cfg.py  ssa.py  guards.py  effects.py  taint.py  summaries.py
  checks/
    base.py  registry.py
    grounding.py  deletion.py  contract.py  semantic.py  security.py
  gate/
    orchestrator.py       # all checks run; no short-circuit
    verdict.py            # aggregation, waivers
    policy.py             # TOML schema, base binding, PR policy-change detection
  evidence/
    canonical.py  sarif.py  writer.py
  runtime/
    budget.py  scheduler.py  diagnostics.py
  cli.py

tests/
  unit/  contracts/  invariants/
  frontend/conformance/
  frontend/differential/          # trusted CPython and Node fixtures
  corpora/
    grounding/ deletion/ contract/ semantic/ security/
  adversarial/
  performance/
  e2e/
```

Dependency direction (acyclic):

```text
cli       → gate, evidence
gate      → scm, scope, checks, evidence, contracts
checks    → contracts, scope, index, analysis
scope     → index, frontend, contracts
index     → scm, frontend, analysis, contracts, index.cache
analysis  → frontend, contracts
frontend  → contracts
scm       → contracts
evidence  → contracts
```

`contracts/` owns every shared record. `checks/base.py` owns only the protocol. No check
imports `scm`, `cli`, or `evidence`; FactProvider is the only path from checks to Git-backed
facts. No frontend imports `checks`. Analysis modules are pure over VFIR and supplied
summaries; they do not request facts. No module imports `runtime` for semantics; budgets are
injected.

Dependencies: Python 3.12 stdlib, `tree-sitter`, pinned `tree-sitter-typescript` and
`tree-sitter-javascript`, and `z3-solver`. No other runtime dependency is required for the
blocking path.

---

## 13. Execution, budgets, and determinism

### 13.1 Execution model

- v3.0 runs checks sequentially in fixed registry order.
- File-fact computation may use a bounded worker pool. Worker count is a performance
  parameter, never a semantic input.
- Facts are requested through `FactProvider`; checks receive facts only.
- Z3 is imported lazily and only when a semantic candidate exists.
- The gate never accesses the network or executes repository code.
- Default deadlines: 60 seconds cold, 10 seconds warm, on the reference workload.

### 13.2 Budgets

Budgets are deterministic operation counts, not wall-clock allowances:

- maximum entities and references per check;
- maximum symbolic paths per function;
- maximum taint iterations and depth;
- maximum solver `rlimit`;
- maximum facts per check.

Budgets are assigned per check and per relevant scope before execution. Checks cannot consume
each other's budget. No shared mutable semantic state exists between checks. The fact cache is
shared immutable storage, not shared semantic state; entries are validated before use and
cannot influence coverage or verdict logic.

A wall-clock watchdog is an operational safeguard. If it fires:

- an existing validated finding remains `FAIL`;
- otherwise the affected check is `INCONCLUSIVE` (`watchdog_interrupted`);
- the affected check's coverage is `PARTIAL` or `UNKNOWN`;
- it never creates `PASS` and never creates a defect.

Solver random seeds and configuration are pinned and included in the toolchain fingerprint.
Scheduler reduction order is stable regardless of completion order.

### 13.3 Determinism scope

> Identical logical inputs, policy, toolchain, and deterministic analysis budgets produce
> byte-identical canonical payloads for completed executions. Resource exhaustion may produce
> INCONCLUSIVE and must never produce PASS.

Caching must not change the result of a completed execution under the same deterministic
budgets. A watchdog-triggered execution may differ because execution completeness differs;
that is an operational interruption, not a cache effect. A cached run must never produce
PASS merely because it finished faster and avoided a watchdog.

---

## 14. Cache model and trust boundary

### 14.1 Location

The default cache lives in the repository's administrative directory:

```text
<git-common-dir>/verifyci-cache/v3/
```

or a dedicated local cache directory outside the working tree. It is never stored in a
tracked or PR-controlled path. An explicit `--cache-dir` that resolves inside the working
tree is rejected with `ERROR` (`invalid_cache_location`).

### 14.2 Entries and validation

- Entries are immutable, sharded, and written atomically (temporary file + rename).
- Keys include content hashes, language/frontend identity, repository-relative path or module
  identity where facts depend on it, and parser/frontend/analyzer/solver versions.
- Policy hash is included where policy affects the result.
- Each entry carries a content digest and toolchain fingerprint.
- Malformed, stale, mismatched, or unverifiable entries are cache misses.
- Cached objects: entity spans, file symbol facts, VFIR, effect/taint summaries, solver
  results. The aggregate verdict is never cached.
- Facts are derived from Git blobs, never the working tree.
- A cache miss falls back to authoritative Git bytes.

Content-addressed naming alone does not prove correctness. The cache is a local acceleration
layer within a defined trust domain: the local host and CI workflows authorized for the
repository. Entries are not signed; authenticity derives from that domain and from validation
of structure, input digests, and toolchain fingerprint. An entry from outside the trust domain
is ignored. The cache cannot override coverage, budgets, policy, or verdict logic.

### 14.3 GitHub Actions cache rules

- Restore caches only from trusted branches or trusted workflow runs.
- Do not restore a cache produced by an untrusted fork or `pull_request_target` workflow into
  a privileged workflow.
- Treat cache artifacts as repository-confidential; scope them to the repository's trusted CI
  workflows and branches.
- Use keys that include the toolchain fingerprint and policy hash.
- Treat any cache artifact as untrusted input: validate structure, digests, and fingerprints;
  fall back to Git on any mismatch.
- Local cache directories are created with user-only permissions.

### 14.4 Cache parity

Release validation requires cached and uncached executions to produce identical verdicts and
canonical payloads when both complete under the same deterministic budgets. Watchdog behavior
is tested separately and is not part of the parity claim.

---

## 15. Testing and release validation

### 15.1 Contract tests

Frozen models, reason codes, canonical serialization, verdict algebra, coverage invariants,
finding preservation under `ERROR`, waiver matching, target-base policy binding, PR
policy-change detection, `deny_changes`, manifest verification, and cache-location rejection.

### 15.2 Frontend conformance

Every construct in the supported capability matrix has a source→VFIR golden test. A construct
cannot be marked supported without one.

### 15.3 Frontend differential fidelity

Supported Python programs run under CPython and the VFIR evaluator; TS/JS programs run under
Node and the VFIR evaluator. Tests use trusted, controlled fixtures in VerifyCI's isolated CI,
never arbitrary repository code during PR verification. They compare return values,
exceptions, evaluation order, and modeled effects within the declared subset. A mismatch
invalidates the affected capability and blocks semantic release.

### 15.4 Check corpora

Each check owns a frozen corpus of small bare Git repositories with hand-authored labels for
outcome, coverage, reason codes, and findings. Labels are authored from this specification,
never generated by the engine.

Release thresholds per check:

- blocking precision **1.0** (zero false blocking findings);
- recall **≥0.95 overall** and per-defect-ID floors;
- coverage classification agreement **1.0**;
- witness replay **1.0** for every blocking finding, including one preserved under `ERROR`;
- deterministic payload across repeated runs and worker counts;
- secret redaction **1.0**.

### 15.5 Invariant suite

No PASS with incomplete coverage; a finding survives later exhaustion; `ERROR` precedence; a
finding survives a later check error and remains in the bundle; waivers preserve findings;
target-base policy authority; target-branch advancement alone never triggers policy review;
PR policy changes are detected from merge-base..head; head policy cannot silence its PR; no
working-tree reads; no network; cache corruption falls back; manifest mismatch fails closed;
every registered check has a result.

### 15.6 Adversarial suite

Tampered Git objects, ambiguous merge bases, binary/Unicode/CRLF files, entity-boundary hunks,
dynamic dispatch, decorators, async, closures, encoded secrets, solver `UNKNOWN`, watchdog
firing, check fault after a witness, target-branch policy advancement, protected-path and
protected-symbol `deny_changes`, malformed policy, path traversal, giant functions, cache
poisoning, and PR-controlled cache paths.

### 15.7 Performance suite

Synthetic 100k LOC reference repository, cold and warm; p95 gate latency; per-check budget
adherence; memory ceiling. Run on a dedicated CI job. Performance targets are proven, not
assumed; a design target in this document is not a measurement.

### 15.8 End-to-end

GitHub Action on fixture PRs; exit codes; SARIF validation; evidence reproducibility;
PR-authored policy-change review; target-advancement no-review; waiver expiry; cache parity.

### 15.9 Release validation versus runtime validation

Frozen corpora, fidelity suites, and threshold checks run in VerifyCI's own CI whenever a
check, its corpus, the relevant toolchain, or supported semantics change. Ordinary
verification of a user repository validates the approved `CheckSpec` manifest and toolchain
fingerprint; it does not replay the entire oracle corpus on every PR. This separation
protects the warm-gate latency target.

---

## 16. Build order and release enforcement

| Milestone | Scope | Exit criteria |
|---|---|---|
| **M0 Foundations** | Contracts, canonical evidence, policy schema, base binding, PR policy-change detection, Git adapter, CLI skeleton, manifest, delete v1/v2 packages | Contract and invariant tests green; no legacy imports |
| **M1 Grounding** | Python/TS entity spans, hunk mapping, provenance, `deny_changes` path/symbol constraints | Grounding corpus: precision 1.0, coverage 1.0, integrity cases `ERROR` |
| **M2 Deletion** | Symbol facts, reference index, entrypoints/exports, dynamic dispatch | Deletion corpus thresholds; unresolved dynamics `INCONCLUSIVE` |
| **M3 Contract** | Signatures, exports, call-site compatibility, public API policy | Contract corpus thresholds; no unresolved caller silently passes |
| **M4 Security** | Secret scanner, dangerous-call policy, taint summaries and paths | Security corpus thresholds; redaction 1.0; clean scans `PASS` |
| **M5 Semantic** | VFIR, CFG/SSA/guards, candidate detection, Z3 witness, replay, frontend fidelity | Semantic corpus thresholds; fidelity matrix complete; every semantic blocking finding has three-part evidence |
| **M6 Release** | CAS, 100k LOC benchmark, Action, SARIF, docs, manifest publication | All release gates; p95 ≤10s warm, ≤60s cold; full invariant suite |

Development versus release:

- Internal development builds may exercise individual checks and corpora for diagnostics.
- No internal build may advertise a complete v3 gate or emit a normal `PASS` while required
  blocking checks remain unvalidated. Unvalidated checks yield aggregate `ERROR`
  (`check_not_validated`).
- A release manifest is published only after all five checks satisfy their corpus thresholds,
  frontend and toolchain contracts are approved, and all invariants and performance gates pass.
- Any change to a check, its corpus, the relevant toolchain, or supported semantics
  invalidates the applicable release approval until release validation completes again.

---

## 17. Migration and deletion

- Delete the legacy v1 and v2 package trees (the existing `verifyci/` v1 tree and
  `verifyci_v2/`) before introducing the v3 `verifyci/` package. The v3 package must not
  import or wrap legacy code. Git history preserves the old code; frozen evidence tags and
  artifacts remain untouched.
- Salvage only labeled corpora, witness fixtures, and proven test oracles after auditing them
  against this specification. Do not carry over harnesses that generate their own labels.
- No compatibility shims, aliases, dual CLI surfaces, or legacy import paths.
- Replace v1/v2 architecture documentation with this specification. Historical documents may
  remain only when clearly marked as superseded.

---

## 18. Acceptance criteria for v3.0

VerifyCI v3.0 is not complete until all of the following are established by artifacts:

- [ ] All five blocking checks are registered with immutable `CheckSpec` records.
- [ ] Every check passes its frozen corpus precision, recall, per-defect, coverage, and
      witness-replay thresholds.
- [ ] Frontend conformance and differential-fidelity suites pass for every supported
      construct used by semantic evidence.
- [ ] Invariant and adversarial suites pass, including fail-closed, cache, policy, and
      manifest cases.
- [ ] A finding preserved under a later check error remains visible and aggregates `ERROR`.
- [ ] Policy-change review triggers only for PR-authored changes; target-branch advancement
      alone does not trigger review.
- [ ] `deny_changes` path and symbol rules are defined, evaluated by grounding, and
      corpus-validated.
- [ ] Cached and uncached completed runs produce identical canonical payloads.
- [ ] Cold and warm latency targets are measured on the reference workload, not assumed.
- [ ] Every blocking finding, including one preserved under `ERROR`, contains validated
      evidence of its declared kind.
- [ ] Every bundle contains a record for every registered blocking check.
- [ ] The GitHub Action produces correct exit codes and valid SARIF.
- [ ] The gate performs no network access and executes no repository code.
- [ ] The release manifest and toolchain fingerprint are published and verified.
- [ ] v1/v2 packages are removed, with frozen evidence tags and artifacts untouched.

---

## Appendix A — Initial reason-code catalog

The catalog is closed; new codes require a specification update and manifest version change.

```text
provenance_integrity_error
mapping_unresolved
policy_prohibited
ambiguous_merge_base
invalid_policy
policy_change_review
waiver_review
invalid_cache_location
manifest_mismatch
check_not_validated
not_executed
invalid_check_result

symbol_live
dangling_reference
dynamic_target_unresolved

signature_break
export_break
call_incompatible

solver_unknown
witness_replay_mismatch
frontend_capability_missing
budget_exhausted
watchdog_interrupted

secret_candidate_ambiguous
taint_path_unresolved
unknown_call_on_path
dangerous_call

candidate_dropped_benign
candidate_outside_defect_set
```

---

## Appendix B — Policy example

```toml
[gate]
cold_deadline_seconds = 60
warm_deadline_seconds = 10

[paths]
generated = ["**/generated/**"]
vendored = ["vendor/**"]
tests = ["tests/**"]

[entrypoints]
symbols = ["app.main.main"]
globs = ["src/api/**"]

[public_api]
symbols = ["mypkg.api.*"]

[deny_changes.protected_core]
paths = ["src/core/**"]
symbols = ["app.auth.require_user"]
reason = "Protected change surface; requires security review"

[protected_guards]
calls = ["auth.require_user", "auth.check_permission"]
sinks = ["db.write", "http.request", "logging.*", "subprocess.*"]

[secrets]
allowlist_paths = ["tests/fixtures/**"]
placeholder_patterns = ["example", "dummy", "redacted"]

[waivers.VC-2026-001]
check = "semantic"
defect_id = "SEM-GUARD-REMOVED"
fingerprint = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
reason = "Temporary migration: legacy endpoint protected by upstream gateway"
approved_by = "security-team"
expires = "2026-12-31"
```

Waivers are valid only when loaded from the target-base policy. A waiver added in the PR is a
policy change and cannot neutralize that PR's findings. `deny_changes` entries are evaluated
by the grounding check; path rules do not depend on entity mapping, while symbol rules require
an exact mapped entity.

---

## Appendix C — Evidence bundle shape

The following illustrates field placement for one check, not a real run. A real payload
contains one `CheckResult` for every registered blocking check and one `CheckSpec` for every
registered check.

```json
{
  "schema": "verifyci.evidence/v3",
  "tool": {
    "name": "verifyci",
    "version": "3.0.0",
    "toolchain_fingerprint": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
  },
  "inputs": {
    "target_base_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "merge_base_commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "head_commit": "cccccccccccccccccccccccccccccccccccccccc",
    "policy": {
      "authoritative_blob_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
      "pr_changed": false,
      "proposed_blob_hash": null
    }
  },
  "manifest": {
    "manifest_hash": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
    "check_specs": [
      {
        "id": "grounding",
        "version": 1,
        "tier": "blocking",
        "corpus_hash": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        "precision_threshold": 1.0,
        "recall_threshold": 1.0,
        "per_defect_thresholds": {"GRD-UNGROUNDED-EDIT": 1.0},
        "coverage_threshold": 1.0,
        "required_capabilities": ["entity_spans"]
      }
    ]
  },
  "scope": {},
  "check_results": [
    {
      "check_id": "grounding",
      "check_version": 1,
      "tier": "blocking",
      "outcome": "PASS",
      "coverage": "COMPLETE",
      "evaluated_scope": {},
      "scope_enumeration": {"method": "entity-spans", "version": 1, "complete": true},
      "candidate_discovery": {"method": "hunk-mapping", "version": 1, "complete": true},
      "applicability_evidence": {},
      "method": "git-blob-provenance",
      "method_version": 1,
      "reason_codes": [],
      "findings": [],
      "diagnostics": [],
      "sub_results": []
    }
  ],
  "findings": [],
  "waivers": [],
  "verdict": {
    "status": "PASS",
    "exit_code": 0,
    "reason_codes": []
  },
  "assumptions": [],
  "excluded_scope": []
}
```

The envelope carries `payload_hash`, timestamp, timings, environment, cache statistics, and an
optional signature. Only the payload is canonical and reproducible.
