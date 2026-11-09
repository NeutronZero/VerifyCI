# Architecture

VerifyCI reads Git objects directly and evaluates a fixed set of deterministic
checks over the diff between a merge base and a head commit. There is no server,
database, model call, or network access on the gate path.

---

## Pipeline

```text
vc gate --base R --head H
        │
        ▼
cli.py ──────────────► gate/orchestrator.run_gate
                         │
        ┌────────────────┼───────────────────────────────┐
        ▼                ▼                               ▼
  scm/git.py      gate/policy.py                  gate/integrity.py
  resolve base,   target-base policy              policy/CODEOWNERS/
  merge base,     (authoritative)                 workflow-change review
  head, blobs,    parse + validate
  diff entries
        │
        ▼
  scope/entities.py  ──►  SourceFacts + ChangedScope
  tree-sitter parse,      (entities, imports, calls,
  hunk→entity mapping      name loads, unmapped hunks)
        │
        ▼
  checks/  (deterministic batch, per-check deadline & budget)
   ├─ grounding   deny_changes + hunk grounding
   ├─ deletion    removed live symbols, dangling/dynamic refs
   ├─ contract    signature/export/call compatibility
   ├─ semantic    CFG + Z3 divergence + concrete replay
   └─ security    secrets, taint-to-sink, dangerous calls
        │
        ▼
  gate/verdict.py   waivers → coverage acceptances → aggregation
        │
        ▼
  evidence/bundle.py  canonical payload + envelope (payload_hash)
        │
        ├─► evidence/sarif.py  (SARIF 2.1.0 projection)
        └─► cli output (text | json | sarif)
```

---

## Trust boundaries

1. **Target-base policy authority.** The policy that judges a PR comes from the
   base revision (or the reviewed proposal when no base policy exists). A PR
   that edits `.verifyci/`, CODEOWNERS, or workflows raises
   `policy_change_review` / `gate_integrity_review`; it cannot change its own
   authority silently.
2. **Frozen manifest.** `contracts/manifest.py` publishes the check registry,
   tool version, and manifest hash. A mismatch is `manifest_mismatch` (ERROR).
3. **Release-validation evidence.** `contracts/release_validation.py` verifies
   signed, non-stale evidence for *this build*. Absent or stale evidence is
   `check_not_validated` (ERROR) — a reviewed repository cannot supply evidence
   for a different build.
4. **Evaluation replay.** `checks/semantic.py` never trusts the solver alone: a
   SAT witness is replayed in a subprocess (`sys.executable -I`, minimal
   environment) or Node (`--experimental-strip-types`, minimal environment).
   Unconfirmed witnesses are `semantic_alignment_unresolved`, never FAIL.
5. **Worker IPC.** `verifyci_release_trust/ipc.py` treats worker output as
   hostile input: strict UTF-8, duplicate-key rejection, depth/size limits,
   schema allowlists, and exit-code/outcome consistency (`0..4`).
6. **Cache.** Fact caching is content-addressed and binds repository identity,
   key id, toolchain, and schema version. Authenticated mode requires an HMAC
   key; sampled recomputation detects divergence (`cache_integrity_mismatch`).

---

## Evidence model

Every check returns a `CheckResult` with:

- `outcome` (`PASS`, `FAIL`, `NOT_APPLICABLE`, `INCONCLUSIVE`, `ERROR`)
- `coverage` and effective coverage (`COMPLETE`, `PARTIAL`, `UNKNOWN`)
- `evaluated_scope`, `scope_enumeration`, `candidate_discovery`,
  `applicability_evidence`
- `coverage_gaps[]` (reason code + subject, optional acceptance id)
- `findings[]` (fingerprint, evidence, premises, disposition)

The bundle adds inputs (commits, blobs, files), the authoritative policy hash,
the manifest, gate-integrity status, waivers, accepted gaps, diagnostics, and
the verdict. The envelope's `payload_hash` makes a run reproducible.

---

## Determinism and budgets

- No wall-clock or environment value reaches the verdict except the explicit
  `--as-of` date, which governs waiver/acceptance validity.
- `runtime/budget.py` bounds entities, references, taint depth/iterations,
  solver rlimit, blob size, AST depth, and node count. Exceeding a budget is
  always a gap (`budget_exhausted`) and therefore INCONCLUSIVE.
- Checks run in a deterministic batch (`runtime/scheduler.py`); `--jobs` only
  changes scheduling, not output.

---

## Public interfaces

- CLI: `vc gate` (see [quickstart](quickstart.md))
- Composite Action: [`action.yml`](../action.yml)
- Evidence bundle JSON and SARIF 2.1.0
- Python package: `verifyci.contracts` (frozen types), `verifyci.gate` (engine)

Stability guarantees are in [STABILITY.md](../STABILITY.md).
