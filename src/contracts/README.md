# Contracts

Frozen schemas. Logic lives elsewhere.

## Frozen

`entity`, `edge`, `event`, `revision`, `graph_schema`, `canonical`,
`identity`, `evidence`, `verification_ir`, `task_ir`, `memory_types`,
`embedding`, `vector_store`, `tool`, `scheduler`, `retriever`,
`code_intel`, `config`, `provenance` — breaking changes require a contract notice.

Cross-boundary types: `Constraint`, `Budget`, `SourceChunk`,
`ProvenanceEntry`, `ExecutableDAG`, `TaskStatus`, `ProjectionState`,
`NodeResult` — defined alongside the frozen schemas above.

## V1 corrections (frozen plan amendments)
- `identity.compute_logical_entity_id` takes an optional parent `scope`
  (default `""`). A method `login` on class `AuthService` must hash
  differently from a top-level function `login`; the frozen four-argument
  form could not distinguish them. Calls without `scope` hash exactly as
  before, so existing golden vectors still hold.
- `verification_ir.CheckResult` gains `deterministic: bool = True`.
  LLM-opinion checks set it `False` so the policy ignores them; all
  built-in checkers are deterministic.
- `InvariantMetrics.detection_recall/detection_precision` are only defined
  against a labeled ground-truth set (`score_labeled`); without labels both
  report 0.0 ("unmeasured").

## Set-membership principle

Any time policy depends on "is X in set S", S must have exactly one
definitional home, or the branches drift. Two instances so far:

- Revision identity: valid-time (`get_entity_as_of`), latest-live
  (`get_current_entity`), and by-name lookup each ask "which version" —
  separate methods, independent tests, no shared WHERE clause.
- Ingestible extensions: ingest collection, diff grounding, and benchmark
  collection all read `INGESTIBLE_EXTENSIONS` from `ingestion/language.py`.
  A file type added in one place and not another used to flip whole diffs
  from PASS to INCONCLUSIVE silently.

## Not Frozen

`BDDSpec`, `NFR`, `Diff`, `CodeGraph`, `ExecutionContext` — transient,
single-module, don't cross the frozen boundary. May change without notice.
