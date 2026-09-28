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

## Not Frozen

`BDDSpec`, `NFR`, `Diff`, `CodeGraph`, `ExecutionContext` — transient,
single-module, don't cross the frozen boundary. May change without notice.
