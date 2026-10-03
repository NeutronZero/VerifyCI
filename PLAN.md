# VerifyCI — Final Detailed Plan (V1 Walking Skeleton)

## Product Identity

**Name:** VerifyCI
**Tagline:** Every agent action verified before human review.
**Wedge:** Verification as a first-class agent primitive — graph-grounded, invariant-aware gating.

> **LLMs may propose. Graphs provide context. Tools produce facts. Deterministic checks establish invariants. The verification policy decides whether an action passes.**

**Positioning:** Gartner's 2026 Magic Quadrant for Enterprise AI Coding Agents defines the category around "multistep planning, execution, and verification." Forrester's 2026 ADP Landscape confirms differentiation is shifting from code generation to orchestration, governance, and enterprise context. VerifyCI is designed around a verification-first architecture in which project-specific invariants, graph impact, and provenance become explicit gates in agent execution.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  INTERFACE (MCP / CLI / HTTP)                               │
│  code.search · code.definition · graph.query                │
│  verify.diff · task.run                                      │
├─────────────────────────────────────────────────────────────┤
│  VERIFICATION LAYER (V1: minimum loop)                      │
│  semi_formal_reason · blast_radius · intent_align          │
│  VerificationReport → PolicyEvaluator → Decision            │
├─────────────────────────────────────────────────────────────┤
│  ORCHESTRATION                                              │
│  Planner → TaskIR(+IntentPackage) → Compiler → DAG          │
│  AsyncDAGScheduler → Executor                               │
│  Every node: pre_commit_hook → verify.diff                  │
├─────────────────────────────────────────────────────────────┤
│  CONTEXT ENGINE                                             │
│  Dense + BM25 + Graph → RRF → Cross-encoder → EvidencePack  │
├─────────────────────────────────────────────────────────────┤
│  KNOWLEDGE + MEMORY                                         │
│  Bitemporal AST-Derived CPG (anchor+delta)                 │
│  Event Ledger (hash-chained, SHA-256)                       │
│  Projections → Replay                                       │
├─────────────────────────────────────────────────────────────┤
│  CODE INTELLIGENCE                                          │
│  Tree-sitter incremental → CPG builder → rustworkx          │
│  SBOM extraction + local vulnerability cache (offline)      │
├─────────────────────────────────────────────────────────────┤
│  STORAGE                                                    │
│  SQLite(events, metadata) · rustworkx(graph) · VectorStore  │
├─────────────────────────────────────────────────────────────┤
│  LOCAL AI                                                   │
│  Ollama · Embeddings · Cross-encoder                        │
├─────────────────────────────────────────────────────────────┤
│  OBSERVABILITY                                              │
│  OpenTelemetry GenAI semconv (compat layer)                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 0 — Contracts (Days 1-3)

### Goal
Freeze all schemas. No code without a contract.

### Day 1: Core Entity Schemas

```
verifyci/contracts/
├── entity.py
├── edge.py
├── event.py
├── revision.py
├── graph_schema.py
├── canonical.py
├── identity.py
└── provenance.py
```

**`identity.py`:**
```python
import hashlib

def compute_logical_entity_id(
    repository_id: str, file_path: str, name: str, type: EntityType,
    scope: str = "",
) -> str:
    """
    Stable across revisions. Scope is the dotted parent scope (methods
    need it: a method `login` on `AuthService` must hash differently
    from a top-level `login`; added as a V1 correction, see
    contracts/README.md). A rename or move yields a new logical identity.
    Rename detection is deferred to V1.2. Do not add heuristics before then.
    """
    payload = f"{repository_id}\x1f{file_path}\x1f{scope}\x1f{name}\x1f{type.value}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def compute_revision_entity_id(logical_entity_id: str, revision_id: str) -> str:
    payload = f"{logical_entity_id}\x1f{revision_id}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
```

**`entity.py`:**
```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

class EntityType(Enum):
    MODULE = "MODULE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    METHOD = "METHOD"
    PARAMETER = "PARAMETER"
    VARIABLE = "VARIABLE"
    TYPE = "TYPE"
    IMPORT = "IMPORT"

class GraphType(Enum):
    AST_DERIVED_CPG = "ast_derived_cpg"
    FULL_CPG = "full_cpg"

@dataclass(frozen=True)
class Entity:
    """
    Temporal fields:
    - valid_from / valid_until:   VALID TIME — when the fact was true in the code.
    - t_created / t_expired:      TRANSACTION TIME — when the platform recorded
                                  or retracted the fact.
    Bitemporal model (Graphiti convention). Both pairs required. Do not merge.
    """
    repository_id: str        # source of logical identity
    logical_entity_id: str    # hash(repository_id, file_path, name, type)
    revision_entity_id: str   # hash(logical_entity_id, revision_id)
    type: EntityType
    name: str
    file_path: str
    line_start: int
    line_end: int
    language: str
    source_hash: str
    revision_id: str
    valid_from: Optional[float] = None
    valid_until: Optional[float] = None
    t_created: Optional[float] = None
    t_expired: Optional[float] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    properties_json: Optional[str] = None

    def provenance_chain(self) -> list[str]:
        return [
            self.source_hash,
            self.revision_id,
            self.file_path,
            f"{self.line_start}-{self.line_end}",
        ]
```

**`edge.py`:**
```python
class EdgeType(Enum):
    CONTAINS = "CONTAINS"
    CALLS = "CALLS"
    IMPORTS = "IMPORTS"
    INHERITS = "INHERITS"
    IMPLEMENTS = "IMPLEMENTS"
    REFERENCES = "REFERENCES"
    DEFINES = "DEFINES"
    USES = "USES"
    RETURNS = "RETURNS"
    DECORATES = "DECORATES"
    DOCUMENTS = "DOCUMENTS"
    DEPENDS_ON = "DEPENDS_ON"

class CPGEdgeSubtype(Enum):
    CONTAINS = "contains"
    HAS_NAME = "has_name"
    CALLS_DIRECT = "calls_direct"
    CALLS_INDIRECT = "calls_indirect"
    CALLS_RECURSIVE = "calls_recursive"
    IMPORTS = "imports"
    INHERITS = "inherits"
    REFERENCES = "references"
    CONTROLS = "controls"
    FLOWS_TO = "flows_to"
    SEQUENTIAL = "sequential"
    REACHES = "reaches"
    USES = "uses"
    DEFINES = "defines"

@dataclass(frozen=True)
class Edge:
    """
    Temporal fields:
    - valid_from / valid_until:   VALID TIME — when the fact was true in the code.
    - t_created / t_expired:      TRANSACTION TIME — when the platform recorded
                                  or retracted the fact.
    Bitemporal model (Graphiti convention). Both pairs required. Do not merge.
    """
    id: str
    src_entity_id: str
    dst_entity_id: str
    type: EdgeType
    subtype: Optional[CPGEdgeSubtype] = None
    valid_from: Optional[float] = None
    valid_until: Optional[float] = None
    observed_at: float = 0.0
    source_commit: Optional[str] = None
    t_created: Optional[float] = None
    t_expired: Optional[float] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    properties_json: Optional[str] = None
```

**`canonical.py`:**
```python
import hashlib
import json
from dataclasses import asdict

CANONICAL_EXCLUDED_FIELDS = {"attestation"}

def canonical_event_bytes(event) -> bytes:
    d = asdict(event)
    for field_name in CANONICAL_EXCLUDED_FIELDS:
        d.pop(field_name, None)
    return json.dumps(
        d,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

def event_hash(event) -> str:
    return hashlib.sha256(canonical_event_bytes(event)).hexdigest()
```

**`event.py`:**
```python
@dataclass(frozen=True)
class AttestationMetadata:
    key_id: str
    signature_algorithm: str
    public_key_id: str
    signed_at: float
    signature: str
    signed_hash: str

@dataclass(frozen=True)
class Event:
    id: str
    type: str
    timestamp: float
    task_id: Optional[str]
    conversation_id: Optional[str]
    payload: dict[str, Any]
    provenance: dict[str, Any]
    prev_event_hash: Optional[str]
    attestation: Optional[AttestationMetadata] = None
```

### Day 2: Verification + Orchestration Schemas

**`verification_ir.py`:**
```python
@dataclass(frozen=True)
class VerificationPlan:
    plan_id: str
    checks: list[VerificationCheck]
    thresholds: dict[str, float]
    blockers: list[str]
    intent_package_id: str

@dataclass(frozen=True)
class VerificationCheck:
    check_id: str
    type: str
    target: str
    parameters: dict[str, Any]
    blocking: bool

@dataclass(frozen=True)
class Certificate:
    """
    certificate_verified is True if and only if:
    - The certificate was generated by an LLM (generated_by is set)
    - At least one deterministic checker in checked_by returned a positive result
    - The conclusion.result is supported by the execution traces
    
    A second LLM review does NOT make a certificate "verified."
    Only deterministic checks establish verification.
    """
    certificate_id: str
    premises: list[Premise]
    evidence: list[FileEvidence]
    execution_traces: list[ExecutionTrace]
    conclusion: Conclusion
    confidence: float
    generated_by: str
    checked_by: list[str]
    verification_method: str
    certificate_verified: bool
    timestamp: float

@dataclass(frozen=True)
class Premise:
    premise_id: str
    statement: str
    source: str

@dataclass(frozen=True)
class FileEvidence:
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    source_hash: str

@dataclass(frozen=True)
class ExecutionTrace:
    trace_id: str
    path: list[str]
    conditions: list[str]

@dataclass(frozen=True)
class Conclusion:
    result: str
    reasoning: str

@dataclass(frozen=True)
class VerificationReport:
    report_id: str
    task_id: str
    policy_id: str
    checks: list[CheckResult]
    blast_radius: BlastRadiusResult
    timestamp: float

@dataclass(frozen=True)
class CheckResult:
    check_id: str
    passed: bool
    score: float
    evidence: list[str]
    explanation: str
    certificate: Optional[Certificate] = None

@dataclass(frozen=True)
class VerificationPolicy:
    policy_id: str
    on_failure: str
    on_inconclusive: str
    on_human_review: str
    require_deterministic_checker: bool

@dataclass(frozen=True)
class VerificationDecision:
    decision_id: str
    report_id: str
    status: str
    policy_id: str
    rationale: str
    timestamp: float

@dataclass(frozen=True)
class BlastRadiusResult:
    affected_callers: list[str]
    affected_callees: list[str]
    test_coverage_gap: list[str]
    risk_score: float
    dependency_impact: list[str]
    vulnerability_impact: list[str]

@dataclass(frozen=True)
class InvariantMetrics:
    check_coverage: float
    detection_recall: float
    detection_precision: float

@dataclass(frozen=True)
class IntentPackage:
    intent_package_id: str
    specs: list[dict[str, Any]]
    invariants: list[Invariant]
    nfrs: list[dict[str, Any]]
    verification_plan_id: str

@dataclass(frozen=True)
class Invariant:
    invariant_id: str
    rule: str
    compiled_query: str
    blocking: bool
```

**`task_ir.py`:**
```python
@dataclass(frozen=True)
class TaskIR:
    goal: str
    intent_package_id: str
    steps: list[Step]
    constraints: list[Constraint]
    budget: Budget
    policy_id: str

@dataclass(frozen=True)
class Step:
    step_id: str
    type: str
    config: dict[str, Any]
    pre_commit_hook_id: Optional[str] = None
    depends_on: list[str] = field(default_factory=list)
```

**`evidence.py`:**
```python
@dataclass(frozen=True)
class EvidencePack:
    query: str
    entities: list[Entity]
    relationships: list[Edge]
    source_chunks: list[SourceChunk]
    provenance: list[ProvenanceEntry]
    scores: dict[str, float]
    retrieval_methods: list[str]
    retrieval_timestamp: float
    graph_revision: str
    blast_radius: Optional[BlastRadiusResult] = None
    verification_metadata: Optional[dict] = None
```

### Day 3: Interfaces + Config

**`scheduler.py`:**
```python
class Scheduler(ABC):
    @abstractmethod
    async def submit(self, dag: ExecutableDAG) -> str: ...

    @abstractmethod
    async def status(self, task_id: str) -> TaskStatus: ...

    @abstractmethod
    async def cancel(self, task_id: str): ...

    @abstractmethod
    async def resume(self, task_id: str): ...

class DurableScheduler(Scheduler):
    @abstractmethod
    async def recover(self, task_id: str) -> bool: ...
```

```
verifyci/contracts/
├── embedding.py
├── vector_store.py
├── tool.py
├── scheduler.py
├── retriever.py
├── code_intel.py
├── config.py
└── provenance.py
```

**`config.py`:**
```python
@dataclass
class VulnerabilityCheckConfig:
    enabled: bool = True
    mode: str = "offline"
    cache_path: str = "./storage/vuln_cache.db"

@dataclass
class VerificationPolicyConfig:
    on_failure: str = "block"
    on_inconclusive: str = "human_review"
    on_human_review: str = "block"
    require_deterministic_checker: bool = True

@dataclass
class PlatformConfig:
    embedding_model: str = "nomic-embed-text"
    local_llm: str = "llama3.1"
    vector_store: str = "sqlite"
    scheduler: str = "async"
    verification: VerificationPolicyConfig = field(default_factory=VerificationPolicyConfig)
    vulnerability_check: VulnerabilityCheckConfig = field(default_factory=VulnerabilityCheckConfig)
```

### Referenced Types: Frozen vs Internal

**Frozen Contracts (define in Phase 0):**

| Type | Where referenced | Purpose | File |
|---|---|---|---|
| `Constraint` | `TaskIR.constraints` | Task constraint | `task_ir.py` |
| `Budget` | `TaskIR.budget` | NanoUSD integer budget | `task_ir.py` |
| `SourceChunk` | `EvidencePack.source_chunks` | Retrieved source fragment | `evidence.py` |
| `ProvenanceEntry` | `EvidencePack.provenance` | Traceability record | `evidence.py` |
| `ExecutableDAG` | `DurableScheduler.submit()` | Compiler output | `scheduler.py` |
| `TaskStatus` | `DurableScheduler.status()` | Scheduler status enum | `scheduler.py` |
| `ProjectionState` | `ReplayEngine.replay()` | Replay output | `memory_types.py` |
| `NodeResult` | `Executor.execute_node()` | Node execution output | `task_ir.py` |

**Internal Types (may change without contract notice):**

`BDDSpec`, `NFR`, `Diff`, `CodeGraph`, `ExecutionContext` — transient, single-module, don't cross frozen boundary.

This boundary must also be documented in `verifyci/contracts/README.md` under a "Not Frozen" heading.

### Acceptance Gate
- All dataclasses serialize to/from JSON
- Pydantic validation passes
- No circular references in schema
- Canonical serialization golden vector tests pass
- Identity function golden vector tests pass
- Provenance chain validation works
- `pytest tests/contracts/` green

---

## Phase 1 — Code Intelligence (Weeks 1-2)

### Goal
Incremental Tree-sitter parsing → AST-derived CPG builder → bitemporal graph + SBOM + local vulnerability cache.

### Week 1: Parsing + CPG Extraction

**Day 1-2: Incremental Tree-sitter parser**
```
verifyci/ingestion/
├── parser.py
├── extractor.py
├── language.py
├── incremental.py
└── dependency.py
```

**Day 3-4: CPG entity/edge extraction**
- Extract from AST only (no LLM)
- V1 emits: CONTAINS, HAS_NAME, CALLS_DIRECT, IMPORTS, INHERITS, REFERENCES
- V1 may emit CALLS_RECURSIVE only if self-recursion is AST-establishable
- V1 does NOT emit: CALLS_INDIRECT, CONTROLS, FLOWS_TO, SEQUENTIAL, REACHES, USES, DEFINES

**Day 5: CPG builder with bitemporal edges**
```
verifyci/graph/
├── builder.py
└── traverse.py
```
(As built: the planned `temporal.py` / `serializer.py` / `stats.py`
split was consolidated — temporal queries live in
`storage/graph_store.py`, traversal in `graph/traverse.py`, stats in
`interface/commands/stats.py`.)

### Week 2: Persistence + CLI

**Day 6-7: SQLite schema**
```sql
CREATE TABLE revisions (
    revision_id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL,
    commit_id TEXT,
    parent_revision_id TEXT,
    source_hash TEXT NOT NULL,
    timestamp REAL NOT NULL,
    ingestion_config_hash TEXT NOT NULL
);

CREATE TABLE entities (
    revision_entity_id TEXT PRIMARY KEY,
    logical_entity_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    language TEXT,
    source_hash TEXT NOT NULL,
    valid_from REAL,
    valid_until REAL,
    t_created REAL,
    t_expired REAL,
    metadata_json TEXT,
    properties_json TEXT,
    FOREIGN KEY (revision_id) REFERENCES revisions(revision_id)
);
CREATE INDEX idx_entities_logical ON entities(logical_entity_id);
CREATE INDEX idx_entities_logical_valid ON entities(logical_entity_id, valid_from, valid_until);

CREATE TABLE edges (
    id TEXT PRIMARY KEY,
    revision_id TEXT NOT NULL,
    src_entity_id TEXT NOT NULL,
    dst_entity_id TEXT NOT NULL,
    type TEXT NOT NULL,
    subtype TEXT,
    valid_from REAL,
    valid_until REAL,
    observed_at REAL,
    source_commit TEXT,
    t_created REAL,
    t_expired REAL,
    metadata_json TEXT,
    properties_json TEXT,
    FOREIGN KEY (revision_id) REFERENCES revisions(revision_id)
);
CREATE INDEX idx_edges_src ON edges(src_entity_id);
CREATE INDEX idx_edges_dst ON edges(dst_entity_id);

CREATE TABLE events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    timestamp REAL NOT NULL,
    task_id TEXT,
    conversation_id TEXT,
    payload_json TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    prev_event_hash TEXT,
    attestation_json TEXT
);

CREATE TABLE anchors (
    anchor_id TEXT PRIMARY KEY,
    revision_id TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    timestamp REAL NOT NULL
);

CREATE TABLE deltas (
    delta_id TEXT PRIMARY KEY,
    from_revision_id TEXT NOT NULL,
    to_revision_id TEXT NOT NULL,
    delta_json TEXT NOT NULL
);
```

**Day 8-10: CLI** (current interface — `verifyci` is the command, `aci` a legacy alias; commit recording lives on `ingest` since `revise` was removed at `d3056c8`)
```bash
verifyci init ./repo
verifyci ingest ./repo
verifyci ingest ./repo --incremental
verifyci ingest ./repo --commit <hash>
verifyci stats
verifyci query "Where is auth?"
verifyci deps
verifyci verify-diff "$(git diff)" --db ./repo/.verifyci/verifyci.db
verifyci run "ship it" --diff "$(git diff)" --db ./repo/.verifyci/verifyci.db
verifyci vuln refresh
verifyci verify-chain --db ./repo/.verifyci/verifyci.db
verifyci serve --transport stdio
```

### Acceptance Gate
- Ingest 3 sample repos (Python, C, Markdown)
- Incremental re-parse: median < 0.2ms, p95 < 1.0ms, p99 < 5.0ms
- CPG contains only AST-derived edges
- SBOM subgraph with DEPENDS_ON edges
- Local vulnerability cache working (offline)
- All entities have logical_entity_id + revision_entity_id
- Bitemporal query returns correct historical state

---

## Phase 2 — Retrieval V1 (Week 3)

### Goal
Hybrid retrieval with rank-based RRF fusion → EvidencePack with blast radius.

```
verifyci/retrieval/
├── dense.py
├── sparse.py          # BM25 (V1) → SPLADE-Code (V1.1)
├── graph_retriever.py
├── fusion.py          # RRF (rank-based)
├── blast_radius.py
├── evidence.py
└── provider.py
```

**RRF fusion:**
```python
def rrf_fusion(dense_results, sparse_results, graph_results, k=60):
    scores = {}
    for rank, result in enumerate(dense_results):
        scores[result.id] = scores.get(result.id, 0) + 1.0 / (k + rank + 1)
    for rank, result in enumerate(sparse_results):
        scores[result.id] = scores.get(result.id, 0) + 1.0 / (k + rank + 1)
    for rank, result in enumerate(graph_results):
        scores[result.id] = scores.get(result.id, 0) + 1.0 / (k + rank + 1)
    return sorted(scores, key=scores.get, reverse=True)
```

### Acceptance Gate
- Dense + BM25 + Graph → RRF → Cross-encoder
- Hybrid retrieval nDCG@10 > dense-only baseline by 5+ points
- Blast radius identifies > 90% of downstream dependents
- EvidencePack contains full provenance + blast_radius

---

## Phase 3 — Memory (Week 4)

### Goal
Event-sourced memory with hash-chained ledger, bitemporal projections, anchor+delta replay.

```
verifyci/memory/
├── ledger.py          # Hash-chained, SHA-256 only (V1)
├── projections/
│   ├── memory.py
│   ├── knowledge.py
│   └── context.py
├── replay.py
└── snapshot.py
```

### Acceptance Gate
- `replay(events[0:n]) == snapshot(n)` for all n
- `replay(events[0:n] + events[n:m]) == replay(events[0:m])`
- Hash chain integrity verified
- Anchor+delta storage: < 50% of full snapshot storage
- 44 equivalence tests pass

---

## Phase 4 — Agent Compiler + Verification (Weeks 5-6)

### Goal
Planner → Compiler → AsyncDAGScheduler with verification gates.

### Week 5: Planner + Compiler

```
verifyci/orchestration/
├── planner.py
├── intent.py
└── compiler/
    ├── validation.py
    ├── permissions.py
    ├── budget.py
    └── strategy.py
```

### Week 6: Verification Layer + Scheduler

```
verifyci/verification/
├── semi_formal_reason.py
├── blast_radius.py
├── intent_align.py
├── verification_ir.py
├── policy.py
└── evidence_verifier.py
```

**Semi-formal reasoning:**
```python
class SemiFormalReasoner:
    def verify(self, diff: Diff, graph: CodeGraph) -> Certificate:
        premises = self._extract_premises(diff, graph)
        paths = self._trace_execution_paths(diff, graph)
        conclusion = self._derive_conclusion(premises, paths)
        det_checks = self._run_deterministic_checks(premises, paths)
        certificate = Certificate(
            certificate_id=generate_id(),
            premises=premises,
            evidence=self._collect_evidence(premises, paths),
            execution_traces=paths,
            conclusion=conclusion,
            confidence=self._compute_confidence(premises, paths),
            generated_by=self.model_name,
            checked_by=[c.checker_id for c in det_checks],
            verification_method="semi_formal_reasoning",
            certificate_verified=any(c.is_deterministic for c in det_checks),
            timestamp=time.time()
        )
        return certificate
```

**Policy decides:**
```python
class PolicyEvaluator:
    def evaluate(self, report: VerificationReport, policy: VerificationPolicy) -> VerificationDecision:
        if all(check.passed for check in report.checks):
            return VerificationDecision(status="PASS", ...)
        if any(check.blocking and not check.passed for check in report.checks):
            return VerificationDecision(status="FAIL", ...)
        return VerificationDecision(status="HUMAN_REVIEW", ...)
```

**Pre-commit hook:**
```python
async def execute(self, context: ExecutionContext) -> NodeResult:
    result = await self._run(context)
    if self.pre_commit_hook_id:
        report, decision = await verify.diff(
            diff=result.diff,
            revision_id=context.revision_id,
            plan_id=self.pre_commit_hook_id
        )
        if decision.status == "FAIL":
            raise VerificationBlocker(report, decision)
        if decision.status == "HUMAN_REVIEW":
            raise HumanReviewRequired(report, decision)
    return result
```

### Acceptance Gate
- Plan a 3-step task → valid DAG with IntentPackage
- Semi-formal reasoning produces valid Certificate with certificate_verified
- Policy decides (not report)
- Pre-commit hook: explicit PASS/FAIL/HUMAN_REVIEW
- Budget breach → graceful termination + BUDGET_BREACHED event
- OTel conversation ID propagated to all spans
- Invariant metrics: coverage 100%, recall ≥ 0.90, precision ≥ 0.85

---

## Phase 5 — MCP + Observability (Week 7)

### Goal
Expose platform via MCP with progressive disclosure, instrument with OTel.

**MCP tool surface (V1):**

| Tool | Type | LLM Tokens |
|------|------|-------------|
| `code.search` | Deterministic | 0 |
| `code.definition` | Deterministic | 0 |
| `graph.query` | Deterministic | 0 |
| `verify.diff` | Verification | Yes |
| `task.run` | Orchestration | Yes |
| `task.status` | Deterministic | 0 |

**OTel compatibility layer:**
```python
# verifyci/observability/genai_semconv.py
from opentelemetry.semconv.gen_ai import (
    GenAiAgentId, GenAiAgentName, GenAiAgentVersion,
    GenAiAgentDescription, GenAiConversationId, GenAiOperationName,
    GenAiUsageInputTokens, GenAiUsageOutputTokens,
)
```

### Acceptance Gate
- MCP server starts, all tools callable
- `verify.diff` returns VerificationReport + VerificationDecision
- Deterministic tools exhaust before LLM tools
- OTel Agent Timeline: every span carries conversation_id
- Evaluation suite passes

---

## V1 Scope (Walking Skeleton)

### V1 status — as of `ae171cb`

**Implementation: complete and audit-hardened.** All Phase 0–5 mechanisms
exist, the freeze checklist is `[x]`, and the six-item re-audit remediation
queue is **closed** (resolver `c247d30` · planner `9486efb` · revision
identity `c1e91ca` · SKIP_DIRS `8ea8f11` · rename `1aba78f` · retriever
`ae171cb`), with a passing end-to-end closure: full suite green, gate
matrix re-verified on real DBs, and every probe demonstrating its defect
before its fix.

**Empirical validation: in progress.** See Success Criteria table — each
gate is marked implemented / measured / target met / not established /
unmeasured. Retrieval smoke results stay reported honestly (hybrid 0.866
vs dense-only 0.877; the +5pt BEIR-scale gate is not established), and the
agent-patch equivalence, verification precision, blast coverage, and
latency gates remain unmeasured. **V1 is implementation-complete, not
empirically validated.**

### V1.1 branch additions (unreleased)

- Diff path partitioning (`verification/partition.py`): CODE_CORE /
  TEST_SUITE / DOCUMENTATION / CONFIGURATION / ANCILLARY. Non-code
  fast paths earn a passing certificate but route to HUMAN_REVIEW
  end-to-end (provenance requires evidence). See the `Certificate`
  contract docstring.
- Three-class deletion verification (`verification/deletion.py`) with
  Class-3 guard-removal waivers (`SignedIntentWaiver`, deny-by-default
  crypto in `contracts/verification_ir.py`).
- Execution witnesses (`verification/witness.py`); snippet-completeness
  records (`EntitySnippetRecord`, additive — frozen `Entity` untouched).
- H1/H2/H3 measurement campaigns under `benchmarks/` (retrieval
  +3.84pts repro, invariant recall 1.0 combined, incremental p95 still
  unmet); H4-A real-LLM sourcing record
  (`benchmarks/patch_real/SOURCING.md`).

### Included in V1
- Contracts with logical/revision entity IDs
- Canonical event serialization (tested contract)
- VerificationPolicy + Decision
- DurableScheduler interface
- Tree-sitter incremental → AST-derived CPG → rustworkx → SQLite
- SBOM extraction with DEPENDS_ON edges
- Local vulnerability cache (offline mode default)
- Dense + BM25 + Graph → RRF → Cross-encoder
- Blast radius (graph traversal only)
- Hash-chained event ledger (SHA-256 only)
- Full + delta replay with anchor+delta
- Memory + Knowledge projections
- Semi-formal reasoning (premise → trace → conclusion → certificate)
- Blast radius check
- Intent alignment check
- Policy → Decision
- Invariant check with split metrics
- Planner → Compiler → AsyncDAGScheduler (in-memory)
- MCP: code.search, code.definition, graph.query, verify.diff, task.run, task.status
- OTel instrumentation with conversation ID

### Deferred to V1.1
- Ed25519 attestation
- SPLADE-Code + HyDE
- Adversarial cross-model review
- Comprehension gate
- Temporal scheduler
- OSV online refresh (opt-in)
- Temporal reasoning agent

### Deferred to V1.2
- LightGBM reranker trained on git history
- Contract synthesis
- Rename detection for logical entity continuity
- Full CFG/DFG

---

## File Structure

```
verifyci/
├── verifyci/
│   ├── contracts/
│   │   ├── entity.py
│   │   ├── edge.py
│   │   ├── event.py
│   │   ├── revision.py
│   │   ├── graph_schema.py
│   │   ├── canonical.py
│   │   ├── identity.py
│   │   ├── evidence.py
│   │   ├── verification_ir.py
│   │   ├── task_ir.py
│   │   ├── memory_types.py
│   │   ├── embedding.py
│   │   ├── vector_store.py
│   │   ├── tool.py
│   │   ├── scheduler.py
│   │   ├── retriever.py
│   │   ├── code_intel.py
│   │   ├── config.py
│   │   └── provenance.py
│   ├── ingestion/
│   │   ├── parser.py
│   │   ├── extractor.py
│   │   ├── language.py
│   │   ├── incremental.py
│   │   └── dependency.py
│   ├── codeintel/          # not built in V1 (no SCIP/LSP adapters)
│   ├── graph/
│   │   ├── builder.py
│   │   └── traverse.py     # (temporal/serializer/stats consolidated, see Day 5 note)
│   ├── retrieval/
│   │   ├── dense.py
│   │   ├── sparse.py
│   │   ├── graph_retriever.py
│   │   ├── fusion.py
│   │   ├── reranker.py
│   │   ├── blast_radius.py
│   │   ├── evidence.py
│   │   └── provider.py
│   ├── memory/
│   │   ├── ledger.py
│   │   ├── replay.py
│   │   ├── snapshot.py
│   │   └── projections/
│   │       ├── memory.py
│   │       ├── knowledge.py
│   │       └── context.py
│   ├── verification/
│   │   ├── semi_formal_reason.py
│   │   ├── blast_radius.py
│   │   ├── intent_align.py
│   │   ├── verification_ir.py
│   │   ├── policy.py
│   │   └── evidence_verifier.py
│   ├── orchestration/
│   │   ├── planner.py
│   │   ├── intent.py
│   │   ├── scheduler.py
│   │   ├── executor.py
│   │   ├── events.py
│   │   └── compiler/
│   │       ├── validation.py
│   │       ├── permissions.py
│   │       ├── budget.py
│   │       └── strategy.py
│   ├── tools/
│   │   ├── registry.py
│   │   ├── sandbox.py
│   │   ├── shell.py
│   │   ├── file_read.py
│   │   ├── file_write.py
│   │   └── llm.py
│   ├── observability/
│   │   ├── genai_semconv.py
│   │   ├── tracing.py
│   │   ├── metrics.py
│   │   └── telemetry.py
│   ├── storage/
│   │   ├── graph_store.py
│   │   ├── metadata.py
│   │   └── revision.py
│   └── interface/
│       ├── mcp_server.py
│       ├── http.py
│       ├── cli.py
│       └── commands/
│           ├── init.py
│           ├── ingest.py
│           ├── stats.py
│           ├── query.py
│           ├── deps.py
│           ├── revise.py
│           ├── vuln.py
│           ├── verify.py
│           ├── run.py
│           └── evaluate.py
├── config/
│   └── default.yaml
├── tests/
│   ├── contracts/
│   ├── ingestion/
│   ├── retrieval/
│   ├── memory/
│   ├── verification/
│   ├── orchestration/
│   └── evaluation/
├── benchmarks/
├── storage/
└── README.md
```

---

## Dependencies

Current state (matches `pyproject.toml` at the `ae171cb` endpoint):

```toml
[project]
name = "verifyci"
version = "0.1.0"
requires-python = ">=3.12"

dependencies = [
    "pydantic>=2.13",
    "typer>=0.25",
    "pyyaml>=6.0.3",
    "tree-sitter>=0.25",
    "tree-sitter-python>=0.25",
    "tree-sitter-c>=0.24",
    "tree-sitter-cpp>=0.23",
    "rustworkx>=0.17",
    "fastmcp>=4.0",
    "fastapi>=0.141",
    "aiohttp>=3.14",
    "opentelemetry-api>=1.42",
]

[project.optional-dependencies]
temporal = ["temporalio>=1.0"]
attestation = ["cryptography>=42.0"]
embeddings = ["sentence-transformers>=3.0"]
otel-semconv = ["opentelemetry-semantic-conventions>=0.40b0"]
dev = ["pytest>=8.0", "pytest-asyncio>=0.23", "pytest-cov>=4.0", "ruff>=0.15"]

[project.scripts]
verifyci = "verifyci.interface.cli:app"
aci = "verifyci.interface.cli:app"  # legacy alias
```

Plan-errata (original plan listed these as core deps; each was removed at
the `563db16` packaging repair): `ollama` (Ollama is called over raw
`aiohttp`, never through the SDK), `rank-bm25` (BM25 is implemented in
`retrieval/sparse.py`), `aiosqlite` (storage uses sync `sqlite3` inside
`asyncio.to_thread`), `uvicorn` (no HTTP runner exists yet), and
`opentelemetry-sdk` (only the API is imported). `sentence-transformers`
moved to the `[embeddings]` extra because it drags in PyTorch and the
provider lazy-imports it.

---

## Success Criteria (V1)

State legend — **implemented**: the mechanism exists and is audit-hardened;
**measured**: an observed number exists; **target met**: measured ≥ target;
**not established**: measured exists but the gate's protocol isn't the one
specified, or the result misses; **unmeasured**: no number at all.

| Criterion | Target | Measurement | Status | Observed (at `ae171cb`) |
|---|---|---|---|---|
| Entity extraction precision | > 0.85 | Manual sample of 100 entities | measured, sample smaller than specified | 1.00 on 13-entity smoke set (not 100) |
| Entity extraction recall | > 0.80 | Compare against ground truth | measured, sample smaller than specified | 1.00 on same 13-entity set |
| Retrieval Recall@5 | > 0.80 | 50 sample queries | measured, below protocol | 0.80 on 5 queries |
| Retrieval nDCG@10 | +5-15 over dense-only | BEIR-style benchmark | measured, **below target** | frozen BEIR-style set (62 judged queries, 60 codebase docs, graded gains, corpus/qrels frozen before any embedding, drift-guarded harness): dense-only 0.6220 → hybrid 0.6603 = **+3.84 pts < +5**. Reruns bit-identical; Recall@5 0.6465→0.6707. Hybrid clearly helps, not yet at gate margin. The 5-query smoke (0.866/0.877) stays historical, never the evidence set |
| Semi-formal Patch Equivalence | > 0.90 | Agent-generated patches | measured, **below target; not established** | frozen 17-case corpus (`benchmarks/patch_corpus/`, synthetic stand-ins mimicking agent failure modes, labels fixed before the single run): 7/8 correct patches reached expected outcome = **0.875**. The one miss (C3) is a blast-exposure hunk-shape gap, reported not retuned. Synthetic + 8 correct patches is too small to *establish* the gate even if it passed. A recorded real-LLM corpus is the follow-on |
| Blast Radius Coverage | > 0.90 | Graph traversal vs. manual | measured, **0.857 < target** | frozen topology corpus (`benchmarks/blast_corpus/`, 9 cases, expected sets hand-derived before detection): traversal EXACT (1.0) on every seeded hunk — direct, transitive 2-hop, multi-path, cross-file, method callee, zero-impact; the single miss is the **pre-labeled tail-insertion gap** (B6: pure insertion → seeding yields [] → risk 0 → 6/6 dependents missed) — the C1 finding reproduced as frozen data, not repaired. One disclosed precision artifact (B5 def-line hunk's context bleeds into the adjacent function → seed re-enters via a real caller; detected ⊇ expected, recall 1.0). `coverage_seeded_only` = 1.0. 7 non-empty cases: measured, not established |
| Invariant check coverage | 100% | All invariants applicable to a diff are evaluated | implemented + measured | 1.0 by construction (unapplicable invariants reported) |
| Invariant detection recall | ≥ 0.90 | On labeled ground-truth set | measured, **below target; not established** | v1 set 6/9 ≈ 0.67; expanded 26-case v2 set 16/18 ≈ 0.89 (precision 16/16 = 1.00, 11 positive secret mechanisms, triple-quoted capped at 1); misses = two documented residuals (unquoted <12-char floor, graph relative-import blindness). Corpus too small to establish the gate even above 0.90 |
| Invariant detection precision | ≥ 0.85 | On same set | measured | v1 4/4; expanded v2 16/16 = 1.00 — zero false alarms across 8 true negatives (env/config lookups, comment, name-only, plain string, empty string) |
| Verification Precision | > 0.85 | Flagged issues vs. ground truth | measured, **met; not established** | of all FAIL verdicts on the frozen patch corpus, 4/4 were truly-wrong = **precision 1.0** (no false-positive FAIL on any correct patch). 4 FAIL verdicts on 17 cases is too small to *establish* the gate; the deterministic-catch half (4/4) is solid, the false-positive half needs a wider correct-patch population |
| Incremental Parse Latency | median < 0.2ms, p95 < 1.0ms, p99 < 5.0ms | Benchmark protocol | measured, **NOT MET (p95)** | frozen 1000-sample rotating-line insertion workload on scheduler.py (34μs median, p95 ~3.8ms, p99 4.3–6.1ms — p99 verdict unstable at its 5ms limit across 3 runs; p95 fails identically every run). Mechanism recorded: cost is edit-position dominated (re-lex to next change point; early-file edits re-lex long tails) + mild cumulative growth (31→40μs halves). Cold full-parse 3.7ms context proves reparsing IS incremental at the median. No source changed, no threshold retuned. Benchmarks in `benchmarks/latency/` |
| Temporal Query Latency | < 200ms | At 10K edges | **measured, MET on this host** | 10,000 edges / 10,000 temporal entity rows / 5.6MB SQLite, hit_rate 1.0: median 0.044ms, p95 0.073ms, p99 0.151ms — ~3 orders of margin under 200ms. Cross-machine establishment NOT claimed (latency is host-specific; protocol + source hashes + environment recorded instead) |
| Replay Equivalence | 100% | 44 tests | measured, met | 44/44 |
| Provenance Coverage | 100% | Every claim traceable | implemented + closure-verified | closure item 10: evidence `source_hash` == entity hash |
| Local-only | Zero cloud deps | No external API calls | implemented, met | embeddings default to offline hash; Ollama is opt-in to a local server |

### Audit-remediation addendum (all six closed, end-to-end closure passed at `ae171cb`)

| Item | Commit | Evidence |
|---|---|---|
| Resolver (no guessed links; suffix grounding declines) | `c247d30` | 6 probes, 3 fail pre-fix; live matrix |
| Planner runs verification once, not 3× | `9486efb` | 4/7 probes fail pre-fix; call count 3→1 |
| Revision identity = content; lineage = append-only `ingests` | `c1e91ca` | revert-cycle probe True→False; live chain ingest→revision→entity→verify |
| SKIP_DIRS single classifier, `pyvenv.cfg` marker, `.verifyciignore` | `8ea8f11` | deps-leak probe 4→0; six-question matrix pinned |
| `verifyci`/`VERIFYCI_*` canonical, `aci`/`ACI_*` fallback | `1aba78f` | 7 prefix probes; argv-derived prog name |
| Retriever: stored BM25 tf, semantic-edge expansion, cached `code_search` | `ae171cb` | construction-count probes (2149→0, 4→1, 5→1); 7 probes fail pre-fix; gate matrix unchanged |
| End-to-end closure | `ae171cb` | items 1–10 re-verified on real DBs (see V1_BASELINE / closure record) |

The closure conclusion rests on targeted regression probes + real-DB
reproduction + controls + unchanged gate semantics. **"N tests pass" is
supporting evidence, not the audit conclusion.**

---

## Timeline

| Phase | Duration | Key Deliverable |
|---|---|---|
| 0 — Contracts | Days 1-3 of Week 1 | CPG schema, Certificate, Policy, DurableScheduler, canonical serialization |
| 1 — Code Intelligence | Weeks 1-2 (Phase 0 absorbed into Week 1) | Incremental CPG + SBOM + local vuln cache |
| 2 — Retrieval V1 | Week 3 | Dense + BM25 + Graph → RRF → Cross-encoder |
| 3 — Memory | Week 4 | Hash-chained ledger + anchor+delta replay |
| 4 — Compiler + Verification | Weeks 5-6 | Semi-formal + blast radius + intent align + Policy |
| 5 — MCP + Observability | Week 7 | Progressive disclosure + OTel Agent Timeline |

**Total:** 7 weeks to V1 walking skeleton.

---

## Freeze Checklist

```
[x] 01  contracts/                    — schemas frozen, no logic
[x] 02  canonical serialization       — golden vector tests pass (38/38 tests green)
[x] 03  SQLite schema                 — migrations run, indexes present
[x] 04  Tree-sitter parser            — parses Python repo end-to-end
[x] 05  AST extractor                 — emits entities + AST edges
[x] 06  minimal rustworkx graph       — in-memory build succeeds
[x] 07  ingest one Python repository  — verifyci ingest writes to SQLite
[x] 08  extraction benchmark          — precision > 0.85, recall > 0.80
[x] 09  Dense + BM25 + Graph          — individual retrievers return
[x] 10  RRF + cross-encoder           — nDCG@10 +5pt gate NOT established (smoke: hybrid 0.866 vs dense-only 0.877; rerank default-off) → superseded by frozen BEIR-style run: hybrid +3.84 pts over dense-only (0.6603 vs 0.6220), below +5, measured below target
[x] 11  EvidencePack                  — full provenance populated
[x] 12  blast radius                  — blast radius coverage > 0.90 gate UNMEASURED (check implemented, advisory-only; rerank/gate unaffected)
[x] 13  VerificationReport            — no `passed` field
[x] 14  VerificationPolicy            — produces VerificationDecision
[x] 15  Planner → TaskIR → DAG        — 3-step task compiles
[x] 16  pre_commit → verify.diff      — blocks on FAIL, routes on HUMAN_REVIEW
[x] 17  MCP server                    — 6 tools callable
[x] 18  OTel                          — conversation_id on every span
```

---

## Core Principles

1. **The LLM is an interpreter and planner, not the source of truth.**
2. **Only the verification policy decides** — not the report, not the LLM.
3. **LLM may propose. Graph may provide context. Tools may produce facts. Deterministic checks may establish invariants.**
4. **Provenance is mandatory** — every claim traceable to file + lines + source_hash + revision_id.
5. **Progressive disclosure** — deterministic tools exhaust before LLM tokens.
6. **Do not add another major subsystem until an evaluation demonstrates that the existing architecture cannot meet a requirement.**

---

## Implementation Invariants

1. Entity identity is split into `logical_entity_id` and `revision_entity_id`. Do not silently merge them.
2. Canonical event serialization is a tested contract with golden vectors. Do not change the canonicalization rules without updating the vectors.
3. `VerificationReport` has no `passed` field. Only `VerificationPolicy` produces a `VerificationDecision`.
4. Invariant metrics are split: `check_coverage`, `detection_recall`, `detection_precision`. Do not conflate.
5. Vulnerability data is local by default. OSV refresh is opt-in.
6. V1 retrieval is Dense + BM25 + Graph → RRF → Cross-encoder. No other retrieval path in V1.
7. V1 scheduler is `AsyncDAGScheduler` only. `DurableScheduler` interface exists; Temporal implementation is V1.1.
8. Enum values exist for forward compatibility. V1 must only emit edges the extractor can deterministically establish. Do not emit V2 edges speculatively.
9. Rename detection is V1.2. V1 treats a rename as delete + create. Do not add rename heuristics before V1.2.

---

**Freeze. Build the walking skeleton. Measure. Expand only on evidence.**
