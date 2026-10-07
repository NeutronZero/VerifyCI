# CAP-008: Concurrent CI Workers & Shared-Storage Contention Attestation Protocol (FROZEN)

**Experiment ID**: CAP-008  
**Corpus SHA-256**: `2a20d57dffd0df86a6a7839c16ad6597475be24c0933df6f478942d677efb1d3`  
**Label SHA-256**: `5dda237b7fab3e2d4bfd5d5119bce29e8d5b557558191d7ab00e871726c5e55a`  
**Oracle Manifest SHA-256**: `7836d44d4c0e1db2859b69851be125acd1874cd560825842997962a0ae97e55b`  
**Total Cases**: 64  
**Total Slices**: 8 (8 cases per slice)  
**Distribution**: 48 PASS, 16 INCONCLUSIVE (tripwires)  
**Worker Counts**: $N \in \{2, 4, 8\}$ independent OS worker processes  
**Storage Engine**: SQLite 3 with Write-Ahead Logging (WAL)  

---

## 1. Objective & Core Invariants

Gate **CAP-008** establishes that VerifyCI preserves evidence integrity, snapshot isolation, ledger consistency, and deterministic verification when multiple concurrent CI worker processes ($N \in \{2, 4, 8\}$) concurrently ingest, query, and mutate revisions against shared SQLite/WAL storage.

> **Core Invariant**: Concurrent execution may change timing and scheduling, but it must not change what VerifyCI can prove, what it commits, or which committed evidence belongs to which worker/revision.

### Refined Serializability Invariant (T2)
For disjoint branch histories:
$$\text{Concurrent}(\text{branch}_A, \text{branch}_B) \equiv \text{Serial}(\text{branch}_A, \text{branch}_B)$$
with respect to each branch's canonical state, and $\text{branch}_A$ state is strictly invariant under $\text{branch}_B$ activity. Shared mutable objects or merged branches declare explicit serial equivalence classes in the case oracle.

### Committed Lineage & Ledger Order Invariant (T5)
Committed anchor order is deterministic under the declared serialization rule and never rewinds, duplicates, or points to an uncommitted revision. Merkle and event chains are rooted in committed event identity and ancestry, strictly independent of wall-clock timing:
$$\text{Chain}(E_n) = \text{Hash}(E_n \mathbin{\Vert} \text{Chain}(E_{n-1})) \quad \text{where } \text{Prev}(E_n) = \text{Hash}(E_{n-1})$$

### Fail-Closed Hard Veto (T6)
$$\text{LockTimeout} \lor \text{PartialRead} \lor \text{CorruptedState} \implies \text{Status} = \text{INCONCLUSIVE} \; (\text{NEVER a partial PASS})$$

---

## 2. The Eight Protocol Locks

### LOCK-1: Real Process Concurrency
Concurrency evaluation MUST be executed using actual independent OS processes ($N \in \{2, 4, 8\}$), not merely Python threads, to expose real SQLite file locking, multi-process memory separation, OS filesystem lock contention, and inter-process race conditions.

### LOCK-2: Independent Concurrency Oracle
The ground-truth concurrency reference oracle (`oracle.py`) is completely decoupled from `verifyci`. It MUST NOT import any module from `verifyci` (zero storage, memory, contracts, or traversal imports) and relies solely on the Python standard library to derive legal snapshots, committed event sets, disjoint branch states, and serial equivalence classes.

### LOCK-3: Explicit Serial Reference
Every concurrent case specifies a declared serial reference ordering or an equivalence class of permitted serial outcomes. The concurrent outcome must be isomorphic to an admitted serial schedule.

### LOCK-4: Atomic Visibility
A reader process concurrently reading from SQLite/WAL during active worker commits must observe either:
$$\text{OldCommittedState} \quad \lor \quad \text{NewCommittedState}$$
and NEVER:
- A half-written revision,
- A half-written edge/entity set, or
- A mixed certificate/ledger state.

### LOCK-5: Zero Lost Updates
All valid non-conflicting concurrent writes submitted across workers must persist in the committed store. No update is silently overwritten or lost due to contention or race conditions.

### LOCK-6: Bounded Lock Handling & Fail-Closed Veto
`database is locked`, busy timeouts, retries, and eventual failure must be observable, deterministic, and bounded. Retry exhaustion must result in an explicit `INCONCLUSIVE` / `INFRA_ERROR` status, never a silent pass or partial write.

### LOCK-7: Deterministic Ledger Identity & Ancestry
Concurrent writes must preserve unique event/revision identity and deterministic ancestry semantics without duplicate logical commits. Event hash chains maintain cryptographic continuity.

### LOCK-8: Immutable Benchmark Freeze Prior to Production Optimization
Corpus cases, labels, oracle manifest, worker schedules, host configuration, and protocol specification are cryptographically sealed with SHA-256 before modifying any VerifyCI storage, transaction, or concurrency code.

---

## 3. Evaluation Gates (T1–T8)

| Gate | Focus | Acceptance Requirement |
| :--- | :--- | :--- |
| **T1** | Snapshot Isolation Integrity | Readers observe strictly consistent pre- or post-commit snapshots; 0 partial or uncommitted entities/edges observed. |
| **T2** | Disjoint Branch Invariance & Serializability | Disjoint branch states are mutually invariant: $\text{State}(B_A \mathbin{\Vert} B_B) \equiv \text{State}(B_A \to B_B)$; declared serial equivalence holds. |
| **T3** | Zero Lost Updates (Write Completeness) | 100% of non-conflicting concurrent writes persist; 0 dropped worker records under contention. |
| **T4** | Concurrent Read Throughput & Non-Blocking | Multiple concurrent readers make progress without being blocked by writers under WAL mode ($p95 < 20\text{ ms}$). |
| **T5** | Committed Lineage & Ledger Order | Deterministic committed event/anchor ancestry; 0 chain rewinds, duplicate links, or uncommitted pointer references. |
| **T6** | Bounded Lock Handling & Fail-Closed Veto | Lock exhaustion or deadlock produces explicit `INCONCLUSIVE` / `INFRA_ERROR`; 0 false-positive passes under contention failure. |
| **T7** | Crash / Interruption Atomicity | Interrupted or aborted transactions rollback cleanly leaving 0 orphaned rows; surviving state remains fully consistent. |
| **T8** | Concurrency Corpus Agreement | 100% agreement between VerifyCI concurrent execution and independent oracle across all 64 cases. |

---

## 4. Stratified Concurrency Slices (64 Cases)

| Slice ID | Slice Name | Workers ($N$) | Ground Truth | Focus & Verification Contract |
| :---: | :--- | :---: | :---: | :--- |
| **1** | `two_worker_read_write_contention` | 2 | PASS (8/8) | 1 writer ingesting bulk revisions, 1 reader querying entities/edges; validates T1 snapshot isolation and T4 non-blocking reads. |
| **2** | `four_worker_mixed_ingest_query` | 4 | PASS (8/8) | 2 writers on disjoint modules, 2 readers polling latest revisions; validates T1, T3 zero lost updates, and T4 throughput. |
| **3** | `eight_worker_high_contention` | 8 | PASS (8/8) | High contention across 8 worker processes on shared SQLite store; validates WAL contention handling, busy-timeout bounds, and T3 completeness. |
| **4** | `same_branch_concurrent_ingest` | 2–4 | PASS (8/8) | Multiple workers committing revisions on the same branch; validates serialized commit progression, monotonic lineage, and absence of split-brain histories. |
| **5** | `different_branch_concurrent_ingest` | 2–6 | PASS (8/8) | Multiple workers ingesting disjoint branches concurrently; validates T2 strict branch invariance ($\text{branch}_A$ unaffected by $\text{branch}_B$). |
| **6** | `certificate_ledger_concurrent_writes` | 2–8 | PASS (8/8) | Concurrent event appends and certificate logging; validates T5 ledger order, cryptographic hash continuity, and absence of lost events. |
| **7** | `forced_lock_timeout_exhaustion_tripwires` | 2–4 | INCONCLUSIVE (8/8) | Intentional lock exhaustion exceeding busy timeout; validates T6 fail-closed veto (`INCONCLUSIVE`, never silent success). |
| **8** | `crash_interruption_during_commit_tripwires` | 2–4 | INCONCLUSIVE (8/8) | Mid-commit crash / unhandled transaction abort; validates T7 atomicity, zero partial rows, and reader fail-closed interception. |

---

## 5. Independent Schema & Event Specification

### Case Definition (`cases.jsonl`)
- `id`: Unique identifier (`cap008_c01` .. `cap008_c64`)
- `name`: Descriptive scenario name
- `slice`: Concurrency slice designation
- `worker_count`: $N \in \{2, 4, 8\}$
- `workers`: Array of worker definitions with declared action schedules:
  - `worker_id`: Worker identifier (`w0`, `w1`, ...)
  - `role`: `"writer"` | `"reader"` | `"auditor"`
  - `actions`: Sequential worker commands (`ingest_revision`, `query_revision`, `query_entities`, `append_event`, `hold_lock`, `abort_transaction`)
- `initial_state`: Optional pre-seeded database state
- `serial_reference_order`: Declared canonical serial execution sequence for verification
- `concurrency_params`:
  - `busy_timeout_ms`: 5000
  - `wal_autocheckpoint`: 1000
  - `synchronous`: "NORMAL"
- `expected_status`: `"PASS"` | `"INCONCLUSIVE"`

### Gold Labels (`labels.jsonl`)
- `id`: Matching case ID
- `slice`: Slice name
- `expected_status`: `"PASS"` | `"INCONCLUSIVE"`
- `expected_revisions`: List of committed revision IDs
- `expected_branch_states`: Map of branch names to canonical `{ latest_revision_id, entity_count, edge_count, canonical_hash }`
- `expected_event_count`: Total committed events in ledger
- `expected_chain_valid`: Boolean (cryptographic continuity)
- `disjoint_invariance_holds`: Boolean
- `tripwire_mechanism`: Description of fail-closed mechanism for tripwires (null for PASS)

### Oracle Manifest (`oracle_manifest.jsonl`)
- `id`: Case ID
- `slice`: Slice name
- `input_hash`: SHA-256 of case JSON definition
- `expected_status`: `"PASS"` | `"INCONCLUSIVE"`
- `oracle_verdict`: Structured verdict from clean-room `oracle.py`
- `oracle_state_hash`: SHA-256 of expected canonical state dictionary
