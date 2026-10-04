# VerifyCI: Master Audit, Grounded Defect Inventory & Phase 1 Execution Plan (v8 — Locked, No External Code)

Phase 2 is new code written from scratch inside VerifyCI. No code is copied from graphify or any other project; external projects are referenced for design patterns only and produce no attribution obligations.

**Final Fully Grounded Pre-Implementation Blueprint**
*Repository*: VerifyCI (`c:\Projects\verifyci`)
*Pinned Git Baseline*: Commit [`451b551`](file:///c:/Projects/verifyci)
*Test Suite Baseline*: **903 passed, 3 skipped in 53.8s**
*Cross-System Reference*: Graphify (`C:\Projects\graphify`) (design patterns reference only)

---

## 1. Architectural Invariants & Pinned Implementation Specifications

### 1.1 S-01: Bitemporal Interval Immutability & Migration Engine
- **Composite Primary Key**: `PRIMARY KEY (revision_entity_id, valid_from)` on `entities` table. `edges` table remains single-PK (as edge IDs embed the revision prefix by construction).
- **Migration Caveat**: Forward-compatible only. Pre-existing databases with previously reset `valid_until = NULL` copy stored values verbatim. Pristine historical audits require clean re-ingest (`verifyci ingest --rebuild`).
- **`_migrate_v0_to_v1` is a no-op**: The v0 schema (at baseline `451b551`) is the pre-composite-key schema. `_migrate_v0_to_v1` must exist as a stub that does nothing and does **not** bump `user_version`, so the subsequent `if v < 2` fires and runs the v2 migration.
- **Fresh vs. Legacy DB Detection**:
  ```python
  def init_or_migrate(conn: sqlite3.Connection) -> None:
      table_exists = conn.execute(
          "SELECT 1 FROM sqlite_master WHERE type='table' AND name='entities'"
      ).fetchone() is not None

      if not table_exists:
          # Fresh database: create v2 schema directly and set user_version = 2
          _create_v2_schema(conn)
          conn.execute("PRAGMA user_version = 2;")
          return

      v = conn.execute("PRAGMA user_version").fetchone()[0]
      if v < 1:
          _migrate_v0_to_v1(conn)
      if v < 2:
          _migrate_v1_to_v2(conn)
  ```
- **Transaction & Isolation Level Safety**:
  Python's default `isolation_level=""` raises `OperationalError` on explicit `BEGIN TRANSACTION`.
  ```python
  def _migrate_v1_to_v2(conn: sqlite3.Connection) -> None:
      old_isolation = conn.isolation_level
      conn.isolation_level = None  # Autocommit mode for explicit transaction control
      conn.execute("PRAGMA foreign_keys = OFF;")
      conn.execute("BEGIN TRANSACTION;")
      try:
          conn.execute("""
              CREATE TABLE entities_v2 (
                  revision_entity_id TEXT NOT NULL,
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
                  valid_from REAL NOT NULL,
                  valid_until REAL,
                  t_created REAL,
                  t_expired REAL,
                  metadata_json TEXT,
                  properties_json TEXT,
                  PRIMARY KEY (revision_entity_id, valid_from),
                  FOREIGN KEY (revision_id) REFERENCES revisions(revision_id)
              );
          """)
          conn.execute("INSERT INTO entities_v2 SELECT * FROM entities;")
          conn.execute("DROP TABLE entities;")
          conn.execute("ALTER TABLE entities_v2 RENAME TO entities;")
          conn.execute("CREATE INDEX idx_entities_logical ON entities(logical_entity_id);")
          conn.execute("CREATE INDEX idx_entities_logical_valid ON entities(logical_entity_id, valid_from, valid_until);")
          conn.execute("CREATE INDEX idx_entities_revision ON entities(revision_id);")
          conn.execute("CREATE INDEX idx_entities_path ON entities(file_path);")
          conn.execute("CREATE INDEX idx_entities_name ON entities(name);")
          conn.execute("PRAGMA user_version = 2;")
          conn.execute("COMMIT;")
      except Exception:
          conn.execute("ROLLBACK;")
          raise
      finally:
          conn.execute("PRAGMA foreign_keys = ON;")
          conn.isolation_level = old_isolation
  ```
- **Defensive Invariant Assertion (Post-Ingest)**:
  At the conclusion of `run_ingest`, execute defensive integrity check:
  ```sql
  SELECT logical_entity_id, COUNT(*) FROM entities
  WHERE valid_until IS NULL
  GROUP BY logical_entity_id HAVING COUNT(*) > 1
  ```
  If any row returns, raise `InfraError("Multiple live intervals detected for logical entity")` before commit.

---

### 1.2 I-01: FastMCP Dual-Store Architecture
- **Boundary Guarantee**:
  - `ro_store = GraphStore(db, read_only=True)` bound to observation tools (`code_search`, `graph_query`, `stats`, `verify_diff`).
  - `rw_store = GraphStore(db, read_only=False)` bound strictly to task context (`context["store"] = rw_store` for `task_run`).
- **Defensive Safeguard**:
  In `scheduler.py:_persist()`, if write operations ever encounter an operational error, set `task["audit_degraded"] = True` and emit a structured log warning to stderr rather than dumping tracebacks.

---

### 1.3 G-01 & G-02: AST Decorator Spans, C/C++ Signatures & Property Accessors
- **Shared Parents Map in `extract_entities`**:
  Build `parents = {}` once at the top of `extract_entities(parsed)` by walking the AST:
  ```python
  parents = {}
  for node in _walk(root):
      for child in node.children:
          parents[_node_key(child)] = node
  ```
- **G-01 (Decorator Span)**:
  If a function/class node's parent is `decorated_definition`, set `line_start = parent.start_point[0] + 1`.
- **G-02 (C/C++ Parameter Type Canonicalization)**:
  Implement `_extract_param_types(node, source)` returning normalized types in declaration order:
  - Spacing around pointers normalized (`int *` $\to$ `int*`).
  - Const placement normalized (`int const*` $\to$ `const int*`).
  - Pointers vs references preserved (`int*` $\ne$ `int&`).
  - **Parameter names strictly excluded**.
  - **C empty-parameter-list normalization**: In `_extract_param_types`, `void f(void)` and `void f()` must produce the same signature (zero parameter types). If the parameter list is exactly one `void` type with no identifier, treat it as empty.
  - **C++ templates are out of scope for Phase 1**: Template argument extraction (`std::vector<int>` vs `std::vector<double>`) is V1.2. Phase 1 disambiguates non-template overloads only. Templates inherit the previous under-disambiguation and are documented as a known limitation.
  - **Two-layer test contract**:
    1. Identity level: `compute_logical_entity_id("r","f.py","n",T,"") == compute_logical_entity_id("r","f.py","n",T,"",signature="")`.
    2. Extractor level: two C snippets with `void f(int x)` and `void f(int y)` yield the same `logical_entity_id`; `void f(int x)` and `void f(double x)` yield different IDs.
- **G-02 (Property Accessor Disambiguation)**:
  Inspect decorator node text on `decorated_definition`:
  - Capped strictly to `@property` (`accessor="getter"`), `@<name>.setter` (`accessor="setter"`), `@<name>.deleter` (`accessor="deleter"`).
  - Store `metadata["accessor"] = accessor`, and append `:getter` / `:setter` to the scope/name.
- **Python Function Continuity**:
  Python function entity IDs exclude parameter signatures, preserving cross-revision continuity and `carry_forward` semantics on parameter edits.

---

### 1.4 Phase 2 Quality Gate & Frozen Reference Set
This section specifies the Phase 2 gate. Phase 2 is not part of this commit sequence; the gate is recorded here so its criteria are pinned before Phase 2 work begins.
- **Corpora Selection**:
  - Primary TS Corpus: **`vercel/swr`** (pinned commit SHA) for deep intra-repo call graphs.
  - Secondary JS Corpus: **`sindresorhus/got`** (pinned commit SHA) for JavaScript coverage.
- **Frozen Reference Specification**:
  - Pre-authored from source **before** extractor code is written.
  - 20 TS call sites across 5 modules in `vercel/swr`.
  - 5 JS call sites in `sindresorhus/got`.
  - Frozen at `tests/fixtures/ts_reference_set_v1.json` with SHA-256 hash committed into version control.
- **Two-Tier Gate**:
  - **Halt Floor**: $\ge 10\%$ aggregate cross-file resolution on reference repo.
  - **Acceptance Bar**: $\ge 70\%$ (14/20) on TS reference set AND $\ge 80\%$ (4/5) on JS reference set.

---

### 1.5 Diagnostic Code Ordering, Configuration Precedence & New Internal Utilities
- **Deterministic Ordering**:
  `file_path` (lexicographical) $\to$ `line_number` (ascending) $\to$ `code` (lexicographical).
- **New Internal Utilities**:
  Write from scratch inside `verifyci/`: `validate.py` (schema check for VerifyCI's entity/edge contracts), `diagnostics.py` (dangling/missing/self-loop/duplicate edge counts), `atomic.py` (tmp-write + `os.replace`), `querylog.py` (append-only JSONL query log), `file_slice.py` (char-range split at `\n#` → `\n\n` → `\n` for oversized snippets). No code, comments, or identifiers are copied from any external project; graphify may be read as a reference for the pattern only.
- **Configuration Precedence**:
  1. CLI `--config <path>`
  2. Root `verifyci.toml`
  3. `[tool.verifyci]` in `pyproject.toml`
  4. Legacy `<repo>/.verifyci/invariants.yaml`

---

## 2. Realigned Commit Sequence

```
Commit 1 (Phase 1): fix: audit-confirmed defects (phase 1)
├── S-01: Composite key (revision_entity_id, valid_from), fresh/legacy user_version dispatch, isolation_level=None
├── I-01: FastMCP dual-store architecture (RO tools, RW task persist) + degraded audit flag
├── G-01: Entity span calculation inherits parent @decorator lines via shared parents map
├── G-02: Overload disambiguation (C/C++ canonical types-only, property accessors, Python continuity)
├── I-02: Add db: str = "" to VerifyRequest in HTTP API (/verify/diff)
├── I-10: Await scheduler.cancel(task_id) on execution timeout
├── I-05: Exit code 3 (INFRA_ERROR) on missing repo in verifyci ingest
├── V-01: Reorder high-signal credential regexes above raw-string carve-out
├── V-04: Parameter continuity for optional/default params in deletion checks
├── V-06: Path normalization in evidence_verifier.py
└── Post-Ingest Invariant: Assert at most one live interval per logical_entity_id

Commit 2 (Phase 1): policy: tighten waiver matching to exact qualified targets (V-11)
└── Change deletion waiver matching from loose line substring t in gl to exact target/file
```

---

## 3. Phase 2 (Separate Plan)

Phase 2 work is new code written from scratch inside VerifyCI and will have its own commit plan.

## License note

Phase 1 introduced no third-party code. Phase 2 is clean-room per §1.5 (patterns only, no copied code, comments, or identifiers). No attribution obligations arise from either. If a future change inlines external code, reintroduce the third-party checklist (LICENSE/NOTICE/SPDX/provenance headers, distribution packaging, SBOM entry) before that commit.
