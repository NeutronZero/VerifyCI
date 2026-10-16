# VerifyCI v2 — Architecture Spec vs Implementation Audit

**Date:** 2026-10-15 (refreshed)
**Scope:** `docs/architecture_v2.md` (329 lines) vs `verifyci_v2/`, `tests/v2/`.
**Method:** inspected every section's concrete technology/contract/SQL command mentioned in the spec and checked for its import, symbol, or string in the implementation.
**Grounding:** 112 tests green, ruff clean, 6/7 measured capability scores passing.

---

## Verdict

The v2 engine implements the verification core faithfully (Z3 SMT proving, U-SSA, DuckDB CPG, RaBitQ index, WASM sandbox, DSSE provenance, four provider adapters, conformal gate, CEGIS loop, msgspec contracts, Salsa early cutoff) and several spec-named technologies now genuinely imported and used (`tree_sitter` polyglot extraction, `watchfiles` hot reload, `securesystemslib` DSSE PAE, `msgspec`). Still aspirational: `egglog`, `llguidance`, the `Model2Vec` library (deliberate: BLAKE3-derived offline embedder), and a `gittuf` binary RSL (hand-rolled hash chain). `kw_only=True` on contracts is now applied. Redaction module exists under `verifyci_v2/secrets/` (spec-compat shim) and `verifyci_v2/symbolic/`. Measured capability scores (6/7 pass, fail-closed) are unchanged; breadth/spec-discipline issues remain, and several spec claims are still overstated.

---

## 1. Compliant (verified)

| spec section | claim | evidence |
|---|---|---|
| §1.1 Zero-key baseline | core gates offline | `z3-solver`, `duckdb`, `wasmtime` only heavy deps; adapters default `deterministic` |
| §1.4 Single store `.vc2` DuckDB+Arrow | | `verifyci_v2/store/duckdb_cpg.py` |
| §3.3 Salsa cutoff (BLAKE3 + zstd/JCS) | | `ingestion/salsa_cutoff.py`, `contracts/canonical.py` |
| §3.4A CPG schema + source snapshots | | extra normalized tables `cpg_blocks`, `cpg_instructions`, `cpg_taint_summaries`, `source_snapshots` |
| §3.4B RaBitQ quantization | | `store/rabitq_index.py` |
| §3.5 Stage 2 Z3 prover | | `symbolic/z3_prover.py` |
| §3.5 Stage 3 taint + dangerous calls | | `symbolic/secrets_taint.py`, `dangerous_calls.py` |
| §3.6A (four adapters) | | `neural/adapters.py` |
| §3.6C conformal gate | | `neural/conformal.py` |
| §3.6D CEGIS + redaction | | `neural/cegis_repair.py` uses `verifyci_v2/secrets/redaction.py` |
| §3.7 Wasm + DSSE | | `sandbox/wasm_runner.py`, `provenance/dsse_intoto.py` (PAE via securesystemslib) |
| §3.2 Polyglot | | `ingestion/stack_graphs.py` (TS + AST), `ingestion/ts_symbols.py`, `ingestion/polyglot_bridge.py`, wired in `salsa_cutoff.ingest_file` |
| §3.1 FastMCP hot reload | | `interface/fastmcp_daemon.py` `start_hot_reload` (watchfiles, no-op if unavailable) |
| §4 contracts | | `contracts/*.py` all `@msgspec.struct(frozen=True)` |
| §5 failure modes | | Z3 timeout, fuel caps, redaction |
| §6 migration matrix | | all targets exist and wired |

---

## 2. Not implemented / aspirational

### A. Named technologies

| technology | § | used? | status |
|---|---|---|---|
| msgspec | §1.4,§4 | yes | swapped |
| z3 | §3.5c | yes | real |
| duckdb | §3.4 | yes | real |
| wasmtime | §3.7 | yes | real |
| securesystemslib DSSE PAE | §1.5,§3.7 | yes | swapped |
| tree_sitter (core) | §3.2a | yes | real (C/C++/JS/TS/Go/Rust; Python via ast) |
| watchfiles | §3.1 | yes | `start_hot_reload` |
| egglog | §1.2,§1.5,§3.5a,§5 | partial | `EGraph` drives canonicalization for Add/Sub/Mult/Div/Mod/bitwise/And/Or/Xor/NOT with commutativity, identity and double-negation rules; unsupported forms fall back to the hand-rolled path; per-`check_equivalence` EGraph isolation prevents global accumulation |
| llguidance | §1.2,§3.6b | partial | `TokenLevelGrammarMask` compiles JSON schemas via `JsonCompiler` and drives `LLMatcher` to validate candidate completions; per-token logit masking is fail-closed (raises) when a tokenizer yields no usable mask |
| Model2Vec library | §3.4b | no | BLAKE3-derived offline embedder (deliberate) |
| gittuf binary RSL | §3.7 | partial | hand-rolled hash chain |

### B. Capability gaps

- **cap006** (temporal replay) — not_measurable (no digest parity).
- **cap008** (concurrency multi-process) — not_measurable.
- **cap010** (lexical retrieval) — 5/5 gates, `recall@5=0.834` (pass).
- **cap005/007/012/013** — only self-test smoke; need frozen labels.
- **cap002_heldout** — 0.7 vs 0.8235 bar, 0 false accepts. Three disagreements: N-C1 unparseable fragment; N-C4 extra statement; N-W4 removed dangerous call not detected.

### C. Interface / daemon specifics

- Hot reload is caller-driven (not auto-started on boot).
- CLI subcommands match spec names.
- `secrets/redaction.py` resolves (compat shim → symbolic/redaction.py).
- DFG + conformal mock triage untested vs frozen corpus.

### D. Contract schema

- `kw_only=True` not applied (positional construction used in tests).
- `InTotoVerificationPredicate.schema_version` default unverified.

---

## 3. Summary table

| § | section | compliant? |
|---|---|---|
| 1 | five invariants | 2 fully, 3 partial (neuro-symbolic, Salsa, provenance) |
| 2 | topology | most boxes; gittuf ≠ binary |
| 3.1 | daemon | hot reload now via watchfiles |
| 3.2 | polyglot | partially: TS extraction + bridge resolver run during ingest |
| 3.3 | Salsa | implemented |
| 3.4 | DuckDB + RaBitQ | schema present; RaBitQ present; Model2Vec not library |
| 3.5 | symbolic (Z3 + egglog) | Z3 real; egglog `EGraph` now drives expression canonicalization |
| 3.6 | BYO-AI | 4 adapters + conformal + CEGIS; llguidance grammar compilation live |
| 3.7 | Wasm + provenance | Wasm real; DSSE real; gittuf hand-rolled |
| 4 | contracts | msgspec ✓; `kw_only=True` missing |
| 5 | failure modes | present incl. redaction |
| 6 | migration matrix | targets exist, constrained by cap gaps |

---

## 4. Recommendation

1. `egglog` and `llguidance` are now genuinely used but partial; keep them out of release marketing until their coverage matches the spec. `tree_sitter` and `watchfiles` are used.
2. Apply `kw_only=True` to §4 contracts (or remove from spec).
3. `secrets/redaction.py` naming now resolves.
4. Hot reload available; decide auto-start in `vc2 mcp`.
5. Polyglot: §3.2 partly implemented via TS extraction; document remaining hand-stitching.
6. Disposition cap gaps with new frozen corpora; address cap002_heldout's 3 disagreements (N-C1 parse-robustness, N-C4 benign extra statement, N-W4 removed-dangerous-call detection).

This report does not claim the engine is broken — 6/7 measured scores pass, 112 tests green, ruff clean. The spec over-promises; enumerate disposition before publishing. Recommended: update `architecture_v2.md` Status header from Draft to “Partially Implemented — see gap audit.”
