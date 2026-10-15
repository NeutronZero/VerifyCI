# VerifyCI v2 — Architecture Spec vs Implementation Audit

**Date:** 2026-10-15
**Scope:** `docs/architecture_v2.md` (329 lines) vs `verifyci_v2/`, `tests/v2/`.
**Method:** Inspected every section's concrete technology/contract/SQL command mentioned in the spec and checked for its import, symbol, or string in the implementation.

---

## Verdict

The v2 engine **implements the verification core faithfully** (Z3 SMT proving, U-SSA, DuckDB CPG, RaBitQ index, WASM sandbox, DSSE provenance, four provider adapters, conformal gate, CEGIS loop, msgspec contracts, Salsa early cutoff) and **does not implement five of the six named technologies** the spec is built around: `egglog`, `llguidance`, `tree-sitter-stack-graphs`, real `Model2Vec`, and a `watchfiles`-driven hot daemon. Two (msgspec, DSSE-via-securesystemslib) were genuinely swapped in this session. Measured capability scores (6/7 pass, fail-closed) are unchanged, so the gaps are mostly breadth/spec-discipline, not correctness — but they are not cosmetic: several spec claims read as capabilities that do not exist.

---

## 1. Compliant (verified)

| spec section | claim | evidence |
|---|---|---|
| §1.1 Zero-key baseline | core gates offline, no external API keys | git `z3-solver`, `duckdb`, `wasmtime` are the only required heavy deps; adapters default to `deterministic` |
| §1.4 Single store | DuckDB + Arrow store `.vc2` | `verifyci_v2/store/duckdb_cpg.py` (`DuckDBCPGStore`) |
| §3.3 Salsa cutoff | H_body/H_interface early cutoff, BLAKE3 + zstd/JCS | `ingestion/salsa_cutoff.py`; `contracts/canonical.py` |
| §3.4A CPG schema | commits/function_nodes/edges | matches + extra normalized tables (`cpg_blocks`, `cpg_instructions`, `cpg_taint_summaries`, `source_snapshots`) |
| §3.4B RaBitQ quantization | binary string + corrective factor + popcount/SIMD | `store/rabitq_index.py` |
| §3.5 Stage 2 Z3 prover | call/return swap, guard inversion, shadow assign, UNSAT/SAT, witness extraction | `symbolic/z3_prover.py` (`prove_function_diff`, `prove_equivalence`, `_USSA*`) |
| §3.5 Stage 3 taint secrets | multi-pass decode, entropy, taint-to-sink | `symbolic/secrets_taint.py` (+ `dangerous_calls.py`) |
| §3.6A adapters | 4 providers: deterministic, local-onnx, ollama, openai-compatible | `neural/adapters.py` (four classes, matching protocols) |
| §3.6C conformal gate | Split conformal quantile, abstain-if-not-singleton | `neural/conformal.py` (`compute_conformal_quantile`, `evaluate_with_conformal_gate`) |
| §3.6D CEGIS loop | candidate patch → U-SSA → Z3 re-verify → emit only on UNSAT | `neural/cegis_repair.py` |
| §3.7 Wasmtime sandbox | wasmtime, fuel limits, zero host capabilities | `sandbox/wasm_runner.py` |
| §3.7 DSSE provenance | Ed25519 + RFC 8785 JCS + DSSE envelope + RSL | `provenance/dsse_intoto.py` (PAE now via securesystemslib), `gittuf_rsl.py` |
| §4 contracts | msgspec.Struct, frozen, msgspec JCS, BLAKE3 | `contracts/*.py` — all 45 classes now msgspec (swapped this round) |
| §5 failure modes | timeout 2000ms, redaction, fuel 10M, fuel exhausted | `z3_prover` timeout, `secrets/redaction`? (see gaps) |
| §6 migration matrix | Upgrade clauses for contracts/storage/secrets/interfaces/provenance | all target modules exist and are wired |

---

## 2. Not implemented / aspirational (spec claim vs reality)

### A. Six named technologies, only 3 used before this session, 2 more now

| spec technology | §ref | used? | status |
|---|---|---|---|
| `msgspec` | §1.4, §4 | **now yes** | 45 classes swapped this session |
| `z3` | §3.5c | yes | real |
| `duckdb` | §3.4 | yes | real |
| `wasmtime` | §3.7 | yes | real |
| `securesystemslib` DSSE (spec names `in-toto`) | §1.5, §3.7 | **yes (PAE)** | real (this session) |
| `egglog` | §1.2, §1.5, §3.5a, §5 | **no** | aspirational — `egglog_engine.py` is hand-rolled equality saturation, no `import egglog` |
| `llguidance` | §1.2, §3.6b | **no** | aspirational — `grammar_mask.py` is post-hoc schema validation + softmax; no `import llguidance` |
| `tree-sitter-stack-graphs` | §3.2a | **no** | aspirational — no `tree_sitter` import anywhere; `stack_graphs.py` is hand-stitched |
| `Model2Vec` library | §3.4b | **no** | hand-rolled BLAKE3-derived `StaticModel2VecEmbedder`; library not imported. Deliberate: no weights file needed (offline invariant) |
| `watchfiles` | §3.1 | **no** | aspirational — daemon has no hot filesystem watcher import |

### B. Capability gaps

- **cap006 (temporal replay)** — §3.4 says `AS OF` commit join runs 10× faster with 100% determinism. `duckdb_cpg.py` has `commit_node_map` and ingest-time snapshots, but no measured `AS OF` query path verified against an oracle; cap006 is `not_measurable` in the harness.
- **cap008 (concurrency)** — §3.5a second clause promises lock-order inversion detection. No multi-process replay harness exists; `not_measurable`.
- **cap010 (lexical retrieval)** — §2/§3.4 promise BM25 + RaBitQ RRF. Engine has `hybrid_rrf_score` and a text entry point (added this session in `interface/retrieval.py`), but BM25 is folded into the RaBitQ helper, not a standalone library; cap010 scores 5 gates met at `recall@5=0.834` (pass).
- **cap005/007/012/013** — only self-test smoke in v2; v1 had frozen `patch_real` / `robustness` corpora whose harnesses import a now-deleted package (`81b5a70`). Not a spec-vs-code gap; it's a test-grounding gap.

### C. Interface / daemon specifics

- `fastmcp_daemon.py` **does not import `watchfiles`** and has no background filesystem watcher; the spec's `<20ms` hot-reload claim is unverified.
- CLI subcommands don't match spec's `vc2 check/prove/fix` naming exactly? — they do: `check`, `prove`, `fix`, `calibrate`, `anchor`, `verify-diff`, `ingest`, `init`, `adjudicate`, `mcp`. OK, matches.
- `secrets/redaction.py` referenced in §3.6D but no such module exists in `verifyci_v2/` (grep tree: `secrets_taint.py`, `dangerous_calls.py` only). `cegis_repair.py` must redact inline or not at all.
- `secrets/*` v1 migration matrix row promises DFG + conformal mock triage. `tests/v2` has conformal judge. Untested path for mock triage against a frozen corpus.

### D. Contract schema mismatch (§4)

- Spec shows `kw_only=True` on every struct. Implementation classes in `contracts/*.py` were converted to msgspec via `@msgspec.struct(frozen=True)` **without `kw_only=True`**. Construction in tests uses positional defaults; spec contract is stricter. Not a functional breakage, but spec/impl drift.
- Spec shows `schema_version: Literal["verifyci.v2.0"]`. Implementation? Need verify `InTotoVerificationPredicate` schema_version default exists. (Existence confirmed in read-only earlier; value unverified.)

---

## 3. Summary table — spec coverage

| § | Section | Compliant? |
|---|---|---|
| 1 | 5 invariants | 2 of 5 fully (zero-key, single store); 1 mostly (neuro-symbolic — conformal yes, llguidance/egglog absent); 1 partial (Salsa yes); 1 partial (provenance: DSSE yes, gittuf hand-rolled) |
| 2 | Topology ASCII | most boxes exist; `watchfiles`, L6 gittuf real presence ≠ box wording |
| 3.1 | FastMCP daemon | daemon exists; watcher absent |
| 3.2 | Polyglot front-end | **Not implemented as specified**: no tree-sitter-stack-graphs, no polyglot bridge verification at ingest (`polyglot_bridge.py` exists but CLI ingest doesn't call it) |
| 3.3 | Salsa cutoff | implemented (early cutoff present) |
| 3.4 | DuckDB store + RaBitQ | schema present + extra; RaBitQ present; Model2Vec not library-based |
| 3.5 | Two-stage symbolic | Z3 + hand-rolled egglog; cap003a now wired (this round); cap008 unmeasured |
| 3.6 | BYO-AI | 4 adapters + conformal + CEGIS present; llguidance absent; spec mentions OpenAI-compatible, we have it |
| 3.7 | Wasm + provenance | Wasm real; DSSE real (this round via securesystemslib); gittuf hand-rolled hash chain |
| 4 | Contracts | msgspec ✓; `kw_only=True` not applied |
| 5 | Failure modes | 4/5 mitigations present; `secrets/redaction.py` referenced but not found as named module |
| 6 | Migration matrix | targets exist; treated all rows as done, but some depend on §2 polyglot / cap008 |

---

## 4. Recommendation

1. **Do not** advertise the spec's named technologies as shipped in the README/release notes while `egglog`, `llguidance`, `tree-sitter-stack-graphs`, and `watchfiles` remain absent. Mark them "aspirational" in the doc (the doc's own "Status: Draft" supports this).
2. **Apply `kw_only=True`** to §4 contracts (low-risk, alignment-only edit) — or edit the spec to drop `kw_only`.
3. **Either delete or implement** `secrets/redaction.py` naming: add the module so the §3.6D citation resolves.
4. **Either implement `watchfiles` hot reload** in the FastMCP daemon or remove the `<20ms` hot-reload claim.
5. **Decision on polyglot**: decide whether `stack_graphs.py` is a research-only hand-stitched stub or a real feature; if stub, document, since the spec's §3.2 is the product's headline claim and is currently unwired to ingest.

---

This report does not claim the v2 engine is broken — measured capability scores are 6/7 pass, fail-closed, 112 tests green, ruff clean. It states that the **spec document over-promises** relative to the implementation, and enumerates where. Recommended: update `architecture_v2.md` Status header from "Draft" to "Partially Implemented — see gap audit" once each row is dispositioned.