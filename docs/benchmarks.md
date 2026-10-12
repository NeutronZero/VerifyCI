# VerifyCI Benchmarks & Evidence Reproduction

VerifyCI treats verification claims as empirical, reproducible hypotheses. All benchmark datasets, query sets, and ground-truth labels are permanently frozen and pinned by cryptographic SHA-256 digests.

---

## Benchmark Corpus Catalog

| Benchmark | Directory | Frozen Digest (SHA-256 prefix) | Cases | Scope |
|---|---|---|---|---|
| **B1: Invariants** | `tests/evaluation/labels/invariants_v2.jsonl` | `e17d65878ccc5330` | 26 cases | Secret patterns, entropy floors, forbidden calls/imports |
| **B2: BEIR Retrieval** | `benchmarks/beir/` | `cac3aa9750f2e6b8` (corpus)<br>`b1debc8b40663c9b` (qrels) | 62 queries<br>60 docs | Hybrid BM25 + dense retrieval vs dense-only |
| **C1: Patch Corpus** | `benchmarks/patch_corpus/cases.jsonl` | `5ff5ab1b4d075559` | 17 cases | Deterministic vs semantic agent wrong-patch detection |
| **C2: Blast Radius** | `benchmarks/blast_corpus/cases.jsonl` | `efbf6b4e12e62fd1` | 9 cases | Multi-hop call graph impact and tail-insertion geometry |
| **C3: Latency** | `benchmarks/latency/config.json` | `efc6451e97f6fc65` | 1,000 samples | Incremental AST re-parse and temporal query latency |
| **CAP-002B: Secrets** | `benchmarks/secret_corpus/cap002b/` | `b6c7df17e334f684` | 35 cases | Multi-signal secret detection and redaction |
| **CAP-003A: Removal** | `benchmarks/removal_corpus/cap003a/` | `51a09c91d27d23af` | 36 cases | Removal provenance verification and fabricated removal detection |
| **CAP-004: Call Semantics** | `benchmarks/call_semantics_corpus/cap004/` | `305da66ef4282c75` | 36 cases | Argument-value and call-semantics verification |
| **CAP-005: Generalization** | `benchmarks/patch_real/cap005/` | `ca475b33a385e8d1` | 64 cases | Real-world multi-language patch generalization |
| **CAP006: Temporal** | `benchmarks/temporal_corpus/cap006/` | Pinned manifest | 64 cases | Lineage replay attestation & truncated-lineage tripwires |
| **CAP007: Scale** | `benchmarks/retrieval_corpus/cap007/` | Pinned manifest | 64 cases | 174,779 nodes / 165,570 edges topology retrieval |
| **CAP008: Concurrency**| `benchmarks/concurrency_corpus/cap008/` | Pinned manifest | 64 cases | Multi-process worker contention & SQLite WAL locks |
| **CAP-009: Diff-to-Impact** | `benchmarks/diff_impact_corpus/cap009/` | `f588414156bd2eed` | 225 cases | End-to-end diff-to-impact correctness & rename-collision isolation |
| **CAP-010: Retrieval Gen** | `benchmarks/retrieval_generalization/cap010/` | `a312fe4ee9eea7e1` | 210 queries<br>1,050 docs | Cross-repo generalization, hard negatives & no-answer abstention |
| **CAP-011: Held-out Secrets** | `benchmarks/secret_heldout/cap011/` | `72865e81db5bbd97` | 50 cases | Held-out synthetic secret detection & runtime redaction boundary |
| **CAP-012: Repo Perf** | `benchmarks/repo_perf/cap012/` | Pinned manifest | Multi-tier repos | End-to-end repository performance envelope & memory profiling |
| **CAP-013: Robustness** | `benchmarks/robustness/cap013/` | Pinned seed | 5 critical / 20 fuzz | Differential, property-based fuzzing & mutation accounting |

---

## Evidence Classification Taxonomy

To prevent unjustified claims, VerifyCI categorizes all measured results into four explicit classifications:

1. **Established**: The target threshold and rigorous statistical protocol were satisfied on a statistically representative corpus (e.g., CAP006/CAP008 64/64 agreement, Replay Equivalence 100%, Local-Only zero cloud).
2. **Measured-Met, Not Established**: The measured number meets the target, but the corpus is small or synthetic, meaning the property is demonstrated but not proven universally (e.g., Invariant precision 1.00 on 26 cases).
3. **Measured-Unmet**: The measured number fell below the pre-declared gate. This is explicitly published rather than hidden or retuned (e.g., BEIR hybrid nDCG@10 +3.31 vs +5.0 gate; incremental parse p95 on certain host systems).
4. **Unmeasured**: No ground-truth label set exists (recorded as `null` in metrics, never `0.0`).

---

## Clean-Room Oracles and Isolation

All benchmark evaluations use **clean-room independent oracles**:
- The oracle that computes expected blast radius or lineage replay runs in an isolated harness separate from the production `SemiFormalReasoner` or `GraphRetriever`.
- Tripwires test fail-closed behavior: truncated lineages, corrupt databases, and out-of-order patches must trigger fail-closed rejections or inability, not silent passes.

---

## How to Reproduce Benchmarks Locally

### 1. Run Standard Evidence Suite
Run evaluation and performance reproduction tests:

```bash
pytest tests/evaluation/ tests/performance/ tests/verification/ -q
```

### 2. Run CAP-009 through CAP-013 Reproduction Tests
Run the standalone reproduction tests for newly added benchmark corpora:

```bash
pytest tests/verification/test_diff_impact_cap009.py \
       tests/verification/test_generalization_cap010.py \
       tests/verification/test_secrets_heldout_cap011.py \
       tests/verification/test_repo_perf_cap012.py \
       tests/verification/test_robustness_cap013.py -q
```

### 3. Run Re-Measure Guards
Opt in to full corpus re-execution across all frozen fixtures:

```bash
VERIFYCI_PATCH_RERUN=1 \
VERIFYCI_BLAST_RERUN=1 \
VERIFYCI_LATENCY_RERUN=1 \
pytest tests/evaluation/ -q
```

Each re-measure guard checks that its source fixtures and labels have not drifted from their SHA-256 pins.

### 3. Generate Evidence Bundle
Build the verifiable JSON evidence bundle containing environment details, git commit hashes, and gate results:

```bash
python scripts/build_evidence_bundle.py
```

Output is written to `evidence/evidence-bundle.json`.

---

## Frozen Corpus Protection Policy

- **No Retuning**: Never change a threshold because a test failed.
- **No In-Place Relabeling**: Never edit a label in `cases.jsonl` to turn a miss into a hit.
- **New Investigations**: Any new benchmark experiment must use a new directory (e.g. `benchmarks/patch_real/cap009/`).
