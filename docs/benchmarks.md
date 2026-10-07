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
| **CAP006: Temporal** | `benchmarks/temporal_corpus/cap006/` | Pinned manifest | 64 cases | Lineage replay attestation & truncated-lineage tripwires |
| **CAP007: Scale** | `benchmarks/retrieval_corpus/cap007/` | Pinned manifest | 64 cases | 174,779 nodes / 165,570 edges topology retrieval |
| **CAP008: Concurrency**| `benchmarks/concurrency_corpus/cap008/` | Pinned manifest | 64 cases | Multi-process worker contention & SQLite WAL locks |

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
pytest tests/evaluation/ tests/performance/ -q
```

### 2. Run Re-Measure Guards
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
