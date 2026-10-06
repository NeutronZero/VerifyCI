# CAP-001 rerank result — PROMOTION REQUEST (decision: reviewer)

## Measurement (accepted experiment, all gates passed)

| arm | nDCG@10 |
|---|---|
| D0 frozen nomic dense (recomputed, exact) | 0.6220 |
| H0 frozen hybrid (recomputed, exact) | 0.6603 |
| H1 H0 top-20 + MS-MARCO cross-encoder rerank to top-10 | 0.7104 |
| D1 MiniLM dense (diagnostic only) | 0.6993 |
| H2 MiniLM hybrid + rerank (diagnostic only) | 0.7254 |

- H1−D0 = +0.0884, margin +0.0384 over gate (10x the Q5 minimum).
- Halves: A +0.1186, B +0.0583 — both independently above +0.05.
- Rerank lift over frozen hybrid: +0.0500 (> +0.01, not tiebreak noise).
- No tuning: depth 20 fixed a priori; no weights swept in this experiment.
- Method: TEMP cap001_rerank.py; frozen tree untouched; offline caches only.

## Production-parity probe (TEMP cap001_parity.py) — DRIFT FOUND, analyzed

Routing the same pairs through production `CrossEncoderReranker` yields
+0.0921, not +0.0884 (drift +0.0037). Two production quirks isolated:

1. **Doc-id prefix**: `rerank()` scores `f"{id} {text}"`, prepending the
   document id to the cross-encoder input. The experiment scores clean
   `(query, doc_text)` pairs. Id-prefixing shifts scores unpredictably.
2. **Stable sort, no docid tiebreak**: production relies on sort stability
   (insertion order) where the gate determinism rule requires
   `(-score, docid)` tiebreaks.

Neither quirk is exploited or hidden: the accepted +0.0884 uses clean
pairs + docid tiebreak, documented here. The quirks are product issues
for separate review — this experiment does NOT change production code,
and promotion must NOT route the harness through the production class
until the quirks are reviewed.

## Promotion mechanics proposed (blast precedent)

1. New harness revision measuring reranked hybrid with the exact
   experiment mechanics (clean pairs, docid tiebreak, depth 20,
   model `cross-encoder/ms-marco-MiniLM-L-6-v2` recorded with hash).
2. `results.json` replaced (dense condition byte-identical: same
   embeddings, 0.6220), `config.json` review note (rerank stage,
   model, depth, tiebreak, cache provenance).
3. Bundle re-verification via canonical predicate; guard tests updated
   with review references (as CAP-003 did for blast).
4. Production default change (real CE backend) explicitly OUT OF SCOPE
   for this promotion; separate product decision with its own tests.

## Verdict requested

H1 ESTABLISHED on the rerank revision, or HOLD for further review.
Frozen v1 preserved in git history either way.
