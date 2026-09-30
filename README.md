# VerifyCI

**Every agent action verified before human review.**

VerifyCI is a verification-first code intelligence platform: project code is
parsed into a bitemporal code-property graph, agent diffs are mapped onto that
graph, and a deterministic policy decides `PASS` / `FAIL` / `HUMAN_REVIEW` /
`INCONCLUSIVE`. LLMs may propose — only deterministic checks establish
verification.

## Quickstart

```bash
pip install -e ".[dev]"
verifyci init ./repo
verifyci ingest ./repo
verifyci stats
verifyci query "where is auth?"
verifyci verify-diff "$(git diff)" --db ./repo/.verifyci/verifyci.db
verifyci run "ship it" --diff "$(git diff)" --db ./repo/.verifyci/verifyci.db
verifyci serve --db ./repo/.verifyci/verifyci.db   # MCP over stdio (or http)
```

`verifyci` is the primary command; the legacy `aci` console script is a
kept alias for the same app, and environment variables read
`VERIFYCI_*` first with `ACI_*` as fallback.

## How verification works

```
diff --git a/src/app.py ...
  ↓  parse_diff_files → map onto graph entities (diffmap)
premises (per changed file) → traces (call-flow paths from changed entities)
  → evidence (file + lines + source hash) → deterministic checks
  → Certificate → PolicyEvaluator → Decision
```

Grounding rules (no exceptions):

- A diff naming no files, or only files absent from the graph, is
  `INCONCLUSIVE` — never `PASS`. Every named file must ground,
  regardless of extension: a clean `.py` hunk does not launder
  unverified content (`Dockerfile`, CI workflows, `.env`) in the same
  diff into a `PASS`. Stated plainly: `PASS` means every file in the
  diff was something the graph could reason about, so routine commits
  touching docs or config alongside code read `INCONCLUSIVE`
  (declined, routed to human review — not blocked) rather than `PASS`.
- Every `-` line must have existed where claimed: removed lines are
  checked against stored base-revision snippets at the hunk's old-side
  offsets. A removal contradicting the stored record is `FAIL`
  (stale, hallucinated, or forged diff). Verified removals of known
  code stay `INCONCLUSIVE` (behavior not verified); removals outside
  entity spans or inside truncated snippets are inability
  (`INCONCLUSIVE`), never `PASS` — so comment-only edits decline
  rather than verify.
- `certificate_verified` requires every deterministic check passed, plus
  non-empty traces and evidence.
- Invariant checkers fail closed: `secrets_scan`, `provenance_check`,
  `forbid_call:<name>`, `forbid_import:<module>`. Unknown queries fail.
  `secrets_scan` covers quoted assignments, long unquoted values, AWS
  keys, PEM blocks, JWTs, and credentialed URLs — measured recall 5/9
  on the labeled set, not a general leak detector.
- V1 proves **provenance and impact**, not semantic intent: a mapped,
  secret-free diff verifies structurally. Intent judgment stays with policy
  reviewers and project-specific invariants. A PASS means "grounds in known
  entities and trips no invariant" — not "correct". Ordinary human code
  rarely trips the gate (3 PASS / 2 INCONCLUSIVE / 0 FAIL on the last 5
  Flask commits; the two INCONCLUSIVE are an empty merge and a mixed
  changelog diff, both honestly ungroundable);
  subtly-wrong agent patches, the population this exists for, are untested.

## Architecture

```
interface (MCP / CLI / HTTP) → verification (semi-formal, blast, invariants, policy)
→ orchestration (planner → TaskIR → AsyncDAGScheduler, pre-commit gates)
→ retrieval (dense + BM25 + graph → RRF → [rerank: experimental, default off] → EvidencePack)
→ graph (AST CPG, bitemporal, anchor+delta) → storage (SQLite)
```

Rerank is marked experimental until it beats fused ranking on a held-out
set (measured 2 lifts / 4 demotions so far). Dense defaults to offline
hash embeddings (deterministic, no server); `VERIFYCI_EMBEDDINGS=ollama[:model]` (legacy `ACI_EMBEDDINGS`)
opts into local Ollama embeddings behind a content-addressed cache, with
honest fallback to hash when the server is unreachable. Measured on a
small 5+5 query set (`benchmarks/embedding_eval.py`, needs a live server):
ollama beats hash on all four cells (recall +0.10, ndcg +0.02–0.06),
directional not gating; CPU inference runs ~50ms/doc, so the cache —
not the model — is what makes it usable.

## Status

V1 walking skeleton. `PLAN.md` is the full plan; `CHANGELOG.md` records what
each revision proved, including measured numbers and known gaps. 476 tests:
`python -m pytest tests/ -q`.
