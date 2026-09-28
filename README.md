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
aci init ./repo
aci ingest ./repo
aci stats
aci query "where is auth?"
aci verify-diff "$(git diff)" --db ./repo/.verifyci/verifyci.db
aci run "ship it" --diff "$(git diff)" --db ./repo/.verifyci/verifyci.db
aci serve --db ./repo/.verifyci/verifyci.db   # MCP over stdio (or http)
```

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
  `INCONCLUSIVE` — never `PASS`.
- `certificate_verified` requires every deterministic check passed, plus
  non-empty traces and evidence.
- Invariant checkers fail closed: `secrets_scan`, `provenance_check`,
  `forbid_call:<name>`, `forbid_import:<module>`. Unknown queries fail.
- V1 proves **provenance and impact**, not semantic intent: a mapped,
  secret-free diff verifies structurally. Intent judgment stays with policy
  reviewers and project-specific invariants. A PASS means "grounds in known
  entities and trips no invariant" — not "correct". Ordinary human code
  rarely trips the gate (4 PASS / 1 INCONCLUSIVE / 0 FAIL on Flask history);
  subtly-wrong agent patches, the population this exists for, are untested.

## Architecture

```
interface (MCP / CLI / HTTP) → verification (semi-formal, blast, invariants, policy)
→ orchestration (planner → TaskIR → AsyncDAGScheduler, pre-commit gates)
→ retrieval (dense + BM25 + graph → RRF → [rerank: experimental, default off] → EvidencePack)
→ graph (AST CPG, bitemporal, anchor+delta) → storage (SQLite)
```

Rerank is marked experimental until it beats fused ranking on a held-out
set (measured 2 lifts / 4 demotions so far). Dense hash embeddings are a
lower-bound placeholder; measured numbers reflect the offline stack.

## Status

V1 walking skeleton. `PLAN.md` is the full plan; `CHANGELOG.md` records what
each revision proved, including measured numbers and known gaps. 185 tests:
`python -m pytest tests/ -q`.
