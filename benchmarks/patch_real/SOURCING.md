# H4-A Sourcing Record (candidates + procedure, NOT the frozen corpus)

Status: SOURCING COMPLETE. Corpus NOT built/frozen (that is H4-B).
No VerifyCI scoring was run on any candidate (that is H4-C).

## Predeclared mechanical selection rule

ALL non-merge commits touching `verifyci/` on this repo's own history,
newest-first, each contributing exactly one correct/wrong pair —
no outcome-based filtering, no cherry-picking, no checker-output
consultation during selection. Rationale: 10 such commits exist,
yielding exactly the contracted minimum N=20.

## Candidate table (10 pairs)

Correct case per commit = the commit's own diff (real fix, real session).
Wrong case per commit = the mechanical revert diff on the fixed tree
(single-variable reintroduction of the authentic historical bug).
Intent per case = the commit message (authentic, unedited).

| # | Commit | Parent | Intent (message) | Ground-truth basis |
|---|--------|--------|------------------|-------------------|
| 1 | 7343c6d | 084994b | combined post-overhaul review fixes | Direct session evidence: 4 bugs demonstrated pre-fix (3 probe FAILs reproduced in H4-A demo setup), 8/8 probes green post-fix |
| 2 | 084994b | 5cb1aa4 | V1 correctness repairs (A1–A8) | Direct session evidence + H4-A execution demo (borrowed probes: 3 fail at parent, 8 pass at fix) |
| 3 | ae171cb | 1aba78f | stored BM25 tf; graph expansion; cached index | Commit-record claim; FOR H4-B execution-verification, exclude on ambiguity |
| 4 | 1aba78f | 8ea8f11 | rename + env fallback | Commit-record claim; same fallback as above |
| 5 | 8ea8f11 | c1e91ca | skip consistency; ignore rules | Commit-record claim; same fallback as above |
| 6 | c1e91ca | 9486efb | revision identity; append-only ingests | Commit-record claim; same fallback as above |
| 7 | 9486efb | c247d30 | planner single gating | Commit-record claim; same fallback as above |
| 8 | c247d30 | fdd495c | resolver no-guess; suffix decline | Commit-record claim; same fallback as above |
| 9 | fdd495c | 563db16 | re-audit fixes | Commit-record claim; same fallback as above |
| 10 | 563db16 | d3056c8 | audit fixes: fail-closed, packaging | Commit-record claim; same fallback as above |

Diff spec per pair (H4-B executes): correct = `git diff <parent> <commit>
-- verifyci tests`; wrong = mechanical revert diff (`git revert -n
<commit>`, take diff) on the fixed tree.
Per-case base for measurement: parent tree (correct) / fixed tree (wrong);
per-case ingest at H4-C (documented extension of the frozen single-base protocol:
same invariants, same per-case `run_verify`, same confusion metrics).

## Ground-truth procedure (CONFIRMED by execution, not just documented)

Worktree at revision + targeted `pytest` (project tests, never VerifyCI
verdicts): borrowed post-fix probes FAIL at the parent state and PASS at
the fixed state. Demonstrated H4-A on the 084994b pair (3 fail → 8 pass);
worktrees removed after. Full per-pair execution belongs to H4-B, where
ambiguous pairs are EXCLUDED with reason per the frozen contract.

## Blind-compliance and limitations (explicit)

- Selection used commit topology + messages only; no candidate was
  filtered, shaped, or validated using any VerifyCI output, score, or
  checker-internal knowledge. Diffs were handled only as opaque
  artifacts for the table above.
- Limitation (not hidden): this history's fixes were authored by
  checker-aware agents, so the checker-independence is weaker than for
  fully external patches. What IS preserved vs the synthetics: real
  multi-file debugging sessions with independently failing/passing
  tests, selected without outcome filtering. Flask-history augmentation
  remains the documented option if H4-B demands stronger independence.
- No frozen files touched; no scores computed; `results_h4.json` not created.
