---
name: vc-gate-integrity
description: Use when changing, reviewing, or debugging VerifyCI gate verdicts, precedence, timeouts, or blocker behavior
---

# VC Gate Integrity

## Overview
Gates fail closed. Uncertainty never becomes a successful gate. Verdict precedence and contract dominance are explicit and deterministic.

## When to Use
- Gate logic changes, timeout classification, infra-failure handling, missing/contradictory evidence cases

## Procedure
1. Assert fail-closed semantics: missing evidence, contradictory evidence, infra failure, timeout → never PASS.
2. Verify verdict precedence order and contract dominance against the frozen predicates.
3. Check deterministic blocker behavior: same inputs, same verdict, every run.
4. Reproduce false accepts and false rejections as counterexamples before fixing.
5. Run synthetic gate tests (missing evidence, contradiction, timeout, infra error) — all must stay non-ESTABLISHED.

## Failure handling
- Ambiguous verdict path: mark UNKNOWN, keep gate closed, escalate.
- Timeout vs failure confusion: classify per protocol, never upgrade a timeout to pass.

## Acceptance
- Precedence table cited, synthetic gate cases all closed, determinism shown.
