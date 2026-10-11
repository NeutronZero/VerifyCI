---
name: vc-verifier-soundness
description: Use when auditing VerifyCI verifier premises, traces, diff-to-graph mapping, or evidence-to-claim links
---

# VC Verifier Soundness

## Overview
A passing test is not proof of general semantic correctness. Every claim needs a premise, a trace, and a mapping — all checkable.

## When to Use
- Verifier changes, premise audits, diff-to-graph mapping reviews, false-accept/false-reject investigations

## Procedure
1. Audit premises: listed, versioned, satisfiable. Missing premise → claim unsupported.
2. Check traces end to end: diff → graph nodes → file/path identity → evidence → claim.
3. Build counterexamples for ambiguity, missing premises, malformed diffs, unsupported semantic conclusions.
4. Reproduce at least one false accept and one false rejection; keep both visible.
5. File/path identity must be exact — no fuzzy matching across renames without a recorded map.

## Failure handling
- Unsupported semantic leap found: FAIL the claim, record the gap.
- Malformed diff: reject input, do not infer intent.

## Acceptance
- Premise list, trace sample, counterexamples, false-accept/reject reproductions recorded.
