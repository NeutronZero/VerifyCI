---
name: vc-evidence-adjudication
description: Use when assigning or reviewing VerifyCI MEASURED, REPRODUCED, ESTABLISHED, or UNESTABLISHED labels
---

# VC Evidence Adjudication

## Overview
Labels follow formal rules. Green CI never promotes a claim by itself. Failed experiments, counterexamples, uncertainty, and negative results are preserved.

## When to Use
- Labeling results, reviewing evidence states, disputing a promotion

## Procedure
1. MEASURED: artifact exists with hash + provenance from a recorded run.
2. REPRODUCED: independent rerun matches within the frozen tolerance.
3. ESTABLISHED: MEASURED + REPRODUCED + all required predicates satisfied + no open counterexamples.
4. Otherwise UNESTABLISHED. Missing evidence, stale hashes, contradictions, and open counterexamples each force UNESTABLISHED.
5. Preserve failed experiments and negative results alongside; never delete to promote.

## Failure handling
- Promotion pressure without predicates: refuse, cite the unsatisfied predicate.
- Disputed label: re-adjudicate from artifacts, not from CI color.

## Acceptance
- Per-claim label with rule citations and artifact pointers recorded.
