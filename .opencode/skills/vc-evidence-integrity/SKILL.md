---
name: vc-evidence-integrity
description: Use when verifying VerifyCI artifact completeness, hashes, provenance, predicates, or result labels
---

# VC Evidence Integrity

## Overview
A missing artifact or unsatisfied required predicate prevents ESTABLISHED. Original evidence is immutable.

## When to Use
- Evidence bundle checks, label reviews (MEASURED/REPRODUCED/ESTABLISHED/UNESTABLISHED), artifact audits

## Procedure
1. Verify artifact completeness: every required artifact present, hashes match, provenance recorded (revision, config, snapshot).
2. Evaluate consistency predicates; any required predicate unsatisfied → not ESTABLISHED.
3. Preserve original evidence; new measurements use newly identified artifacts, never edits of history.
4. Apply formal adjudication rules (see vc-evidence-adjudication for the label logic).

## Failure handling
- Hash mismatch or stale artifact: FAIL integrity, quarantine dependents.
- Missing artifact: label caps at UNESTABLISHED.

## Acceptance
- Per-artifact hash verdicts, predicate results, label justification recorded.
