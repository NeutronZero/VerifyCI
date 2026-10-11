---
name: vc-blast-radius
description: Use before and after any VerifyCI code change to map and re-evaluate impact
---

# VC Blast Radius

## Overview
Impact is mapped before the change with the frozen protocol and re-evaluated after with the same protocol. No silent scope creep.

## When to Use
- Any VerifyCI code change: gates, verifier, storage, API, CI, retrieval

## Procedure
1. Before: identify affected components, callers, contracts, tests, evidence artifacts. Use the frozen impact protocol.
2. Implement the change at the smallest scope that holds.
3. After: re-evaluate impact with the same protocol; confirm or update the map.
4. Re-run affected tests plus adversarial cases touching the blast zone.

## Failure handling
- Map grows mid-change: stop, re-scope, get direction if it crosses module/service lines.
- Unexpected dependent found post-change: add to map, test it, record.

## Acceptance
- Before/after maps, test results for the blast zone recorded.
