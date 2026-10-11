---
name: vc-provenance-lineage
description: Use when tracking VerifyCI revisions, snapshots, lineage, replays, or stale-artifact questions
---

# VC Provenance Lineage

## Overview
Every artifact traces to a revision, config, and snapshot. Stale artifacts are detected, never silently reused. History is immutable.

## When to Use
- Lineage questions, replay validation, stale-hash investigations, baseline comparisons

## Procedure
1. Record revision, configuration, snapshot ID, and parent lineage for every artifact.
2. Replay: same inputs reproduce same outputs; mismatch means stale artifact or source mismatch — find which.
3. Detect stale artifacts by hash + revision comparison before consuming.
4. Keep historical evidence immutable, including the v1.0-evidence-baseline tag and its artifacts.
5. Remediation/benchmark/research results stay separate with their own source commits.

## Failure handling
- Source mismatch: stop consumption, re-resolve lineage.
- Baseline mutation request: refuse without explicit authorization.

## Acceptance
- Lineage chain, replay result, staleness verdicts recorded.
