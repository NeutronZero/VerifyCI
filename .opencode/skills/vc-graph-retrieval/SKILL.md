---
name: vc-graph-retrieval
description: Use when analyzing or changing VerifyCI graph traversal, retrieval, indexing, caching, or scaling
---

# VC Graph Retrieval

## Overview
Profile actual bottlenecks before proposing migrations, rewrites, or storage replacements. Numbers first, architecture second.

## When to Use
- Retrieval latency, traversal cost, index/cache design, concurrency or scaling proposals

## Procedure
1. Profile: traversal paths, dense/sparse retrieval mix, index hits, cache behavior, DB round trips, concurrency limits.
2. Identify the measured bottleneck with flame/graph evidence, not intuition.
3. Propose the smallest change addressing the measured bottleneck; forbid language-migration or storage-replacement proposals without profile proof.
4. Re-measure with the frozen benchmark protocol; report p50/p95/p99 with sample sizes.

## Failure handling
- No measurable bottleneck: no architecture change; record the profile.
- Proposal without profile: rejected, sent back for measurement.

## Acceptance
- Profile, bottleneck, change rationale, before/after numbers recorded.
