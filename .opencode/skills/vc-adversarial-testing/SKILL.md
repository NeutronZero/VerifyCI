---
name: vc-adversarial-testing
description: Use when converting VerifyCI defects into regression tests or probing false-accept, inconclusive, and hostile paths
---

# VC Adversarial Testing

## Overview
Every reproduced defect becomes a regression test. False accepts, false rejections, inconclusive outcomes, malformed evidence, stale hashes, hostile inputs, timeouts, and contradictions are all covered.

## When to Use
- Post-fix hardening, gate/verifier changes, robustness reviews

## Procedure
1. For each reproduced defect, write a regression test that fails on old code and passes on new.
2. Cover: false accepts, false rejections, inconclusive outcomes, malformed evidence, stale hashes, hostile inputs (filenames, payloads), timeout paths, contradictory results.
3. Keep counterexamples visible in the suite, not deleted after green.
4. Run the full adversarial set before claiming the fix.

## Failure handling
- Defect not reproducible: record attempts, mark UNKNOWN, no speculative test.
- Flaky adversarial test: quarantine with reason, fix determinism, do not delete.

## Acceptance
- Regression tests per defect, adversarial matrix results recorded.
