---
name: vc-release-verification
description: Use when verifying VerifyCI distributions, release metadata, versions, or install behavior
---

# VC Release Verification

## Overview
Releases are verified as installed artifacts, not as source checkouts. Frozen releases are never overwritten or modified without explicit authorization.

## When to Use
- Release cuts, distribution checks, GitHub Actions release workflows, version-identity questions

## Procedure
1. Verify installed-package behavior: install the built distribution in isolation, smoke-test it.
2. Check release metadata, version identity, provenance, and artifact hashes against the release record.
3. Audit the release GitHub Actions workflow (permissions, pins, gates).
4. Never publish, overwrite, or modify a frozen release without explicit authorization.

## Failure handling
- Identity mismatch: block release, investigate provenance.
- Failed install verification: FAIL, no publish.

## Acceptance
- Install verification log, metadata/hash match, workflow audit recorded.
