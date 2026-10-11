---
name: vc-api-security
description: Use when reviewing or testing VerifyCI API authentication, authorization, validation, or confinement
---

# VC API Security

## Overview
Every endpoint proves authentication, authorization, validation, redaction, and confinement. Forbidden calls fail loudly and safely.

## When to Use
- API changes, auth reviews, error-message audits, DB-confinement checks

## Procedure
1. Check: authentication required, authorization per resource, request validation (types, ranges, allowlists), secret redaction in logs/errors, safe error messages (no internals), database confinement (scoped queries, no cross-tenant reads).
2. Test forbidden calls: unauthenticated, wrong-principal, and out-of-scope requests — all must be rejected with safe errors.
3. Adversarial cases: oversized payloads, type confusion, path traversal, injection strings.
4. Test only against authorized local/test environments.

## Failure handling
- Auth bypass or data leak: FAIL, fix root cause, add regression test.
- Verbose error leaking internals: redact, re-test.

## Acceptance
- Auth matrix, adversarial results, redaction checks recorded.
