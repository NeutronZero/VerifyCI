---
name: vc-ci-security
description: Use when auditing VerifyCI GitHub Actions, command construction, inputs, or release workflows
---

# VC CI Security

## Overview
CI runs untrusted inputs. Command injection, privilege creep, and unsafe filename handling are tested adversarially, not assumed away.

## When to Use
- Workflow changes, action input reviews, release workflow audits, allowlist reviews

## Procedure
1. Audit: permissions (least privilege per job), command construction (no untrusted interpolation into shell), filename handling (allowlist + quoting), action pinning (SHA, not floating tags), secret scoping.
2. Create adversarial regression tests: malicious filenames (`; rm`, `$()`, newlines), hostile PR titles/bodies, privilege-boundary probes.
3. Verify release workflows separately: no publish on untrusted events, environment gates intact.
4. Use authorized local repos and test environments only.

## Failure handling
- Injection path found: FAIL, fix with allowlist/parameterization, keep the regression test.
- Unpinned action: pin to SHA or record the exception with expiry.

## Acceptance
- Audit checklist, adversarial tests added and passing, pins verified.
