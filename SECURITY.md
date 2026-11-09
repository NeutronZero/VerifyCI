# Security Policy

VerifyCI is a verification gate: a bypass of its checks is a security issue in
its own right. This document covers reporting and the components that are in
scope.

---

## Supported versions

| Version | Supported |
|---|---|
| `3.1.x` | :white_check_mark: |
| `main` branch | :white_check_mark: |
| `0.x` (retired v1/v2 line) | :x: |

---

## Reporting a vulnerability

Please **do not open a public issue** for a security defect.

1. Use [GitHub Private Vulnerability Reporting](https://github.com/NeutronZero/VerifyCI/security/advisories/new).
2. If that is unavailable, contact the maintainers at `security@verifyci.org`.

Include:

- the affected component and the trust boundary it crosses;
- a minimal repository/commit range and the exact `vc gate` command;
- the observed verdict, evidence bundle (`--format json`), and diagnostics;
- whether the issue reproduces with an uncached run (`--cache-mode none`).

Response: acknowledgement within 48 hours, initial assessment within 5 business
days, coordinated disclosure after a fix is verified.

---

## In-scope components

- **Gate integrity and policy authority** (`verifyci/gate/`): checks that a
  pull request cannot change the policy that judges it, that the target-base
  policy is the authoritative one, and that waived/cleared results stay bound
  to their evidence.
- **Check soundness** (`verifyci/checks/`): false PASS, false FAIL, missed
  findings, solver/replay divergence, evidence that does not support its
  finding, and analysis that silently narrows scope.
- **Coverage acceptance and waivers** (`verifyci/gate/verdict.py`,
  `verifyci/gate/policy.py`): acceptance records that clear more scope than
  they name, expired records that still apply, and accepted analytical gaps
  that become PASS.
- **Evidence and lineage** (`verifyci/evidence/`, `verifyci/contracts/`):
  fingerprint collisions, canonicalisation ambiguity, SARIF paths that point at
  the wrong source location, and bundle manipulation.
- **Release trust boundary** (`verifyci_release_trust/`,
  `verifyci/contracts/release_validation.py`): signature/OIDC/provenance
  checks, the hostile-input IPC parser, and the container launcher
  (`docker/worker/`).
- **Secret handling** (`verifyci/checks/security.py`): plaintext secret
  material leaking into findings, logs, SARIF, or the evidence bundle.
- **Cache integrity** (`verifyci/index/`): poisoned cache entries, HMAC
  downgrade, and sampled-recomputation mismatches.

## Out of scope

- Dummy credentials, fixtures, and deliberately vulnerable corpora under
  `corpora/`, `benchmarks/`, and `tests/`.
- Frozen baseline artifacts (`v1.0-evidence-baseline`, `corpora/` oracles);
  they are static research inputs, not production code.
- Known frontend limits: unsupported languages are reported as
  `unsupported_language` gaps by design.
- Repositories that intentionally configure permissive policies or accept the
  gaps the gate reports.
- Installation of unpinned development dependencies outside the pinned worker
  lock (`docker/worker/requirements.lock`).
