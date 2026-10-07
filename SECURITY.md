# Security Policy

VerifyCI takes security and verification integrity seriously. This document describes our security reporting procedure and in-scope components.

---

## Supported Versions

| Version | Supported |
|---|---|
| `0.1.x` | :white_check_mark: |
| `main` branch | :white_check_mark: |

---

## Reporting a Vulnerability

Please **do not report security vulnerabilities through public GitHub issues**.

To report a vulnerability:
1. Use **[GitHub Private Vulnerability Reporting](https://github.com/NeutronZero/VerifyCI/security/advisories/new)** on the VerifyCI repository.
2. If private reporting is unavailable, contact the project maintainers securely via email at `security@verifyci.org` or open a security draft advisory.

### What to Include in Your Report
- A description of the issue and its potential impact.
- Exact steps to reproduce, or a minimal proof-of-concept diff/repository.
- The affected component (e.g. `secrets_scan`, `SignedIntentWaiver`, `PolicyEvaluator`, `fastmcp_server`).
- Any potential mitigations or patch suggestions.

### Response Timeline
- **Acknowledgment**: Within 48 hours of receipt.
- **Initial Assessment**: Within 5 business days.
- **Fix and Advisory**: Coordinated public disclosure following verification and patch release.

---

## Scope & Security Boundaries

### In-Scope Components
- **Verification Engine & Policy Gate** (`verifyci/verification/`, `verifyci/contracts/`): Invariant bypasses, false-accept flaws in fail-closed logic, guard removal evasion.
- **Cryptographic Intent Waivers** (`verifyci/contracts/verification_ir.py`): Signature forgery, replay attacks, or bypasses of Ed25519/HMAC authentication.
- **Secret Detection & Redaction Boundaries** (`verifyci/secrets/`, `verifyci/export/`): Leaks of plaintext secret tokens through CLI, logs, SARIF, or JSON exports.
- **Storage & Lineage Integrity** (`verifyci/storage/`, `verifyci/memory/`): SQL injection, ledger tamper-chain collision, WAL concurrency corruption.
- **Interface Exposure** (`verifyci/interface/http.py`, `fastmcp_server.py`): Authentication bypass, loopback restriction bypass, denial of service via oversized diffs.

### Out-of-Scope Components
- **Synthetic Test Fixtures**: Dummy credentials and fake tokens in `tests/` or `benchmarks/` explicitly marked as test cases.
- **Frozen Benchmark Evidence**: Historical benchmark datasets and frozen corpora are static research artifacts and do not execute in production environments.
- **Known Language/AST Limitations**: As documented in `README.md` and `docs/architecture.md`, simple syntactic checks (e.g. `e = eval; e(x)`) are deterministic invariant checks, not dynamic runtime sandboxes.
- **Permissive Configurations**: Repositories where the user has explicitly disabled invariants or opted into unauthenticated bearer waivers.
