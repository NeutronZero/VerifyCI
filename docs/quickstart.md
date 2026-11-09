# VerifyCI Quickstart

VerifyCI is a deterministic, local-first pre-merge gate. It reads Git objects
directly (no database, server, network call, or LLM) and emits a signed-shape
evidence bundle plus a SARIF projection.

---

## 1. Install

VerifyCI requires **Python 3.12+** and a Git checkout with the history the gate
must inspect.

```bash
git clone https://github.com/NeutronZero/VerifyCI.git
cd VerifyCI
pip install -e ".[dev]"

vc --version
```

The console entry point is `vc` (equivalently `python -m verifyci.cli`).

---

## 2. Add a policy to the target branch

Policy lives at `.verifyci/policy.toml` **on the base revision** and is
authoritative for the run. A minimal policy:

```toml
[gate]
target_drift = "record"

[paths]
source_roots = ["."]

[forbidden_calls.eval]
symbols = ["eval", "exec"]
reason = "Dynamic code execution is prohibited"

[deny_changes.secrets]
paths = ["**/*.pem", "**/id_rsa"]
reason = "Private key material must not be committed"
```

Commit it on the base branch before gating a change; a policy added only in the
pull request is a `policy_change_review` (REVIEW) event, not new authority.

---

## 3. Run the gate

```bash
# Compare a PR branch with its target branch
vc gate --repo . --base origin/main --head HEAD --format text

# Machine-readable evidence bundle
vc gate --repo . --base origin/main --head HEAD \
  --format json --output verifyci-evidence.json

# SARIF 2.1.0 for code scanning
vc gate --repo . --base origin/main --head HEAD \
  --format sarif --output verifyci-results.sarif
```

Useful options:

| Option | Meaning |
|---|---|
| `--merge-base <rev>` | Pin an already-verified merge base. |
| `--as-of YYYY-MM-DD` | Deterministic date for waiver/acceptance evaluation. |
| `--review-mode fail\|codeowners` | Whether proven codeowner approval clears REVIEW. |
| `--jobs N` | Deterministic batch width for checks. |
| `--cache-mode none\|local\|authenticated` | Cache trust mode. `local` requires `--allow-local-cache`; `authenticated` requires `VERIFYCI_CACHE_KEY` (64 lowercase hex characters). |
| `--cache-read-only` | Never write cache entries (used for PR runs). |

---

## 4. Read the verdict

```text
VERDICT: PASS (exit 0)
Policy: target_blob sha256:…
Reasons: …
Evidence payload: sha256:…
```

| Verdict | Exit | Meaning |
|---|:---:|---|
| `PASS` | `0` | Every applicable blocking check completed with COMPLETE coverage and no unwaived defect. |
| `FAIL` | `1` | A blocking defect was established with validated evidence. |
| `INCONCLUSIVE` | `2` | Coverage is incomplete (unmapped hunks, unsupported language, solver unknown, budget). |
| `ERROR` | `3` | Internal fault, missing Git object, or invalid policy. |
| `REVIEW` | `4` | Policy or gate-integrity files changed; codeowner review required. |

An unvalidated development build additionally reports `check_not_validated` and
emits `ERROR`: absence of signed release-validation evidence can never be a
PASS. See [docs/release-evidence.md](release-evidence.md).

---

## 5. Inspect the evidence

The JSON output is the canonical bundle envelope:

```json
{
  "payload": {
    "schema": "verifyci.evidence/v3.1",
    "tool": {"name": "verifyci", "version": "3.1.10"},
    "inputs": {"target_base_commit": "…", "merge_base_commit": "…", "head_commit": "…"},
    "policy": {"authoritative_policy_source": "target_blob", "effective_policy_hash": "sha256:…"},
    "check_results": [{"check_id": "grounding", "outcome": "PASS", "coverage": "COMPLETE", "coverage_gaps": []}],
    "accepted_gaps": [],
    "findings": [],
    "diagnostics": [],
    "verdict": {"status": "PASS", "exit_code": 0}
  },
  "envelope": {"payload_hash": "sha256:…"}
}
```

Every finding carries a stable fingerprint, its evidence kind and payload, and
the premises (commits, blobs, policy hash, toolchain) that bound it.

---

## 6. Accept a gap, waive a finding

Reviewed exclusions are policy records, not code comments:

```toml
[coverage_acceptances.rust-frontend]
check = "semantic"
reason_code = "unsupported_language"
paths = ["tools/agent.rs"]
reason = "Rust is outside the accepted frontend set for this service"
approved_by = "@security"
created = "2026-10-01"
expires = "2026-12-31"

[waivers.known-fp]
check = "security"
defect_id = "SEC-DANGEROUS-CALL"
fingerprint = "vci1:…"
reason = "Sandbox launcher, reviewed"
approved_by = "@security"
created = "2026-10-01"
expires = "2026-12-31"
```

An acceptance can clear a `scope_enumeration.complete = false` result **only**
when every remaining gap is an acceptable scope exclusion
(`unsupported_language`, `frontend_capability_missing`), and the accepted
exclusions are recorded in the evidence (`accepted_exclusions`). Analytical gaps
(solver unknown, dynamic target, parse error, budget) remain INCONCLUSIVE even
when accepted.

---

## 7. Next steps

- Verdict and coverage semantics: [verdicts.md](verdicts.md)
- Architecture and data flow: [architecture.md](architecture.md)
- CI integration: [integrations/ci_pipelines.md](integrations/ci_pipelines.md)
- End-to-end example: [examples/basic_walkthrough.md](examples/basic_walkthrough.md)
