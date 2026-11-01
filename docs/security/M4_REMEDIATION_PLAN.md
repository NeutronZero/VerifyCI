# M4 Release-Signing Remediation Plan (v3.1.10)

Status: in progress. Branch: `feat/v3.1.10-m4-security`.

## Findings addressed

1. Candidate-local reusable signing workflow (`ci.yml` -> `./.github/workflows/release_signing.yml`).
2. Signing secret passed from candidate-controlled caller.
3. `release` environment had no reviewers, no branch policy, admin bypass enabled.
4. Measurement OIDC accepted a candidate `ci.yml` prefix as trusted identity.
5. Provenance did not bind artifact ID/digest to the downloaded zip or the upload step.
6. Checked-in evidence referenced run `41205733022`, not the latest reviewed run.

## Target trust boundary

```
candidate branch (untrusted)                    release-authority branch (protected)
  ci.yml                                          release_measurements.yml @ SHA A
    uses: owner/repo/.github/workflows/             (workflow_call, no secrets)
          release_measurements.yml@SHA_A  ------>   runs candidate tests/benchmarks
                                                    uploads release-measurements
                                                    measurement OIDC:
                                                      job_workflow_ref = release_measurements.yml
                                                      job_workflow_sha = SHA_A
                                                      sha = candidate SHA
                                                            |
maintainer dispatch (workflow_dispatch)                     |
  release_signing.yml @ release-authority <-----------------+
    environment: release (reviewers + branch policy)
    secret only here
    no candidate checkout
    download artifact by ID, verify API provenance + zip digest
    run trusted signer from release-authority
    sign + upload evidence-bundle
```

- `release-authority` is protected: required review, no force push, admin enforcement.
- `release` environment: required reviewer, custom branch policy `release-authority`, admin bypass disabled.
- Trusted workflow is referenced by full commit SHA from candidate CI.
- The signer script and measurement script are hash-pinned in the trusted workflow.
- Candidate source is consumed only as data (tarball) for fingerprint recomputation.

## Implementation steps

1. Add failing adversarial tests (OIDC exact identity, provenance artifact binding, archive validation, workflow static checks).
2. Rework `scripts/standalone_signer.py`:
   - explicit measurement run/attempt, artifact ID/digest/zip, trusted workflow SHA/ref;
   - exact `job_workflow_ref` + `job_workflow_sha` + `ref`/`sha`/run checks;
   - artifact zip validation; API run/attempt/job/step/artifact binding.
3. Add `.github/workflows/release_measurements.yml` (trusted, workflow_call, no secrets).
4. Replace `.github/workflows/release_signing.yml` with protected workflow_dispatch signer.
5. Update `.github/workflows/ci.yml`: call trusted measurement workflow by SHA; remove local signing/secret flow.
6. Update `verifyci/contracts/release_validation.py` provenance requirements.
7. Update `scripts/validate_release.py` attestation (ref, workflow identity fields).
8. Run focused + full tests, ruff.
9. Commit A (trusted code), create/protect `release-authority` at A; configure environment.
10. Commit B (ci.yml pins A); push; run CI.
11. Dispatch trusted signing for B; approve environment; collect artifact IDs/digests.
12. Commit evidence (child of B, only evidence file); push.
13. Independent verification + final report.

## Non-negotiable

- No candidate code execution in the secret-bearing job.
- No reused run IDs, artifact IDs, digests, or signatures.
- NO-GO if trusted workflow was not actually used or environment controls are absent.
