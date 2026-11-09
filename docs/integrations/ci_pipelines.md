# CI/CD Integration

VerifyCI is local-first: any runner with Python 3.12+, Git, and the target
branch's history can run the gate. Nothing is uploaded unless you upload the
SARIF report yourself.

The gate consumes a **commit range**, not a patch file: it reads Git objects for
the base, merge base, and head, and treats the target-base policy as
authoritative.

---

## 1. GitHub Actions

The composite action in the repository root wraps `vc gate`:

```yaml
name: VerifyCI Gate

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write
  pull-requests: read

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: VerifyCI Gate
        id: verifyci
        uses: NeutronZero/VerifyCI@main
        with:
          format: sarif
          output-file: verifyci-results.sarif
          review-mode: codeowners

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: verifyci-results.sarif
```

The action records `status` and `exit-code` even when the gate exits non-zero,
then fails the step. `status` is read from `payload.verdict.status` (JSON) or
`runs[0].properties.verdict` (SARIF), with the exit code as fallback.

Do **not** pass a cache key on `pull_request_target` or for fork PRs; the action
forces `cache-mode: none` there. For authenticated caching, pass
`cache-key: ${{ secrets.VERIFYCI_CACHE_KEY }}` (64 lowercase hex characters) from
a trusted workflow only.

An unvalidated build emits `ERROR` with `check_not_validated`; only a release
build with valid signed evidence can return `PASS`.

---

## 2. GitLab CI

```yaml
verifyci-gate:
  stage: verify
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y git
    - pip install verifyci
    - git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
  script:
    - >
      vc gate --repo . 
      --base "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
      --head "$CI_COMMIT_SHA"
      --format sarif --output verifyci.sarif
      --review-mode fail
  artifacts:
    when: always
    paths: [verifyci.sarif]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

---

## 3. Bitbucket Pipelines

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: VerifyCI Gate
          image: python:3.12
          script:
            - pip install verifyci
            - git fetch origin "$BITBUCKET_PR_DESTINATION_BRANCH"
            - >
              vc gate --repo .
              --base "origin/$BITBUCKET_PR_DESTINATION_BRANCH"
              --head "$BITBUCKET_COMMIT"
              --format sarif --output verifyci.sarif
          artifacts:
            - verifyci.sarif
```

---

## 4. Generic runner

```bash
git fetch origin main
vc gate --repo . --base origin/main --head HEAD --format json --output evidence.json
case $? in
  0) echo "PASS" ;;
  1) echo "FAIL" ;;
  2) echo "INCONCLUSIVE (coverage gap)" ;;
  3) echo "ERROR (no verdict established)" ;;
  4) echo "REVIEW required" ;;
esac
```

Persist `evidence.json` alongside the job: the payload hash is the reproducible
identity of the run.

---

## 5. Pre-commit

There is no pre-commit hook: a commit range gate needs a base revision and a
policy from the target branch, which a per-file pre-commit hook does not have.
Run `vc gate --base HEAD~1 --head HEAD` in a local `pre-push` hook or CI instead.
