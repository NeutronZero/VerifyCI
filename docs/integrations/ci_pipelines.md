# CI/CD Pipeline Integrations

VerifyCI is local-first, zero-SaaS, and runs natively in any standard containerized or VM CI runner.

---

## 1. GitHub Actions

Use the official composite action located in the repository root (`action.yml`):

```yaml
name: Verify Pull Request Diff

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write # Required if uploading SARIF to GitHub Code Scanning

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Required for git diff base calculation

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: VerifyCI Gate
        uses: NeutronZero/VerifyCI@main
        with:
          format: "sarif"
          output-file: "verifyci-results.sarif"
          fail-on-inconclusive: "true"

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: "verifyci-results.sarif"
```

---

## 2. GitLab CI (`.gitlab-ci.yml`)

```yaml
stages:
  - verify

verifyci-diff:
  stage: verify
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y git
    - pip install uv && uv pip install --system verifyci
  script:
    # Initialize and index repository graph
    - verifyci init .
    - verifyci ingest .
    # Compute diff against target branch and evaluate
    - git fetch origin $CI_MERGE_REQUEST_TARGET_BRANCH_NAME --depth=1 || true
    - git diff origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME HEAD > pr.diff
    - verifyci verify-diff --diff-file pr.diff --format json --output verifyci-report.json
  artifacts:
    when: always
    reports:
      codequality: verifyci-report.json
    paths:
      - verifyci-report.json
  only:
    - merge_requests
```

---

## 3. Bitbucket Pipelines (`bitbucket-pipelines.yml`)

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: VerifyCI Deterministic Gate
          image: python:3.12
          script:
            - pip install verifyci
            - verifyci init .
            - verifyci ingest .
            - git fetch origin $BITBUCKET_PR_DESTINATION_BRANCH --depth=1 || true
            - git diff origin/$BITBUCKET_PR_DESTINATION_BRANCH HEAD > pr.diff
            - verifyci verify-diff --diff-file pr.diff --format json --output report.json
          artifacts:
            - report.json
```

---

## 4. Pre-commit Hook (`.pre-commit-config.yaml`)

Verify staged diffs before creating commits locally:

```yaml
repos:
  - repo: https://github.com/NeutronZero/VerifyCI
    rev: v0.1.0
    hooks:
      - id: verifyci-staged
```
