# VerifyCI End-to-End Adoption Walkthrough

This self-contained example demonstrates how an external team can adopt VerifyCI in a new or existing repository, define custom invariants, verify diffs locally, inspect machine-readable outputs, and integrate with CI.

---

## 1. Prerequisites and Installation

VerifyCI requires **Python 3.12+**. VerifyCI is local-first, runs entirely on your workstation or runner, and requires no cloud account or API key.

```bash
# Option A: Install from source / development checkout
git clone https://github.com/NeutronZero/VerifyCI.git
cd VerifyCI
pip install -e .

# Option B: Install released wheel / PyPI (when published)
# pip install verifyci
```

Check your CLI installation:
```bash
verifyci --help
```

---

## 2. Set Up a Sample Repository

Create a minimal sample project representing a backend microservice:

```bash
mkdir order_service
cd order_service
git init
git config user.name "Adopter Demo"
git config user.email "demo@example.com"

# Create application logic
cat << 'EOF' > billing.py
def calculate_subtotal(items: list[dict]) -> float:
    """Calculate the sum of all item prices."""
    return sum(item["price"] * item.get("quantity", 1) for item in items)

def calculate_order_total(items: list[dict], tax_rate: float) -> float:
    """Calculate final order total including tax."""
    if tax_rate < 0 or tax_rate > 1.0:
        raise ValueError("Tax rate must be between 0.0 and 1.0")
    subtotal = calculate_subtotal(items)
    return subtotal * (1.0 + tax_rate)
EOF

git add billing.py
git commit -m "feat: initial order total calculation"
```

---

## 3. Initialize and Ingest

VerifyCI constructs a bitemporal Code Property Graph (CPG) stored locally in `.verifyci/verifyci.db`:

```bash
# 1. Initialize VerifyCI workspace
verifyci init .

# 2. Ingest codebase to extract entities and call/dependency edges
verifyci ingest .

# 3. View graph statistics
verifyci stats
```

Example output:
```text
revisions: 1
entities: 2
edges: 1
events: 1
anchors: 0
deltas: 0
resolution: resolved=1 ambiguous=0 missing=0 unresolved_edges=0
```

---

## 4. Define Project Invariants

Define project rules in `.verifyci/invariants.yaml`. Rules run deterministically during verification:

```bash
cat << 'EOF' > .verifyci/invariants.yaml
invariants:
  - id: disallow_eval
    rule: "Disallow dynamic eval calls in billing calculations"
    query: "forbid_call:eval"
    blocking: true

  - id: disallow_telnetlib
    rule: "Disallow legacy unencrypted protocol libraries"
    query: "forbid_import:telnetlib"
    blocking: true
EOF
```

---

## 5. Verify a Valid Change (PASS)

Add a helper function `apply_fixed_discount` that calls `calculate_subtotal`:

```bash
cat << 'EOF' >> billing.py

def apply_fixed_discount(items: list[dict], discount: float) -> float:
    """Apply promotional dollar discount to order subtotal."""
    subtotal = calculate_subtotal(items)
    return max(0.0, subtotal - discount)
EOF

git diff > valid_feature.patch
```

Run VerifyCI to verify the patch:
```bash
verifyci verify-diff --diff-file valid_feature.patch
```

Output:
```text
PASS: all_checks_passed_behavior_not_verified (b81c2f10-9851-4eb7-a72e-336719dc7889)
files: billing.py
```
Exit code: `0` (Success).

---

## 6. Inspect Machine-Readable Artifacts

### A. Authoritative JSON Certificate
```bash
verifyci verify-diff --diff-file valid_feature.patch --format json --output cert.json
```

The output JSON includes the authoritative `Certificate`, `VerificationReport`, and provenance metadata:
```json
{
  "$schema": "https://verifyci.org/schemas/v1/certificate-report.json",
  "version": "1.0",
  "verdict": {
    "status": "PASS",
    "rationale": "all_checks_passed_behavior_not_verified",
    "report_id": "b81c2f10-9851-4eb7-a72e-336719dc7889",
    "exit_code": 0
  },
  "provenance": {
    "files": ["billing.py"],
    "changed_entities": ["apply_fixed_discount"],
    "reproducible": true
  }
}
```

### B. OASIS SARIF v2.1.0 for CI & Security Dashboards
```bash
verifyci verify-diff --diff-file valid_feature.patch --format sarif --output results.sarif
```

The SARIF report conforms to OASIS SARIF v2.1.0, ready for upload to GitHub Code Scanning or SonarQube.

---

## 7. Verify a Policy Violation (FAIL)

Test what happens if an unauthorized patch introduces `eval` or an invalid construct:

```bash
cat << 'EOF' > billing.py
def calculate_subtotal(items: list[dict]) -> float:
    """Calculate the sum of all item prices."""
    return sum(item["price"] * item.get("quantity", 1) for item in items)

def calculate_order_total(items: list[dict], tax_rate: float) -> float:
    subtotal = calculate_subtotal(items)
    return eval("subtotal * (1.0 + tax_rate)")
EOF

git diff > bad_eval.patch
verifyci verify-diff --diff-file bad_eval.patch
```

Output:
```text
FAIL: blocking_check_failed (f2c81d33-4f9e-4a61-9f76-bc3952136e9d)
files: billing.py
```
Exit code: `1` (Verification Failure).

VerifyCI catches the violation before tests or review run.

---

## 8. Add VerifyCI to GitHub Actions

Create `.github/workflows/verifyci.yml` in your repository:

```yaml
name: VerifyCI Verification Gate

on:
  pull_request:
    branches: [main]

jobs:
  verify:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      # Run VerifyCI Gate Composite Action
      - uses: NeutronZero/VerifyCI@v0.1.0
        id: verifyci
        with:
          format: sarif
          output-file: verifyci-results.sarif

      # Upload findings to GitHub Security Tab
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: verifyci-results.sarif
```
