# VerifyCI Quickstart Guide

Get up and running with VerifyCI in 5 minutes. This guide walks you through an end-to-end verification flow: from installing VerifyCI to ingesting a sample repository, evaluating invariants, verifying a patch, and inspecting machine-readable evidence.

---

## 1. Installation

VerifyCI requires **Python 3.12+**. It is local-first, runs entirely on your machine, and requires no hosted accounts or external servers.

```bash
# Install from source / development checkout:
git clone https://github.com/NeutronZero/VerifyCI.git
cd VerifyCI
pip install -e ".[dev]"

# (Once published to PyPI: pip install verifyci)
```

Verify your installation:

```bash
verifyci --help
```

---

## 2. Set Up a Sample Repository

Create a minimal sample project to test:

```bash
mkdir my-project
cd my-project
git init

# Create an application module
cat << 'EOF' > app.py
def calculate_discount(price: float, rate: float) -> float:
    """Calculate discounted price with non-negative bounds."""
    if rate < 0 or rate > 1.0:
        raise ValueError("Invalid discount rate")
    return price * (1.0 - rate)

def process_order(price: float, rate: float) -> float:
    return calculate_discount(price, rate)
EOF

git add app.py
git commit -m "feat: initial order calculation service"
```

---

## 3. Ingestion & Graph Construction

VerifyCI parses your project into a bitemporal Code Property Graph (CPG) stored in SQLite:

```bash
# 1. Initialize VerifyCI database and directory (.verifyci/)
verifyci init .

# 2. Ingest codebase to extract entities (functions, classes) and call/dependency edges
verifyci ingest .

# 3. View graph statistics
verifyci stats
```

You should see output similar to:
```text
revisions: 1
entities: 2
edges: 1
events: 1
anchors: 0
deltas: 0
resolution: resolved=1 ambiguous=0 missing=0 unresolved_edges=0
```

You can query the graph directly:
```bash
verifyci query "where is calculate_discount?"
```

---

## 4. Policy and Invariant Configuration

VerifyCI enforces deterministic project invariants defined in `.verifyci/invariants.yaml`. 
By default, VerifyCI checks:
1. `secrets_scan`: Scans added lines for hardcoded credentials, tokens, and private keys.
2. `provenance_check`: Ensures changes ground into known code entities and produce evidence.

You can add project-specific architectural rules to `.verifyci/invariants.yaml`:

```bash
cat << 'EOF' > .verifyci/invariants.yaml
invariants:
  - id: no_eval
    rule: "Disallow use of eval()"
    query: "forbid_call:eval"
    blocking: true

  - id: no_telnetlib
    rule: "Disallow telnetlib imports"
    query: "forbid_import:telnetlib"
    blocking: true
EOF
```

---

## 5. Produce a Patch (Diff)

Let's modify `app.py` by adding a promotion helper function:

```bash
cat << 'EOF' > app.py
def calculate_discount(price: float, rate: float) -> float:
    """Calculate discounted price with non-negative bounds."""
    if rate < 0 or rate > 1.0:
        raise ValueError("Invalid discount rate")
    return price * (1.0 - rate)

def process_order(price: float, rate: float) -> float:
    return calculate_discount(price, rate)

def apply_promo(price: float) -> float:
    """Apply standard promotion discount."""
    return calculate_discount(price, 0.10)
EOF

# Export unified diff
git diff > change.patch
```

---

## 6. Verify the Diff

Run VerifyCI to verify the proposed patch against the ingested graph:

```bash
verifyci verify-diff --diff-file change.patch
```

Example terminal output:
```text
PASS: all_checks_passed_behavior_not_verified (63c3a9f0-29c8-47f3-b547-b2488417c805)
files: app.py
```

Exit code: `0` (Success).

---

## 7. Inspecting Machine-Readable Results

VerifyCI produces authoritative, machine-readable verification certificates and standard SARIF reports.

### Exporting JSON Certificate:

```bash
verifyci verify-diff --diff-file change.patch --format json --output cert.json
```

Inspect `cert.json`:
```json
{
  "$schema": "https://verifyci.org/schemas/v1/certificate-report.json",
  "version": "1.0",
  "verdict": {
    "status": "PASS",
    "rationale": "all_checks_passed_behavior_not_verified",
    "report_id": "63c3a9f0-29c8-47f3-b547-b2488417c805",
    "exit_code": 0
  },
  "provenance": {
    "revision_id": "8f8303f90fa12a...",
    "files": ["app.py"],
    "changed_entities": ["calculate_discount", "apply_promo", "process_order"],
    "reproducible": true
  },
  "certificate": {
    "certificate_verified": true,
    "confidence": 1.0,
    "evidence": [
      {
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 5,
        "source_hash": "..."
      }
    ]
  }
}
```

### Exporting SARIF v2.1.0 for GitHub Code Scanning:

```bash
verifyci verify-diff --diff-file change.patch --format sarif --output results.sarif
```

This generates standard OASIS SARIF v2.1.0, compatible with GitHub Code Scanning, SonarQube, and CI dashboards.

---

## 8. Testing a Gate Rejection (FAIL)

Now test what happens when an agent proposes a patch introducing a forbidden call:

```bash
cat << 'EOF' > app.py
def calculate_discount(price: float, rate: float) -> float:
    return eval("price * (1.0 - rate)")

def process_order(price: float, rate: float) -> float:
    return calculate_discount(price, rate)
EOF

git diff > bad_change.patch
verifyci verify-diff --diff-file bad_change.patch
```

Output:
```text
FAIL: blocking_check_failed (97a1d1e4-84d5-48fa-bb64-c852467d130a)
files: app.py
```

Exit code: `1` (Verification Failure).

VerifyCI catches the violation before tests or human code review run, halting invalid diffs immediately.

---

## Next Steps

- Learn about all supported outcomes in [docs/verdicts.md](verdicts.md).
- Understand the pipeline architecture in [docs/architecture.md](architecture.md).
- Integrate VerifyCI into GitHub Actions with [action.yml](../action.yml).
- Author custom checkers with [docs/extension.md](extension.md).
