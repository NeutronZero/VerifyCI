# End-to-end walkthrough

This example starts from an empty repository and ends with a blocked pull
request and a machine-readable evidence bundle. Every command is deterministic
and runs offline.

---

## 1. Install

```bash
git clone https://github.com/NeutronZero/VerifyCI.git
cd VerifyCI
pip install -e .
vc --version
```

Requires Python 3.12+ and Git.

---

## 2. Create a repository with a target-branch policy

```bash
mkdir order_service && cd order_service
git init -b main
git config user.name "Adopter Demo"
git config user.email "demo@example.com"

mkdir -p .verifyci
cat > .verifyci/policy.toml <<'EOF'
[gate]
target_drift = "record"

[paths]
source_roots = ["."]

[forbidden_calls.dynamic]
symbols = ["eval", "exec"]
reason = "Dynamic code execution is prohibited"

[protected_guards.tax_bound]
effects = ["calculate_subtotal"]
guard_calls = []
paths = ["billing.py"]
reason = "tax rate must be validated before pricing"

[deny_changes.keys]
paths = ["**/*.pem", "**/id_rsa"]
reason = "Key material must not be committed"
EOF

cat > billing.py <<'EOF'
def calculate_subtotal(items):
    return sum(item["price"] * item.get("quantity", 1) for item in items)

def calculate_total(items, tax_rate):
    if tax_rate < 0 or tax_rate > 1.0:
        raise ValueError("Tax rate must be between 0.0 and 1.0")
    return calculate_subtotal(items) * (1.0 + tax_rate)
EOF

git add -A
git commit -m "feat: initial order service"
git branch base
```

`base` is the authoritative target revision for the example.

---

## 3. Propose a change

```bash
git checkout -b feature/discount
cat > billing.py <<'EOF'
def calculate_subtotal(items):
    return sum(item["price"] * item.get("quantity", 1) for item in items)

def calculate_total(items, tax_rate):
    return calculate_subtotal(items) * (1.0 + tax_rate)

def apply_discount(code, price):
    return eval(code) * price
EOF
git add -A
git commit -m "feat: discount codes"
```

The change removes the tax-rate guard and adds an `eval` call.

---

## 4. Run the gate

```bash
vc gate --repo . --base base --head HEAD --format text
```

Typical output (an internal build additionally reports `check_not_validated` and
exits 3 — see [release evidence](../release-evidence.md)):

```text
VERDICT: FAIL (exit 1)
Policy: target_blob sha256:…
Reasons: guard_removed, dangerous_call
Findings:
  [BLOCKING] SEM-GUARD-REMOVED (guard_removed) billing.py billing:calculate_total: protecting guard removed for effect calculate_subtotal
  [BLOCKING] SEC-DANGEROUS-CALL (dangerous_call) billing.py eval: policy-forbidden call eval introduced at billing.py:8
Evidence payload: sha256:…
```

Interpretation:

- `SEM-GUARD-REMOVED` is established by solver evidence plus a concrete replay
  witness, not by a heuristic.
- `SEC-DANGEROUS-CALL` matches the target-branch `[forbidden_calls]` rule.
- Exit `1` means the PR is rejected. Fix the patch or add a reviewed waiver on
  the target branch.

---

## 5. Inspect the evidence bundle

```bash
vc gate --repo . --base base --head HEAD --format json --output evidence.json
python - <<'EOF'
import json
bundle = json.load(open("evidence.json"))
print(bundle["payload"]["verdict"]["status"])
for result in bundle["payload"]["check_results"]:
    print(result["check_id"], result["outcome"], result["coverage"])
print(bundle["envelope"]["payload_hash"])
EOF
```

Each finding in `payload.findings` contains:

- `fingerprint` — stable identity used by waivers and SARIF deduplication;
- `evidence` — kind and payload (solver model, replay observation, call site,
  reference, or taint path);
- `premises` — base/merge-base/head commits, blobs, policy hash, toolchain
  fingerprint, and check version.

---

## 6. Fail-closed behaviour to expect

- Unsupported language in the diff → `unsupported_language` gap; the verdict is
  `INCONCLUSIVE` unless a policy acceptance covers every such gap.
- Changed blob above `max_file_bytes` → `parse_resource_limit` gap /
  `INCONCLUSIVE`, not `internal_fault`.
- Target policy unparseable → `ERROR`/`invalid_policy` naming the target blob;
  the builtin bootstrap policy is not silently substituted.
- Missing or stale signed release evidence → `ERROR`/`check_not_validated`.
- A repository under review cannot supply release evidence to clear that fault.

---

## 7. Next steps

- Add the gate to CI: [CI integrations](../integrations/ci_pipelines.md)
- Verdict and acceptance semantics: [verdicts](../verdicts.md)
- Architecture: [architecture](../architecture.md)
