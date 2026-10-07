# CAP-005 Protocol: Generalization & Real-World Patch Validation (FROZEN)

**Experiment ID**: CAP-005  
**Corpus SHA-256**: `ca475b33a385e8d1478afedf00d2eeeefdc8ae0f72c9e5527f20fc1fe814e17c`  
**Label SHA-256**: `589231d38fdf85a764eab85ba19f1ad9e2839fe63c043c3c9636d745f1893075`  
**Source Manifest SHA-256**: `f330fca7d317ec9a1e8398295d930c49f802e2cc25cf94b3906d7b9b0d47af8d`  
**Harness SHA-256**: `8e8874bea2c45fc941472a921b0c24329e0053fb47f95b68279fdd05a172ef4f`  
**Results SHA-256**: `e7ed2033774e27646232eb8e9ce82b0ee891186acfb35cd2f6529e74fa0133ba`  
**Total Cases**: 64  
**Total Sources**: 5  

## Category & Slice Distribution
- Total Cases: 64
- Pass (Grounded Verification): 38
- Fail (Definitive Rejection): 9
- Human Review (Fail-Closed Escalation): 15
- Inconclusive (Dynamic/Ungrounded/Ambiguous): 2

### Stratified Slices
{
  "authentic_security_patches": 8,
  "production_code_removals": 8,
  "call_site_and_signature_evolution": 8,
  "multi_file_feature_additions": 8,
  "dynamic_runtime_idioms": 8,
  "complex_composite_diffs": 8,
  "agent_generated_hallucinations": 8,
  "manifests_and_documentation": 8
}

### Pre-labeled Falsifier-Bearing Denominator (Lock 3)
{
  "secret_name_independence": 3,
  "removal_provenance": 3,
  "argument_value_blindness": 3
}
**Total Pre-labeled Falsifiers**: 9 (Target P5: 100% caught)

## Core Protocol Locks
1. **Licensing & Provenance First-Class (Lock 1)**:
   Every case records `source_repo`, `source_commit`, `source_license`, and `license_evidence`. All external code is strictly restricted to permissive licenses (MIT, BSD-3, Apache-2.0, or author-owned agent logs).
2. **Gold Labels Sealed (Lock 2)**:
   Labels and expected classifications are sealed before evaluation.
3. **Explicit Falsifier Denominator (Lock 3)**:
   P5 requires 100% detection on the explicitly pre-labeled set of 9 falsifier-bearing cases (`secret_name_independence`, `removal_provenance`, `argument_value_blindness`).
4. **Distributional Latency Gate (Lock 4)**:
   P7 requires recording p50, p95, p99, and max latency, with target $p95 \le 500\text{ms}$ and no resource timeouts.
5. **No Raw Secrets in Logs or Metadata**:
   All credentials are mock tokens or truncated hashes.
