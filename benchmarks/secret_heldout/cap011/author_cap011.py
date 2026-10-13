#!/usr/bin/env python3
"""CAP-011 Corpus Authoring Script: Held-Out Secret Detection & Redaction Safety.

Clean-room independent authoring tool.
Synthesizes 50 held-out cases:
- 30 positive secret cases across 5 slices (name_independent, provider_structured,
  encoded, connection_strings, private_keys)
- 20 negative cases across 2 slices (negatives_placeholders, negatives_test_fixtures)
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

CORPUS_DIR = Path(__file__).resolve().parent


def build_cap011_cases() -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    cases: list[dict[str, Any]] = []
    labels: list[dict[str, Any]] = []
    slice_counts: dict[str, int] = {}

    case_idx = 1

    def _diff(content: str, path: str = "src/config.py", lineno: int = 1) -> str:
        return (
            f"diff --git a/{path} b/{path}\n"
            f"--- a/{path}\n"
            f"+++ b/{path}\n"
            f"@@ -{lineno},0 +{lineno},1 @@\n"
            f"+{content}\n"
        )

    # Slice 1: name_independent (10 positives with neutral identifiers like x, val, buf, target)
    slice_name = "name_independent"
    slice_counts[slice_name] = 10
    ni_secrets = [
        ("sk-live-" + hashlib.sha256(f"ni_openai_{i}".encode()).hexdigest()[:32], "provider_openai_key", f"x_{i}")
        for i in range(1, 6)
    ] + [
        ("ghp_" + hashlib.sha256(f"ni_ghp_{i}".encode()).hexdigest()[:36], "provider_github_token", f"temp_{i}")
        for i in range(6, 11)
    ]
    for secret, rule, var_name in ni_secrets:
        cid = f"CAP011-{case_idx:03d}"
        diff_text = _diff(f'{var_name} = "{secret}"', path=f"src/util_{case_idx}.py")
        cases.append({
            "case_id": cid,
            "slice": slice_name,
            "diff": diff_text,
            "path": f"src/util_{case_idx}.py",
            "is_secret": True,
            "synthetic_secret": secret,
        })
        labels.append({
            "case_id": cid,
            "slice": slice_name,
            "is_secret": True,
            "expected_rules": [rule],
            "synthetic_secret": secret,
        })
        case_idx += 1

    # Slice 2: provider_structured (5 positives)
    slice_name = "provider_structured"
    slice_counts[slice_name] = 5
    ps_secrets = [
        (f"AKIA{hashlib.sha256(f'aws_{i}'.encode()).hexdigest()[:16].upper()}", "provider_aws_access_key", "aws_key_id")
        for i in range(1, 6)
    ]
    for secret, rule, var_name in ps_secrets:
        cid = f"CAP011-{case_idx:03d}"
        diff_text = _diff(f'{var_name} = "{secret}"', path=f"src/cloud_{case_idx}.py")
        cases.append({
            "case_id": cid,
            "slice": slice_name,
            "diff": diff_text,
            "path": f"src/cloud_{case_idx}.py",
            "is_secret": True,
            "synthetic_secret": secret,
        })
        labels.append({
            "case_id": cid,
            "slice": slice_name,
            "is_secret": True,
            "expected_rules": [rule],
            "synthetic_secret": secret,
        })
        case_idx += 1

    # Slice 3: encoded (5 positives with base64 / hex)
    slice_name = "encoded"
    slice_counts[slice_name] = 5
    for i in range(1, 6):
        cid = f"CAP011-{case_idx:03d}"
        raw_token = f"sk-live-{hashlib.sha256(f'enc_{i}'.encode()).hexdigest()[:32]}"
        if i % 2 == 1:
            encoded_str = base64.b64encode(raw_token.encode()).decode()
            line = f'encoded_blob_{i} = "{encoded_str}"'
        else:
            encoded_str = raw_token.encode().hex()
            line = f'hex_credential_{i} = "{encoded_str}"'
        diff_text = _diff(line, path=f"src/storage_{case_idx}.py")
        cases.append({
            "case_id": cid,
            "slice": slice_name,
            "diff": diff_text,
            "path": f"src/storage_{case_idx}.py",
            "is_secret": True,
            "synthetic_secret": raw_token,
        })
        labels.append({
            "case_id": cid,
            "slice": slice_name,
            "is_secret": True,
            "expected_rules": ["provider_openai_key"],
            "synthetic_secret": raw_token,
        })
        case_idx += 1

    # Slice 4: connection_strings (5 positives)
    slice_name = "connection_strings"
    slice_counts[slice_name] = 5
    for i in range(1, 6):
        cid = f"CAP011-{case_idx:03d}"
        pwd = f"S3cur3Pass_{i}!"
        conn = f"postgres://db_user_{i}:{pwd}@db.production.internal:5432/orders_{i}"
        diff_text = _diff(f'database_uri_{i} = "{conn}"', path=f"src/db_{case_idx}.py")
        cases.append({
            "case_id": cid,
            "slice": slice_name,
            "diff": diff_text,
            "path": f"src/db_{case_idx}.py",
            "is_secret": True,
            "synthetic_secret": conn,
        })
        labels.append({
            "case_id": cid,
            "slice": slice_name,
            "is_secret": True,
            "expected_rules": ["credential_connection_string"],
            "synthetic_secret": conn,
        })
        case_idx += 1

    # Slice 5: private_keys (5 positives)
    slice_name = "private_keys"
    slice_counts[slice_name] = 5
    for i in range(1, 6):
        cid = f"CAP011-{case_idx:03d}"
        key_body = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0...\\n-----END RSA PRIVATE KEY-----"
        diff_text = _diff(f'signing_key_{i} = "{key_body}"', path=f"src/crypto_{case_idx}.py")
        cases.append({
            "case_id": cid,
            "slice": slice_name,
            "diff": diff_text,
            "path": f"src/crypto_{case_idx}.py",
            "is_secret": True,
            "synthetic_secret": "-----BEGIN RSA PRIVATE KEY-----",
        })
        labels.append({
            "case_id": cid,
            "slice": slice_name,
            "is_secret": True,
            "expected_rules": ["crypto_private_key"],
            "synthetic_secret": "-----BEGIN RSA PRIVATE KEY-----",
        })
        case_idx += 1

    # Slice 6: negatives_placeholders (10 negatives)
    slice_name = "negatives_placeholders"
    slice_counts[slice_name] = 10
    placeholders = [
        'doc_placeholder = "YOUR_API_KEY_HERE"',
        'config_template = "<INSERT_TOKEN_HERE>"',
        'placeholder_val = "TODO_REPLACE_WITH_PRODUCTION_SECRET"',
        'mock_credential = "CHANGE_ME_IN_PRODUCTION"',
        'sample_mask = "****************"',
        'dummy_token_ref = "dummy_secret_for_local_dev"',
        'sample_param = "example-token-12345"',
        'format_string = "{YOUR_CREDENTIALS}"',
        'env_var_hint = "export SERVICE_KEY=<placeholder>"',
        'api_doc_example = "https://api.example.com/v1/auth?token=REPLACE_ME"',
    ]
    for ph in placeholders:
        cid = f"CAP011-{case_idx:03d}"
        diff_text = _diff(ph, path=f"src/config_{case_idx}.py")
        cases.append({
            "case_id": cid,
            "slice": slice_name,
            "diff": diff_text,
            "path": f"src/config_{case_idx}.py",
            "is_secret": False,
            "synthetic_secret": None,
        })
        labels.append({
            "case_id": cid,
            "slice": slice_name,
            "is_secret": False,
            "expected_rules": [],
            "synthetic_secret": None,
        })
        case_idx += 1

    # Slice 7: negatives_test_fixtures (10 negatives: commit hashes, UUIDs, math constants)
    slice_name = "negatives_test_fixtures"
    slice_counts[slice_name] = 10
    fixtures = [
        'commit_sha = "76c19df2b826a6f4ce6fc1749b5314048514298c"',
        'parent_sha = "c3f19a0029b4e1837bc39d892839487b92738d82"',
        'task_uuid = "f5bee46f-014f-444a-a24d-0c60f9846902"',
        'session_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"',
        'digest_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
        'cache_key = "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"',
        'metric_bucket = "bucket_8293740291823746"',
        'pi_constant = 3.14159265358979323846',
        'matrix_seed = 0xdeadbeefcafebabe',
        'telemetry_id = "tel_998877665544332211"',
    ]
    for fix in fixtures:
        cid = f"CAP011-{case_idx:03d}"
        diff_text = _diff(fix, path=f"tests/test_{case_idx}.py")
        cases.append({
            "case_id": cid,
            "slice": slice_name,
            "diff": diff_text,
            "path": f"tests/test_{case_idx}.py",
            "is_secret": False,
            "synthetic_secret": None,
        })
        labels.append({
            "case_id": cid,
            "slice": slice_name,
            "is_secret": False,
            "expected_rules": [],
            "synthetic_secret": None,
        })
        case_idx += 1

    return cases, labels, slice_counts


def write_frozen_corpus() -> None:
    cases, labels, slice_counts = build_cap011_cases()
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)

    cases_file = CORPUS_DIR / "cases.jsonl"
    labels_file = CORPUS_DIR / "labels.jsonl"

    cases_text = "\n".join(json.dumps(c, sort_keys=True) for c in cases) + "\n"
    labels_text = "\n".join(json.dumps(lbl, sort_keys=True) for lbl in labels) + "\n"

    cases_file.write_bytes(cases_text.encode("utf-8"))
    labels_file.write_bytes(labels_text.encode("utf-8"))

    c_hash = hashlib.sha256(cases_file.read_bytes()).hexdigest()
    l_hash = hashlib.sha256(labels_file.read_bytes()).hexdigest()

    (CORPUS_DIR / "CORPUS_SHA256").write_bytes((c_hash + "\n").encode("utf-8"))
    (CORPUS_DIR / "LABEL_SHA256").write_bytes((l_hash + "\n").encode("utf-8"))

    config = {
        "experiment_id": "CAP-011",
        "title": "Held-Out Secret Detection and Redaction Safety Benchmark",
        "case_count": len(cases),
        "positive_count": sum(1 for c in cases if c["is_secret"]),
        "negative_count": sum(1 for c in cases if not c["is_secret"]),
        "slice_counts": slice_counts,
        "corpus_sha256": c_hash,
        "label_sha256": l_hash,
        "status": "CORPUS_FROZEN",
        "freeze_rule": "Held-out synthetic credentials sealed; CAP-002B corpus left untouched.",
        "gates": {
            "recall_min": 0.95,
            "name_independent_recall_min": 0.90,
            "precision_min": 0.99,
            "redaction_violations_max": 0,
        },
    }
    (CORPUS_DIR / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

    mode_protocol = f"""# CAP-011 Protocol: Held-Out Secret Detection (FROZEN)

**Experiment ID**: CAP-011  
**Corpus SHA-256**: `{c_hash}`  
**Label SHA-256**: `{l_hash}`  
**Total Cases**: {len(cases)} ({config['positive_count']} positive, {config['negative_count']} negative)  

## Slice Distribution
{json.dumps(slice_counts, indent=2)}

## Gates & Invariants
1. **P0-3 Redaction Boundary**: Zero raw secret leakage into logs, reports, or results.json. cases.jsonl is the only authorized location for synthetic credentials.
2. **Name-Independent Recall >= 0.90**: Neutral variable names (x, val, temp) detected via entropy & structural patterns.
3. **Precision >= 0.99**: Negatives (documentation placeholders, UUIDs, test fixture hashes) strictly rejected.
4. **Overall Recall >= 0.95**: Comprehensive coverage of providers, encoded secrets, and private keys.
"""
    (CORPUS_DIR / "MODE_PROTOCOL.md").write_text(mode_protocol, encoding="utf-8")
    print(f"Authored CAP-011: {len(cases)} cases, c_hash={c_hash}, l_hash={l_hash}")


if __name__ == "__main__":
    write_frozen_corpus()
