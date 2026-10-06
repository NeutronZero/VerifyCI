"""CAP-004: Argument-Value and Call-Semantics Verification Test Suite.

Guards:
- Cryptographic freeze hashes for CAP-004 corpus and labels
- Resolution of the CAP-002 N-S4 argument-blindness falsifier
- Positional, keyword, default-argument, and receiver verification
- Constant folding of compile-time expressions
- Absence of proof is not proof of compliance (dynamic -> INCONCLUSIVE)
- Zero false acceptances (FAR = 0.0000) on safety-critical violations
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from verifyci.verification.call_semantics import (
    call_semantics_check,
    extract_calls_from_text,
    verify_call_semantics,
)

HERE = Path(__file__).resolve().parent
CORPUS_DIR = HERE.parent.parent / "benchmarks" / "call_semantics_corpus" / "cap004"

FROZEN_CORPUS_SHA256 = "305da66ef4282c7537d9d0366f5d6726acb2b5557114823298e053dbf038c064"
FROZEN_LABEL_SHA256 = "1733902248e7bc4dcad51c01ffe6e10e362f1a34e899317f958aa4d04d95ab59"


def test_frozen_corpus_and_labels_integrity():
    cases_file = CORPUS_DIR / "cases.jsonl"
    labels_file = CORPUS_DIR / "labels.jsonl"

    assert cases_file.exists(), "CAP-004 cases.jsonl missing"
    assert labels_file.exists(), "CAP-004 labels.jsonl missing"

    c_hash = hashlib.sha256(cases_file.read_bytes()).hexdigest()
    l_hash = hashlib.sha256(labels_file.read_bytes()).hexdigest()

    assert c_hash == FROZEN_CORPUS_SHA256, f"Corpus SHA-256 drift: {c_hash}"
    assert l_hash == FROZEN_LABEL_SHA256, f"Labels SHA-256 drift: {l_hash}"


def test_cap002_n_s4_falsifier_resolved():
    """Replica of CAP-002 N-S4: send_email('a') -> send_email('b')."""
    diff = (
        "diff --git a/src/callers.py b/src/callers.py\n"
        "--- a/src/callers.py\n"
        "+++ b/src/callers.py\n"
        "@@ -3,3 +3,3 @@\n"
        " def notify_1():\n"
        "-    send_email(\"a\")\n"
        "+    send_email(\"b\")\n"
    )
    check = call_semantics_check(diff)
    assert check.passed is False
    assert check.blocking is False
    assert len(check.evidence) == 1
    assert "send_email arguments mutated" in check.evidence[0]


def test_positional_arguments_mapped_to_signature():
    sig = {"parameters": ["host", "port", "use_ssl"], "defaults": {"use_ssl": False}}
    contract = {"callee": "connect_db", "required_args": {"use_ssl": True}}

    # 1. Positional True -> VERIFIED
    c1 = extract_calls_from_text("connect_db('db.local', 5432, True)")[0]
    st1, _ = verify_call_semantics(c1, contract, sig)
    assert st1 == "VERIFIED"

    # 2. Positional False -> FAIL
    c2 = extract_calls_from_text("connect_db('db.local', 5432, False)")[0]
    st2, _ = verify_call_semantics(c2, contract, sig)
    assert st2 == "FAIL"

    # 3. Positional dynamic -> INCONCLUSIVE
    c3 = extract_calls_from_text("connect_db('db.local', 5432, get_ssl())")[0]
    st3, _ = verify_call_semantics(c3, contract, sig)
    assert st3 == "INCONCLUSIVE"


def test_keyword_values_and_constant_folding():
    contract = {"callee": "setup", "required_kwargs": {"cipher": "AES-GCM", "rounds": 100000}}

    # Folded constants -> VERIFIED
    c1 = extract_calls_from_text("setup(cipher='AES' + '-GCM', rounds=100 * 1000)")[0]
    st1, _ = verify_call_semantics(c1, contract)
    assert st1 == "VERIFIED"

    # Contradicting literal -> FAIL
    c2 = extract_calls_from_text("setup(cipher='DES', rounds=1000)")[0]
    st2, _ = verify_call_semantics(c2, contract)
    assert st2 == "FAIL"


def test_conditional_branch_safety():
    contract = {"callee": "sandbox", "required_kwargs": {"allow": False}}

    # Dynamic conditional branch permitting True -> FAIL
    c = extract_calls_from_text("sandbox(allow=True if debug else False)")[0]
    st, why = verify_call_semantics(c, contract)
    assert st == "FAIL"
    assert "conditional branch permits contradicting value" in why


def test_kwargs_dynamic_unpacking_safety():
    sig = {"parameters": ["uid", "secure"], "defaults": {"secure": True}}
    contract = {"callee": "session", "required_kwargs": {"secure": True}}

    # Ungrounded **kwargs unpacking when relying on defaults -> INCONCLUSIVE
    c1 = extract_calls_from_text("session(uid, **options)")[0]
    st1, _ = verify_call_semantics(c1, contract, sig)
    assert st1 == "INCONCLUSIVE"

    # Explicit literal override alongside **kwargs -> FAIL if contradicting
    contract_debug = {"callee": "service", "required_kwargs": {"debug": False}}
    c2 = extract_calls_from_text("service('name', debug=True, **extra)")[0]
    st2, _ = verify_call_semantics(c2, contract_debug)
    assert st2 == "FAIL"


def test_receiver_type_verification():
    contract = {
        "callee": "write",
        "required_receiver_type": "SecureStorage",
        "forbidden_receiver_type": "InsecureStorage",
    }
    c = extract_calls_from_text("store.write('k', 'v')")[0]

    # Matching receiver -> VERIFIED
    st1, _ = verify_call_semantics(c, contract, receiver_type="SecureStorage")
    assert st1 == "VERIFIED"

    # Forbidden receiver -> FAIL
    st2, _ = verify_call_semantics(c, contract, receiver_type="InsecureStorage")
    assert st2 == "FAIL"

    # Ungrounded receiver -> INCONCLUSIVE
    st3, _ = verify_call_semantics(c, contract, receiver_type=None)
    assert st3 == "INCONCLUSIVE"


def test_cap004_benchmark_full_agreement():
    results_path = CORPUS_DIR / "results.json"
    assert results_path.exists(), "results.json not yet generated"
    data = json.loads(results_path.read_text(encoding="utf-8"))

    m1 = data["metrics"]["c1_semantics"]
    assert m1["agreement"] == 1.0, f"Agreement drift: {m1['agreement']}"
    assert m1["false_acceptance_rate"] == 0.0, f"FAR drift: {m1['false_acceptance_rate']}"
    assert m1["false_confidence_rate"] == 0.0, f"FCR drift: {m1['false_confidence_rate']}"
    assert m1["correct"] == 36
    assert m1["total"] == 36
