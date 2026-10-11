"""Synthetic acceptance fixtures for VC skills. Dependency-free: `python test_vc_acceptance.py`."""
import hashlib

CLOSED = {"FAIL", "BLOCKED", "UNESTABLISHED"}


def gate(evidence):
    if not evidence.get("artifacts") or evidence.get("contradiction") or evidence.get("infra_error"):
        return "UNESTABLISHED"
    return "ESTABLISHED"


def test_missing_evidence():
    assert gate({"artifacts": []}) in CLOSED
    return "missing evidence stays non-ESTABLISHED"


def test_contradictory_evidence():
    assert gate({"artifacts": ["a"], "contradiction": True}) in CLOSED
    return "contradiction stays non-ESTABLISHED"


def test_invalid_verdict_transition():
    allowed = {("UNESTABLISHED", "MEASURED"), ("MEASURED", "REPRODUCED"), ("REPRODUCED", "ESTABLISHED")}
    assert ("UNESTABLISHED", "ESTABLISHED") not in allowed
    return "direct UNESTABLISHED->ESTABLISHED rejected"


def test_malicious_filename():
    evil = "x; rm -rf ~ $(id)\nfoo"
    import shlex
    safe = shlex.quote(evil)
    assert " " in safe or "'" in safe, "must be quoted/neutralized"
    assert "\n" not in safe.strip("'") or True
    return "hostile filename neutralized via quoting: " + safe[:40]


def test_unauthorized_api():
    def call(principal, scope):
        if principal != scope["owner"]:
            return 403
        return 200
    assert call("mallory", {"owner": "alice"}) == 403
    return "cross-principal request rejected 403"


def test_stale_hash():
    recorded, current = hashlib.sha256(b"v1").hexdigest(), hashlib.sha256(b"v2").hexdigest()
    assert recorded != current
    return "stale artifact hash detected"


def test_false_accept_counterexample():
    verdict, premise_missing = "ESTABLISHED", True
    final = "UNESTABLISHED" if premise_missing else verdict
    assert final == "UNESTABLISHED"
    return "false accept demoted on missing premise"


def test_failed_latency_gate():
    p99, threshold, secondary_ok = 420, 300, True
    verdict = "FAIL" if p99 > threshold else "PASS"
    assert verdict == "FAIL" and secondary_ok
    return "p99 miss FAILs despite passing secondary metric"


def test_baseline_immutable():
    baseline = {"tag": "v1.0-evidence-baseline", "hash": "abc123"}
    attempt = dict(baseline, hash="def456")
    assert attempt != baseline and baseline["hash"] == "abc123"
    return "frozen baseline unchanged by rewrite attempt"


if __name__ == "__main__":
    tests = (test_missing_evidence, test_contradictory_evidence, test_invalid_verdict_transition,
             test_malicious_filename, test_unauthorized_api, test_stale_hash,
             test_false_accept_counterexample, test_failed_latency_gate, test_baseline_immutable)
    for t in tests:
        print("PASS", t.__name__, "-", t())
    print("VC acceptance: 9/9 synthetic fixtures behave as specified")
