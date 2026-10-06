from verifyci.verification.call_semantics import (
    call_semantics_check,
    extract_calls_from_text,
    verify_call_semantics,
)


def test_extract_calls_simple_and_attribute():
    code = "db.connect('localhost', 5432, ssl=True)"
    calls = extract_calls_from_text(code)
    assert len(calls) == 1
    c = calls[0]
    assert c.callee == "connect"
    assert c.receiver == "db"
    assert len(c.positional_args) == 2
    assert c.positional_args[0] == ("LITERAL", "localhost")
    assert c.positional_args[1] == ("LITERAL", 5432)
    assert "ssl" in c.keyword_args
    assert c.keyword_args["ssl"] == ("LITERAL", True)


def test_constant_folding():
    code = "setup(cipher='AES' + '-GCM', iterations=100 * 1000)"
    calls = extract_calls_from_text(code)
    assert len(calls) == 1
    c = calls[0]
    assert c.keyword_args["cipher"] == ("LITERAL", "AES-GCM")
    assert c.keyword_args["iterations"] == ("LITERAL", 100000)


def test_dynamic_expressions():
    code = "fetch(url, verify=os.environ.get('SSL'))"
    calls = extract_calls_from_text(code, top_level_only=True)
    assert len(calls) == 1
    c = calls[0]
    assert c.callee == "fetch"
    assert c.keyword_args["verify"][0] == "DYNAMIC"


def test_conditional_expression():
    code = "sandbox(allow=True if debug else False)"
    calls = extract_calls_from_text(code)
    assert len(calls) == 1
    c = calls[0]
    kind, val = c.keyword_args["allow"]
    assert kind == "CONDITIONAL"
    (b1_k, b1_v), (b2_k, b2_v) = val
    assert b1_v is True and b2_v is False


def test_kwargs_unpacking_literal_dict():
    code = "client('endpoint', **{'timeout': 30})"
    calls = extract_calls_from_text(code)
    assert len(calls) == 1
    c = calls[0]
    assert "timeout" in c.keyword_args
    assert c.keyword_args["timeout"] == ("LITERAL", 30)
    assert c.has_kwargs is False


def test_kwargs_unpacking_dynamic():
    code = "client('endpoint', **options)"
    calls = extract_calls_from_text(code)
    assert len(calls) == 1
    c = calls[0]
    assert c.has_kwargs is True


def test_semantic_verification_pass_fail_inconclusive():
    sig = {"parameters": ["token", "strict"], "defaults": {"strict": False}}

    # 1. Matching keyword -> VERIFIED
    c1 = extract_calls_from_text("verify(token, strict=True)")[0]
    status1, _ = verify_call_semantics(c1, {"callee": "verify", "required_kwargs": {"strict": True}}, sig)
    assert status1 == "VERIFIED"

    # 2. Contradicting keyword -> FAIL
    c2 = extract_calls_from_text("verify(token, strict=False)")[0]
    status2, _ = verify_call_semantics(c2, {"callee": "verify", "required_kwargs": {"strict": True}}, sig)
    assert status2 == "FAIL"

    # 3. Dynamic expression -> INCONCLUSIVE
    c3 = extract_calls_from_text("verify(token, strict=get_mode())")[0]
    status3, _ = verify_call_semantics(c3, {"callee": "verify", "required_kwargs": {"strict": True}}, sig)
    assert status3 == "INCONCLUSIVE"


def test_tripwire_n_s4_argument_swap():
    # Replica of CAP-002 N-S4 diff
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
    assert len(check.evidence) > 0
    assert "send_email arguments mutated" in check.evidence[0]
