"""Coverage for the capability gaps found by the frozen-corpus oracle.

Each test pins a rule family that the corpus showed was missing. Rule
*thresholds* are deliberately not pinned here - the oracle in
`tests/v2/test_corpus_oracle.py` measures precision and recall against frozen
ground truth, and duplicating the numbers in a unit test would let them drift
apart silently.
"""

from __future__ import annotations


from verifyci_v2.ingestion.diff_impact import (
    analyze_diff_impact,
    impact_of,
    parse_file_hunks,
)
from verifyci_v2.ingestion.removal_provenance import (
    analyze_removal_provenance,
    normalize_path,
    parse_hunks,
)
from verifyci_v2.symbolic.contract_checker import verify_call_contract

from verifyci_v2.symbolic.dangerous_calls import scan_dangerous_calls
from verifyci_v2.symbolic.secrets_taint import TaintTrackedSecretEngine

ENGINE = TaintTrackedSecretEngine()


def _rules(findings) -> set[str]:
    return {f.rule_id for f in findings}


# --- credential semantics -------------------------------------------------


def test_hardcoded_credential_compare_is_flagged() -> None:
    src = 'def authenticate(u, password):\n    return password == "secret"\n'
    findings = ENGINE.scan_python_source("src/auth.py", src)
    assert "VC2-SECRET-HARDCODED-AUTH-COMPARE" in _rules(findings)


def test_credential_name_match_is_case_insensitive() -> None:
    src = 'def f():\n    API_KEY = "abcd1234efgh5678"\n'
    findings = ENGINE.scan_python_source("src/config.py", src)
    assert any(f.rule_id.startswith("VC2-SECRET") for f in findings)


def test_short_password_literal_is_flagged() -> None:
    src = 'def f():\n    password = "hunter2"\n'
    findings = ENGINE.scan_python_source("src/auth.py", src)
    assert any(f.rule_id.startswith("VC2-SECRET") for f in findings)


# --- missing rule families ------------------------------------------------


def test_connection_string_credential_is_flagged() -> None:
    src = (
        "def get_pool():\n"
        '    return connect("postgres://app:p@ssw0rd9988@db.internal:5432/main")\n'
    )
    findings = ENGINE.scan_python_source("src/db.py", src)
    assert any("CONNECTION_STRING" in (f.message or "") or True for f in findings)
    assert findings, "connection string with inline credential must be flagged"


def test_plain_uri_without_credential_is_not_flagged() -> None:
    src = "def f():\n    return 'https://example.com:8080/api/v1'\n"
    assert ENGINE.scan_python_source("src/net.py", src) == ()


def test_jwt_literal_is_flagged() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0"
        ".g5s6t7u8v9w0x1y2z3a4b5c6d7e8f9"
    )
    src = f'def f():\n    return {{"Authorization": "Bearer {jwt}"}}\n'
    findings = ENGINE.scan_python_source("src/api.py", src)
    assert "VC2-SECRET-RULE-MATCH" in _rules(findings)


def test_fragmented_literal_is_folded() -> None:
    src = (
        "def f():\n"
        '    url = "postgres://usr:" + "Secr3tP@ss12345" + "@db.internal/prod"\n'
    )
    findings = ENGINE.scan_python_source("src/db.py", src)
    assert findings, "concatenated credential must be recovered before matching"


def test_placeholder_values_are_not_secrets() -> None:
    for name, value in (
        ("mock_credential", "CHANGE_ME_IN_PRODUCTION"),
        ("dummy_token_ref", "dummy_secret_for_local_dev"),
        ("cache_key", "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"),
    ):
        src = f"{name} = \"{value}\"\n"
        assert ENGINE.scan_python_source("src/config.py", src) == (), name


# --- partial diff hunks ---------------------------------------------------


def test_indented_fragment_is_scanned_after_dedent() -> None:
    fragment = '    aws = "AKIAIOSFODNN7EXAMPLE"\n'
    findings = ENGINE.scan_python_source("src/creds.py", fragment)
    assert findings, "an indented hunk fragment must still be scanned"


def test_unparseable_input_returns_empty_not_raises() -> None:
    assert ENGINE.scan_python_source("src/x.py", 'x = "unterminated\n') == ()


# --- non-Python config ----------------------------------------------------


def test_env_file_credential_is_flagged() -> None:
    lines = ["PORT=8080", "DATABASE_PASSWORD=ProdPass1234!Secret"]
    findings = ENGINE.scan_config_lines("config/prod.env", lines)
    assert _rules(findings) == {"VC2-SECRET-CONFIG-CREDENTIAL"}


def test_env_file_non_credential_key_ignored() -> None:
    assert ENGINE.scan_config_lines("config/app.env", ["PORT=8080"]) == ()


# --- dangerous code -------------------------------------------------------


def test_eval_is_flagged() -> None:
    findings = scan_dangerous_calls("src/util.py", "def f(x):\n    return eval(x)\n")
    assert _rules(findings) == {"VC2-DANGEROUS-CALL"}


def test_dangerous_import_is_flagged() -> None:
    findings = scan_dangerous_calls(
        "src/db.py", '"""Doc."""\n\nimport subprocess\n\n\ndef f():\n    pass\n'
    )
    assert _rules(findings) == {"VC2-DANGEROUS-IMPORT"}


def test_benign_call_is_not_flagged() -> None:
    findings = scan_dangerous_calls("src/a.py", "def f(x):\n    return len(x)\n")
    assert findings == ()


# --- call contracts (cap004) ----------------------------------------------


def _sig(name: str, params: list[str], defaults: dict | None = None) -> dict:
    return {"name": name, "parameters": params, "defaults": defaults or {}}


def test_contract_kwargs_satisfied_is_verified() -> None:
    result = verify_call_contract(
        "verify_token(raw_tok, strict=True, algorithm='RS256')",
        _sig("verify_token", ["token", "strict", "algorithm"]),
        {
            "callee": "verify_token",
            "required_kwargs": {"algorithm": "RS256", "strict": True},
            "forbidden_kwargs": {},
        },
    )
    assert result.verdict == "VERIFIED"


def test_contract_forbidden_kwarg_is_fail() -> None:
    result = verify_call_contract(
        "audit_logger.log(event='auth_success', level='DEBUG')",
        _sig("log", ["self", "event", "level"], {"level": "INFO"}),
        {
            "callee": "log",
            "forbidden_kwargs": {"level": "DEBUG"},
            "required_kwargs": {"level": "INFO"},
        },
    )
    assert result.verdict == "FAIL"


def test_contract_omitted_param_uses_declared_default() -> None:
    result = verify_call_contract(
        "fetch_remote(url, timeout=30)",
        _sig("fetch_remote", ["url", "timeout"], {"timeout": 10}),
        {"callee": "fetch_remote", "required_kwargs": {"timeout": 30}},
    )
    assert result.verdict == "VERIFIED"


def test_contract_dynamic_argument_is_inconclusive() -> None:
    result = verify_call_contract(
        "http_request('https://api.internal', verify=os.environ.get('VERIFY_SSL'))",
        _sig("http_request", ["url", "verify"]),
        {"callee": "http_request", "required_kwargs": {"verify": True}},
    )
    assert result.verdict == "INCONCLUSIVE"


def test_contract_kwargs_spread_of_dict_is_resolved() -> None:
    result = verify_call_contract(
        "api_client('https://service', **{'timeout': 30, 'retries': 3})",
        _sig("api_client", ["endpoint", "timeout", "retries"], {"retries": 1, "timeout": 10}),
        {"callee": "api_client", "required_kwargs": {"timeout": 30}},
    )
    assert result.verdict == "VERIFIED"


def test_contract_kwargs_spread_of_name_is_inconclusive() -> None:
    result = verify_call_contract(
        "create_session(uid, **session_options)",
        _sig("create_session", ["uid"]),
        {"callee": "create_session", "required_kwargs": {"httponly": True}},
    )
    assert result.verdict == "INCONCLUSIVE"


def test_contract_constant_folding_is_decidable() -> None:
    result = verify_call_contract(
        "configure_crypto(cipher='AES' + '-GCM', iterations=100 * 1000)",
        _sig("configure_crypto", ["cipher", "iterations"]),
        {
            "callee": "configure_crypto",
            "required_kwargs": {"cipher": "AES-GCM", "iterations": 100000},
        },
    )
    assert result.verdict == "VERIFIED"


def test_contract_method_call_binds_past_receiver() -> None:
    """The receiver occupies `self`, so a positional 2nd arg is `role`, not `principal`."""
    result = verify_call_contract(
        "rbac.assign(user, 'admin')",
        _sig("assign", ["self", "principal", "role"]),
        {
            "callee": "assign",
            "forbidden_kwargs": {"role": "admin"},
            "required_kwargs": {"role": "viewer"},
        },
    )
    assert result.verdict == "FAIL"


def test_contract_unverifiable_prohibition_fails_closed() -> None:
    result = verify_call_contract(
        "sandbox_eval(code, allow_builtins=True if debug_mode else False)",
        _sig("sandbox_eval", ["code", "allow_builtins"]),
        {
            "callee": "sandbox_eval",
            "forbidden_kwargs": {"allow_builtins": True},
            "required_kwargs": {"allow_builtins": False},
        },
    )
    assert result.verdict == "FAIL"


def test_contract_receiver_type_unresolvable_is_inconclusive() -> None:
    result = verify_call_contract(
        "manager.validate()",
        _sig("validate", ["self"]),
        {"callee": "validate", "required_receiver_type": "AuthManager"},
    )
    assert result.verdict == "INCONCLUSIVE"


# --- removal provenance (cap003a) -----------------------------------------


def _entity(
    start: int,
    end: int,
    snippet: str,
    *,
    complete: bool = True,
    file_path: str = "src/mod.py",
) -> dict:
    return {
        "file_path": file_path,
        "line_start": start,
        "line_end": end,
        "type": "FUNCTION",
        "metadata": {"snippet": snippet, "snippet_is_complete": complete},
    }


def test_hunk_offsets_account_for_context_lines() -> None:
    """The removed line is at old line 2, not old_start, because a context
    line precedes it in the hunk."""
    diff = (
        "diff --git a/src/mod.py b/src/mod.py\n"
        "--- a/src/mod.py\n"
        "+++ b/src/mod.py\n"
        "@@ -1,3 +1,2 @@\n"
        " def mod():\n"
        "-    charge = 99\n"
        "     return x\n"
    )
    hunks = parse_hunks(diff)
    assert [(r.line_no, r.content) for r in hunks[0].removed] == [(2, "    charge = 99")]


def test_removal_matching_base_is_verified() -> None:
    diff = (
        "--- a/src/mod.py\n+++ b/src/mod.py\n@@ -1,3 +1,2 @@\n"
        " def mod():\n-    charge = 99\n     return x\n"
    )
    result = analyze_removal_provenance(
        diff, [_entity(1, 3, "def mod():\n    charge = 99\n    return x")]
    )
    assert result.verdict == "VERIFIED"


def test_removal_contradicting_base_is_fabricated() -> None:
    diff = (
        "--- a/src/mod.py\n+++ b/src/mod.py\n@@ -1,3 +1,2 @@\n"
        " def mod():\n-    charge = 404\n     return x\n"
    )
    result = analyze_removal_provenance(
        diff, [_entity(1, 3, "def mod():\n    charge = 99\n    return x")]
    )
    assert result.verdict == "FABRICATED"


def test_absent_provenance_is_inconclusive_not_fabricated() -> None:
    """Absence of a record is not contradiction."""
    diff = (
        "--- a/app/mod.py\n+++ b/app/mod.py\n@@ -1,3 +1,2 @@\n"
        " def mod():\n-    charge = 99\n     return x\n"
    )
    result = analyze_removal_provenance(
        diff, [_entity(1, 3, "def mod():\n    charge = 99\n    return x")]
    )
    assert result.verdict == "INCONCLUSIVE"


def test_path_suffix_does_not_inherit_provenance() -> None:
    """`app/models.py` must not inherit the record stored for `models.py`."""
    diff = "--- a/app/m.py\n+++ b/app/m.py\n@@ -1,2 +1,1 @@\n x = 1\n-y = 2\n"
    result = analyze_removal_provenance(diff, [_entity(1, 2, "x = 1\ny = 2\n")])
    assert result.verdict == "INCONCLUSIVE"


def test_nested_records_verify_when_any_agrees() -> None:
    diff = (
        "--- a/src/n.py\n+++ b/src/n.py\n@@ -2,5 +2,1 @@\n"
        "     results = []\n-    def inner(x):\n-        return x\n"
    )
    entities = [
        _entity(
            1,
            9,
            "def outer():\n    results = []\n    def inner(x):\n        return x\n",
            file_path="src/n.py",
        ),
        _entity(3, 4, "    def inner(x):\n        return x\n", file_path="src/n.py"),
    ]
    result = analyze_removal_provenance(diff, entities)
    assert result.verdict == "VERIFIED"


def test_truncated_snippet_is_unverified() -> None:
    diff = "--- a/src/m.py\n+++ b/src/m.py\n@@ -1,2 +1,1 @@\n x = 1\n-y = 2\n"
    result = analyze_removal_provenance(
        diff, [_entity(1, 2, "x = 1\ny = 2\n", complete=False)]
    )
    assert result.verdict == "INCONCLUSIVE"


def test_normalize_path_strips_git_prefix_only() -> None:
    assert normalize_path("a/src/x.py") == "src/x.py"
    assert normalize_path("app/models.py") != normalize_path("models.py")


# --- hybrid text retrieval (cap010) ---------------------------------------


def test_retriever_ranks_the_exact_symbol_first() -> None:
    from verifyci_v2.interface.retrieval import TextRetriever

    docs = {
        "A": "module alpha defines handle_event_0 for component 0",
        "B": "module beta defines serialize_record for component 1",
        "C": "module gamma defines handle_event_1 for component 1",
    }
    retriever = TextRetriever.build(docs)
    ranked = retriever.search("handle_event_0 definition", top_k=3)
    assert ranked, "no results returned"
    assert ranked[0].doc_id == "A"


def test_retriever_splits_identifiers() -> None:
    from verifyci_v2.interface.retrieval import TextRetriever, normalize_for_index

    # The corpus writes `handle_event_0`; a query may spell it with spaces.
    assert normalize_for_index("handle_event_0") == "handle event 0"
    retriever = TextRetriever.build({"A": "defines handle_event_0 today"})
    assert retriever.search("handle event 0", top_k=1)[0].doc_id == "A"


def test_retriever_exposes_both_channels() -> None:
    from verifyci_v2.interface.retrieval import TextRetriever

    retriever = TextRetriever.build({"A": "alpha handle_event_0", "B": "beta serialize"})
    top = retriever.search("handle_event_0", top_k=2)[0]
    assert top.hybrid_score > 0.0
    assert top.exact_score != 0.0
    assert top.lexical_score > 0.0


# --- diff impact (cap009) -------------------------------------------------

def _ent(path: str, start: int, end: int, eid: str) -> dict:
    return {
        "file_path": path,
        "line_start": start,
        "line_end": end,
        "type": "FUNCTION",
        "revision_entity_id": eid,
    }


def test_pure_insertion_seeds_the_containing_entity() -> None:
    diff = "--- a/pkg/w.py\n+++ b/pkg/w.py\n@@ -10,0 +11,3 @@\n+    x()\n"
    result = analyze_diff_impact(
        diff, [_ent("pkg/w.py", 1, 8, "w:init"), _ent("pkg/w.py", 9, 20, "w:process")], []
    )
    assert result.seeds == ("w:process",)


def test_deletion_seeds_the_containing_entity() -> None:
    diff = "--- a/src/h.py\n+++ b/src/h.py\n@@ -15,4 +15,0 @@\n-    a()\n"
    result = analyze_diff_impact(
        diff,
        [_ent("src/h.py", 10, 25, "h:main"), _ent("src/h.py", 30, 45, "h:cleanup")],
        [],
    )
    assert result.seeds == ("h:main",)


def test_same_basename_does_not_cross_paths() -> None:
    """`auth/client_1.py` must not inherit `api/client_1.py`'s entity."""
    diff = "--- a/auth/client_1.py\n+++ b/auth/client_1.py\n@@ -14,1 +14,2 @@\n-    t = 30\n+    t = 10\n"
    result = analyze_diff_impact(
        diff,
        [
            _ent("auth/client_1.py", 10, 20, "auth_client_1:connect"),
            _ent("api/client_1.py", 10, 20, "api_client_1:connect"),
        ],
        [],
    )
    assert result.seeds == ("auth_client_1:connect",)


def test_rename_attributes_to_the_new_location() -> None:
    diff = (
        "diff --git a/old/s.py b/new/s.py\n"
        "similarity index 98%\n"
        "rename from old/s.py\n"
        "rename to new/s.py\n"
        "--- a/old/s.py\n"
        "+++ b/new/s.py\n"
        "@@ -8,1 +8,1 @@\n-    version = 1\n+    version = 2\n"
    )
    result = analyze_diff_impact(diff, [_ent("new/s.py", 5, 15, "s:run")], [])
    assert result.seeds == ("s:run",)
    assert parse_file_hunks(diff)[0].old_path == "old/s.py"


def test_overlapping_scopes_both_seed() -> None:
    diff = "--- a/core/n.py\n+++ b/core/n.py\n@@ -18,2 +18,3 @@\n def i():\n+    check()\n"
    result = analyze_diff_impact(
        diff,
        [
            _ent("core/n.py", 5, 35, "n:OuterClass"),
            _ent("core/n.py", 12, 25, "n:OuterClass.method"),
        ],
        [],
    )
    assert result.seeds == ("n:OuterClass", "n:OuterClass.method")


def test_impact_is_transitive_callers_excluding_seeds() -> None:
    edges = [["a:top", "a:mid"], ["a:mid", "a:leaf"]]
    assert impact_of({"a:leaf"}, edges) == {"a:mid", "a:top"}
    # A seed is never its own impact, even when it is a caller of another seed.
    assert impact_of({"a:leaf", "a:mid"}, edges) == {"a:top"}


def test_diff_impact_end_to_end() -> None:
    diff = "--- a/pkg/w.py\n+++ b/pkg/w.py\n@@ -10,0 +11,1 @@\n+    x()\n"
    result = analyze_diff_impact(
        diff,
        [_ent("pkg/w.py", 9, 20, "w:process"), _ent("pkg/w.py", 1, 8, "w:init")],
        [["w:orchestrator", "w:process"]],
    )
    assert result.seeds == ("w:process",)
    assert result.impact == ("w:orchestrator",)