"""Regression tests for check correctness and entity scope fixes.

Covers:
- Internal line deletion mapping (modified vs removed).
- TypeScript single object literal argument compatibility.
- Security variable name word boundaries and OpenAI token regex tightening.
- Centralized authoritative code extensions.
"""

from __future__ import annotations

from verifyci.checks.contract import _call_problem, _sig
from verifyci.checks.security import (
    _SECRET_PATTERNS,
    _SECRET_VAR_NAMES,
    _is_placeholder,
    _valid_secret,
)
from verifyci.contracts.manifest import CODE_EXTENSIONS
from verifyci.contracts.model import DiffEntry, Entity, Hunk
from verifyci.gate.orchestrator import _CODE_SUFFIXES as ORCH_SUFFIXES
from verifyci.checks.semantic import _CODE_SUFFIXES as SEMANTIC_SUFFIXES
from verifyci.scope.entities import (
    CallSite,
    analyze_source,
    build_changed_scope,
    find_matching_entity,
)


def test_internal_deletion_find_matching_entity_count_zero():
    """find_matching_entity with count 0 matches the enclosing head entity."""
    entity = Entity(
        file_path="src/service.py",
        qname="src/service:process",
        kind="function",
        start_line=10,
        end_line=25,
    )
    # Line 15 is inside the function
    match = find_matching_entity([entity], start_line=15, count=0)
    assert match is not None
    assert match.qname == "src/service:process"

    # Line 5 is outside the function
    assert find_matching_entity([entity], start_line=5, count=0) is None
    # Line 0 is invalid
    assert find_matching_entity([entity], start_line=0, count=0) is None


def test_deletion_inside_function_maps_as_modified_not_removed():
    """A hunk deleting lines inside an existing function maps as modified, not removed."""
    base_src = (
        "def compute():\n"  # 1
        "    x = 1\n"       # 2
        "    y = 2\n"       # 3 (deleted)
        "    z = 3\n"       # 4 (deleted)
        "    return x\n"    # 5 -> 3
    )
    head_src = (
        "def compute():\n"  # 1
        "    x = 1\n"       # 2
        "    return x\n"    # 3
    )

    # Deletion hunk: deleted lines 3..4 in base, at new_start 3, count 0 in head
    hunk = Hunk(old_start=3, old_count=2, new_start=3, new_count=0)
    entry = DiffEntry(
        status="M",
        base_path="calc.py",
        head_path="calc.py",
        base_blob="1" * 40,
        head_blob="2" * 40,
        base_mode="100644",
        head_mode="100644",
        base_source=base_src,
        head_source=head_src,
        hunks=(hunk,),
    )

    scope = build_changed_scope([entry])

    assert len(scope.mapped_entities) == 1
    mapped = scope.mapped_entities[0]
    assert mapped["qname"] == "calc:compute"
    assert mapped["change"] == "modified"
    assert mapped["head_blob"] is not None


def test_ts_single_object_literal_argument_call_site():
    """TS f({a: 1}) argument extraction counts positional=1 and records keywords."""
    ts_code = "function f(opts) {}\nf({ a: 1, b: 2 });\n"
    facts = analyze_source("app.ts", ts_code)

    assert len(facts.calls) == 1
    call = facts.calls[0]
    assert call.callee == "f"
    assert call.positional == 1
    assert "a" in call.keywords
    assert "b" in call.keywords


def test_ts_single_object_literal_argument_contract_compatibility():
    """TS f({a: 1}) is compatible with function f(opts) and does not trigger errors."""
    entity = Entity(
        file_path="src/api.ts",
        qname="src/api:handle",
        kind="function",
        start_line=1,
        end_line=5,
        parameters=(("opts", "positional", False),),
    )
    sig = _sig(entity)
    assert sig.is_ts
    assert sig.required_positional == 1

    # Call with a single object literal argument
    call = CallSite(callee="handle", line=10, positional=1, keywords=("a", "b"))
    problem = _call_problem(call, sig)
    assert problem == "", f"Expected no problem, got: {problem}"

    # Call with 0 arguments should still fail with too_few_positional_arguments
    empty_call = CallSite(callee="handle", line=10, positional=0, keywords=())
    assert _call_problem(empty_call, sig) == "too_few_positional_arguments"


def test_security_secret_var_names_word_boundaries():
    """_SECRET_VAR_NAMES must match on identifier boundaries and avoid false substrings."""
    # Positive matches
    assert _SECRET_VAR_NAMES.search("token") is not None
    assert _SECRET_VAR_NAMES.search("api_key") is not None
    assert _SECRET_VAR_NAMES.search("secret") is not None
    assert _SECRET_VAR_NAMES.search("db_password") is not None
    assert _SECRET_VAR_NAMES.search("AUTH_TOKEN") is not None
    assert _SECRET_VAR_NAMES.search("user_private_key") is not None

    # Negative matches (unrelated identifiers containing substrings)
    assert _SECRET_VAR_NAMES.search("tokenizer") is None
    assert _SECRET_VAR_NAMES.search("secretariat") is None
    assert _SECRET_VAR_NAMES.search("betokening") is None
    assert _SECRET_VAR_NAMES.search("retoken") is None
    assert _SECRET_VAR_NAMES.search("passwordless") is None


def test_security_placeholder_detection_word_boundaries():
    """Placeholder detection does not treat arbitrary substrings as placeholders."""
    # Real placeholders
    assert _is_placeholder("example")
    assert _is_placeholder("mock_secret_key")
    assert _is_placeholder("your_api_key")
    assert _is_placeholder("changeme")
    assert _is_placeholder("foo-example-bar")

    # High-entropy tokens containing 'example' or 'mock' as inner substring
    assert not _is_placeholder("sk-proj-abcexample1234567890abcdef")
    assert not _is_placeholder("AKIAmock9876543210FEDCBA")


def test_security_openai_token_regex_rejects_sklearn():
    """OpenAI token regex rejects sklearn and sk-learn package names."""
    openai_pattern = next(pat for name, pat in _SECRET_PATTERNS if name == "OPENAI_KEY")

    # Package names must not match
    assert openai_pattern.search("sk-learn") is None
    assert openai_pattern.search("sklearn") is None
    assert openai_pattern.search("sk-learning-model") is None
    assert not _valid_secret("OPENAI_KEY", "sk-learn")[0]
    assert not _valid_secret("OPENAI_KEY", "sklearn")[0]

    # Valid OpenAI keys must match
    valid_key = "sk-proj-" + "A" * 48
    match = openai_pattern.search(valid_key)
    assert match is not None
    assert _valid_secret("OPENAI_KEY", valid_key)[0]


def test_authoritative_code_extensions_consistency():
    """Centralized CODE_EXTENSIONS matches across orchestrator, contract, and semantic."""
    assert CODE_EXTENSIONS == ORCH_SUFFIXES
    assert CODE_EXTENSIONS == SEMANTIC_SUFFIXES

    expected_extensions = {
        "py", "pyi", "ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts",
        "go", "rs", "java", "kt", "kts", "c", "cc", "cpp", "cxx", "h", "hpp",
        "cs", "rb", "php", "swift", "scala", "lua", "ex", "exs", "erl", "hrl",
    }
    assert CODE_EXTENSIONS == expected_extensions
