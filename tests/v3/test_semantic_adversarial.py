"""Empirical Adversarial Stress-Test Suite for Milestone M6 Semantic Engine.

Authored by challenger_m6_1 to stress-test and empirically challenge:
1. Replay sandbox security: forbidden builtins, import statements, and dunder attribute access.
2. Replay timeout handling: termination within 2.0s on infinite loops / hangs.
3. Unconfirmed witness fail-closed: SAT alone never emits finding without concrete replay confirmation.
4. Guard precedence rules: strict order SEM-GUARD-INVERTED -> SEM-GUARD-REMOVED -> SEM-GUARD-WEAKENED.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path
import shutil
import subprocess
import time

import pytest

from verifyci.checks.base import CheckContext
from verifyci.checks.semantic import (
    execute_function_isolated,
    ReplaySafetyViolation,
    replay_witness,
    run as run_semantic,
    _validate_ast_safety,
)
from verifyci.contracts.model import Coverage, Outcome
from verifyci.gate.orchestrator import _augment_scope_with_repository
from verifyci.gate.policy import parse_policy_bytes
from verifyci.scm.git import GitRepo
from verifyci.scope.entities import build_changed_scope


def _build_repo(
    files_base: dict[str, str],
    files_head: dict[str, str],
    target_dir: Path,
) -> tuple[GitRepo, str, str, str]:
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True)

    subprocess.run(["git", "init", "-q", "-b", "main", str(target_dir)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "core.autocrlf", "false"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "user.name", "AdversarialTester"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "user.email", "challenger@verifyci.dev"], check=True, capture_output=True)

    for rel_path, content in files_base.items():
        file_path = target_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8", newline="")

    subprocess.run(["git", "-C", str(target_dir), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(target_dir), "commit", "-q", "-m", "base"], check=True, capture_output=True)
    base_commit = subprocess.check_output(["git", "-C", str(target_dir), "rev-parse", "HEAD"], text=True).strip()

    for item in target_dir.iterdir():
        if item.name != ".git":
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

    for rel_path, content in files_head.items():
        file_path = target_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8", newline="")

    subprocess.run(["git", "-C", str(target_dir), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(target_dir), "commit", "-q", "-m", "head", "--allow-empty"], check=True, capture_output=True)
    head_commit = subprocess.check_output(["git", "-C", str(target_dir), "rev-parse", "HEAD"], text=True).strip()

    return GitRepo(target_dir), base_commit, base_commit, head_commit


# ===========================================================================
# 1. REPLAY SANDBOX SECURITY CHALLENGES
# ===========================================================================

@pytest.mark.parametrize(
    "import_snippet",
    [
        "import os",
        "import sys",
        "import subprocess",
        "from pathlib import Path",
        "from os.path import exists",
        "import math as m",
    ],
)
def test_sandbox_security_blocks_all_import_variants(import_snippet: str):
    """Every form of import statement must trigger ReplaySafetyViolation and fail closed."""
    src = f"""def target_fn(x):
    {import_snippet}
    return x
"""
    # 1. Direct AST validation check
    with pytest.raises(ReplaySafetyViolation) as exc_info:
        _validate_ast_safety(ast.parse(src))
    assert "import statements are forbidden" in str(exc_info.value)

    # 2. execute_function_isolated check
    with pytest.raises(ReplaySafetyViolation):
        execute_function_isolated(src, "target_fn", {"x": 1})

    # 3. replay_witness fails closed
    replay_res = replay_witness(
        base_src="def target_fn(x): return x",
        head_src=src,
        fn_name="target_fn",
        defect_family="SEM-GUARD-REMOVED",
        target="do_action",
        model_values={"x": 1},
    )
    assert replay_res.confirmed is False
    assert "safety violation" in replay_res.reason or "forbidden" in replay_res.reason


@pytest.mark.parametrize(
    "forbidden_func",
    [
        "open",
        "eval",
        "exec",
        "compile",
        "__import__",
        "globals",
        "locals",
        "getattr",
        "setattr",
        "delattr",
        "breakpoint",
        "exit",
        "quit",
        "input",
    ],
)
def test_sandbox_security_blocks_all_forbidden_builtins(forbidden_func: str):
    """Every forbidden function call must trigger ReplaySafetyViolation and fail closed."""
    src = f"""def attack(payload):
    {forbidden_func}(payload)
    return payload
"""
    with pytest.raises(ReplaySafetyViolation) as exc_info:
        _validate_ast_safety(ast.parse(src))
    assert f"forbidden call in replay sandbox: {forbidden_func}" in str(exc_info.value)

    with pytest.raises(ReplaySafetyViolation):
        execute_function_isolated(src, "attack", {"payload": "data"})

    replay_res = replay_witness(
        base_src="def attack(payload): return payload",
        head_src=src,
        fn_name="attack",
        defect_family="SEM-GUARD-REMOVED",
        target="do_action",
        model_values={"payload": "data"},
    )
    assert replay_res.confirmed is False
    assert "safety violation" in replay_res.reason


@pytest.mark.parametrize(
    "dunder_attr",
    [
        "__class__",
        "__subclasses__",
        "__builtins__",
        "__globals__",
        "__code__",
        "__dict__",
        "__base__",
        "__mro__",
    ],
)
def test_sandbox_security_blocks_all_dunder_attribute_access(dunder_attr: str):
    """Access to dunder attributes in replay targets must trigger ReplaySafetyViolation."""
    src = f"""def exploit(obj):
    leak = obj.{dunder_attr}
    return leak
"""
    with pytest.raises(ReplaySafetyViolation) as exc_info:
        _validate_ast_safety(ast.parse(src))
    assert f"dunder attribute access is forbidden in replay sandbox: {dunder_attr}" in str(exc_info.value)

    with pytest.raises(ReplaySafetyViolation):
        execute_function_isolated(src, "exploit", {"obj": {}})

    replay_res = replay_witness(
        base_src="def exploit(obj): return 0",
        head_src=src,
        fn_name="exploit",
        defect_family="SEM-GUARD-REMOVED",
        target="do_action",
        model_values={"obj": {}},
    )
    assert replay_res.confirmed is False
    assert "safety violation" in replay_res.reason


def test_sandbox_security_violation_in_gate_fails_closed_to_inconclusive(tmp_path: Path):
    """If head code contains forbidden operations, gate check fails closed to INCONCLUSIVE (never emits false defect or bypassed pass)."""
    base_src = """def purge(user, item_id):
    if not user.is_admin:
        return
    delete_item(item_id)
"""
    # Head tries to call open() while removing guard
    head_src = """def purge(user, item_id):
    open("/tmp/pwned", "w")
    delete_item(item_id)
"""
    repo, base, mb, head = _build_repo(
        {"src/purge.py": base_src},
        {"src/purge.py": head_src},
        tmp_path / "repo_sandbox_gate",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    policy = dataclasses.replace(
        parse_policy_bytes(b""),
        protected_guards={"del_rule": {"effects": ["delete_item"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-27",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test-adversarial",
        source_roots=(),
    )

    result = run_semantic(ctx)
    assert result.outcome == Outcome.INCONCLUSIVE
    assert result.coverage == Coverage.PARTIAL
    assert "semantic_alignment_unresolved" in result.reason_codes
    assert len(result.findings) == 0


# ===========================================================================
# 2. TIMEOUT HANDLING CHALLENGES
# ===========================================================================

def test_replay_timeout_terminates_infinite_loop_at_bounded_timeout():
    """An infinite loop during concrete replay must abort at the specified timeout without hanging."""
    hanging_src = """def hang_fn(x):
    while True:
        pass
    return x
"""
    # execute_function_isolated with short timeout 0.5s
    t0 = time.monotonic()
    with pytest.raises(TimeoutError) as exc_info:
        execute_function_isolated(hanging_src, "hang_fn", {"x": 1}, timeout=0.5)
    t1 = time.monotonic()

    elapsed = t1 - t0
    assert 0.4 <= elapsed <= 1.5, f"Expected timeout around 0.5s, took {elapsed:.2f}s"
    assert "timed out after 0.5s" in str(exc_info.value)


def test_replay_witness_handles_hanging_function_gracefully():
    """replay_witness must return confirmed=False with timeout reason when target hangs."""
    hanging_head = """def process(user):
    while True:
        pass
    do_effect()
"""
    t0 = time.monotonic()
    replay_res = replay_witness(
        base_src="def process(user): do_effect()",
        head_src=hanging_head,
        fn_name="process",
        defect_family="SEM-GUARD-REMOVED",
        target="do_effect",
        model_values={"user.is_admin": False},
        timeout=1.0,
    )
    t1 = time.monotonic()

    assert replay_res.confirmed is False
    assert "timed out" in replay_res.reason
    assert (t1 - t0) <= 2.5


# ===========================================================================
# 3. UNCONFIRMED WITNESS FAIL-CLOSED (REAL EXECUTION WITHOUT MONKEYPATCHING)
# ===========================================================================

def test_real_unconfirmed_witness_solver_sat_divergence_unconfirmed_yields_inconclusive(tmp_path: Path):
    """Empirically prove: Solver SAT alone NEVER emits a finding if concrete execution fails to confirm divergence.

    We construct a case where AST traversal and Z3 find Delta(E) is SAT,
    but runtime execution in head encounters an exception before calling the effect,
    so divergence is NOT observed concretely.
    """
    base_src = """def dispatch(user, item_id):
    if not user.is_admin:
        return
    delete_item(item_id)
"""
    # Head removes the guard, but has a runtime exception (ValueError) before delete_item
    # int("unparseable") is an ast.Call which AST accepts and does not model as an early exit.
    head_src = """def dispatch(user, item_id):
    int("unparseable")
    delete_item(item_id)
"""
    repo, base, mb, head = _build_repo(
        {"src/dispatch.py": base_src},
        {"src/dispatch.py": head_src},
        tmp_path / "repo_unconfirmed_real",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    policy = dataclasses.replace(
        parse_policy_bytes(b""),
        protected_guards={"del_rule": {"effects": ["delete_item"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-27",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test-adversarial",
        source_roots=(),
    )

    result = run_semantic(ctx)
    # Must fail closed to INCONCLUSIVE with partial coverage; 0 findings emitted
    assert result.outcome == Outcome.INCONCLUSIVE
    assert result.coverage == Coverage.PARTIAL
    assert "semantic_alignment_unresolved" in result.reason_codes
    assert len(result.findings) == 0
    assert any(
        "solver SAT but concrete replay could not confirm divergence" in str(g.subject.get("detail", ""))
        for g in result.coverage_gaps
    )


def test_binding_swap_unconfirmed_witness_yields_inconclusive(tmp_path: Path):
    """When tuple binding swap is detected syntactically but concrete return values coincide, fails closed to INCONCLUSIVE."""
    # Syntactically swapped: (user.token, user.role) vs (user.role, user.token)
    # Z3 solves user.token != user.role (SAT), but at runtime attributes are assigned identical values.
    base_src = """def get_credentials(user):
    user.role = "fixed"
    user.token = "fixed"
    return (user.token, user.role)
"""
    head_src = """def get_credentials(user):
    user.role = "fixed"
    user.token = "fixed"
    return (user.role, user.token)
"""
    repo, base, mb, head = _build_repo(
        {"src/pair.py": base_src},
        {"src/pair.py": head_src},
        tmp_path / "repo_binding_unconfirmed",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    ctx = CheckContext(
        git=repo,
        policy=parse_policy_bytes(b""),
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-27",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test-adversarial",
        source_roots=(),
    )

    result = run_semantic(ctx)
    # Return values in concrete replay both evaluate to ["fixed", "fixed"] -> coincidence -> INCONCLUSIVE
    assert result.outcome == Outcome.INCONCLUSIVE
    assert result.coverage == Coverage.PARTIAL
    assert len(result.findings) == 0


# ===========================================================================
# 4. GUARD PRECEDENCE RULES CHALLENGES
# ===========================================================================

def test_guard_precedence_inverted_over_removed_and_weakened(tmp_path: Path):
    """When guard polarity is inverted, it must be classified as SEM-GUARD-INVERTED (precedence rule 1)."""
    base_src = """def authorize(user):
    if not user.is_admin:
        return
    execute_privileged_op()
"""
    head_src = """def authorize(user):
    if user.is_admin:
        return
    execute_privileged_op()
"""
    repo, base, mb, head = _build_repo(
        {"src/auth.py": base_src},
        {"src/auth.py": head_src},
        tmp_path / "repo_prec_inv",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    policy = dataclasses.replace(
        parse_policy_bytes(b""),
        protected_guards={"op_rule": {"effects": ["execute_privileged_op"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-27",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test-adversarial",
        source_roots=(),
    )

    result = run_semantic(ctx)
    assert result.outcome == Outcome.FAIL
    assert len(result.findings) == 1
    assert result.findings[0].defect_id == "SEM-GUARD-INVERTED"


def test_guard_precedence_removed_over_weakened(tmp_path: Path):
    """When a guard is completely removed, it must be classified as SEM-GUARD-REMOVED (precedence rule 2)."""
    base_src = """def authorize(user):
    if not user.is_admin:
        return
    execute_privileged_op()
"""
    head_src = """def authorize(user):
    execute_privileged_op()
"""
    repo, base, mb, head = _build_repo(
        {"src/auth.py": base_src},
        {"src/auth.py": head_src},
        tmp_path / "repo_prec_rem",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    policy = dataclasses.replace(
        parse_policy_bytes(b""),
        protected_guards={"op_rule": {"effects": ["execute_privileged_op"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-27",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test-adversarial",
        source_roots=(),
    )

    result = run_semantic(ctx)
    assert result.outcome == Outcome.FAIL
    assert len(result.findings) == 1
    assert result.findings[0].defect_id == "SEM-GUARD-REMOVED"


def test_guard_precedence_weakened_nested_guard(tmp_path: Path):
    """When an outer guard is retained but nested guard removed, classified as SEM-GUARD-WEAKENED."""
    base_src = """def commit(user):
    if user.is_authenticated:
        if user.is_admin:
            execute_privileged_op()
"""
    head_src = """def commit(user):
    if user.is_authenticated:
        execute_privileged_op()
"""
    repo, base, mb, head = _build_repo(
        {"src/commit.py": base_src},
        {"src/commit.py": head_src},
        tmp_path / "repo_prec_weak_nest",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    policy = dataclasses.replace(
        parse_policy_bytes(b""),
        protected_guards={"op_rule": {"effects": ["execute_privileged_op"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-27",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test-adversarial",
        source_roots=(),
    )

    result = run_semantic(ctx)
    assert result.outcome == Outcome.FAIL
    assert len(result.findings) == 1
    assert result.findings[0].defect_id == "SEM-GUARD-WEAKENED"
    assert "nested guard" in result.findings[0].message


def test_guard_precedence_weakened_boundary_relaxation(tmp_path: Path):
    """When a guard threshold is relaxed (e.g. limit > 100 to limit > 50), classified as SEM-GUARD-WEAKENED."""
    base_src = """def transfer(amount):
    if amount > 100:
        execute_privileged_op()
"""
    head_src = """def transfer(amount):
    if amount > 50:
        execute_privileged_op()
"""
    repo, base, mb, head = _build_repo(
        {"src/transfer.py": base_src},
        {"src/transfer.py": head_src},
        tmp_path / "repo_prec_weak_bound",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    policy = dataclasses.replace(
        parse_policy_bytes(b""),
        protected_guards={"op_rule": {"effects": ["execute_privileged_op"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-27",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test-adversarial",
        source_roots=(),
    )

    result = run_semantic(ctx)
    assert result.outcome == Outcome.FAIL
    assert len(result.findings) == 1
    assert result.findings[0].defect_id == "SEM-GUARD-WEAKENED"
    assert "guard boundary relaxed" in result.findings[0].message
