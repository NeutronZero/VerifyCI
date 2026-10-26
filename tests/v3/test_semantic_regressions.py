"""Adversarial and regression test suite for VerifyCI M4 Semantic check.

Addresses audit findings M4-1 through M4-5:
1. Validates symbolic CFG path conditions and early-return reachability.
2. Validates multiple effect sites in a single function.
3. Validates De Morgan and equivalent boolean rewrites prove UNSAT and evaluate to PASS.
4. Validates independent concrete replay execution confirms divergence.
5. Validates replay mismatch rejection (no finding emitted when replay fails).
6. Validates fail-closed handling on parse errors (Coverage.PARTIAL, Outcome.INCONCLUSIVE).
7. Validates fail-closed handling on unsupported languages (Coverage.UNKNOWN, Outcome.INCONCLUSIVE).
8. Validates policy-based decorator transparency vs unknown decorator gaps.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
import shutil
import subprocess

import pytest
import z3

from verifyci.checks.base import CheckContext
from verifyci.checks.semantic import (
    replay_witness,
    run as run_semantic,
)
from verifyci.contracts.model import Coverage, Outcome
from verifyci.gate.orchestrator import _augment_scope_with_repository
from verifyci.gate.policy import parse_policy_bytes
from verifyci.scm.git import GitRepo
from verifyci.scope.entities import build_changed_scope


def _build_repo(files_base: dict[str, str], files_head: dict[str, str], target_dir: Path) -> tuple[GitRepo, str, str, str]:
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True)

    subprocess.run(["git", "init", "-q", "-b", "main", str(target_dir)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "user.name", "TestRunner"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "user.email", "test@verifyci.dev"], check=True, capture_output=True)

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


@pytest.mark.invariant
def test_early_return_guard_removal(tmp_path: Path):
    """Guard clause with early return: if not user.is_admin: return; delete_item(x)."""
    base_src = (
        "def purge(user, item_id):\n"
        "    if not user.is_admin:\n"
        "        return\n"
        "    delete_item(item_id)\n"
    )
    head_src = (
        "def purge(user, item_id):\n"
        "    delete_item(item_id)\n"
    )
    repo, base, mb, head = _build_repo(
        {"src/purge.py": base_src},
        {"src/purge.py": head_src},
        tmp_path / "repo1",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    base_policy = parse_policy_bytes(b"")
    policy = dataclasses.replace(
        base_policy,
        protected_guards={"del_rule": {"effects": ["delete_item"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    result = run_semantic(ctx)
    assert result.outcome == Outcome.FAIL
    assert len(result.findings) == 1
    assert result.findings[0].defect_id == "SEM-GUARD-REMOVED"
    assert result.findings[0].reason_code == "guard_removed"


@pytest.mark.invariant
def test_multiple_effect_sites_reachability(tmp_path: Path):
    """Function with two distinct call sites to the same effect."""
    base_src = (
        "def checkout(user, amount):\n"
        "    if user.is_vip:\n"
        "        execute_payment(amount)\n"
        "    if amount < 50:\n"
        "        execute_payment(amount)\n"
    )
    # Head removes amount < 50 check, calling unconditionally
    head_src = (
        "def checkout(user, amount):\n"
        "    if user.is_vip:\n"
        "        execute_payment(amount)\n"
        "    execute_payment(amount)\n"
    )
    repo, base, mb, head = _build_repo(
        {"src/pay.py": base_src},
        {"src/pay.py": head_src},
        tmp_path / "repo2",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    base_policy = parse_policy_bytes(b"")
    policy = dataclasses.replace(
        base_policy,
        protected_guards={"pay_rule": {"effects": ["execute_payment"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    result = run_semantic(ctx)
    assert result.outcome == Outcome.FAIL
    assert len(result.findings) == 1
    assert result.findings[0].defect_id == "SEM-GUARD-REMOVED"


@pytest.mark.invariant
def test_de_morgan_equivalent_refactor_unsat(tmp_path: Path):
    """De Morgan refactoring not (a and b) vs (not a or not b) is algebraically proven UNSAT."""
    base_src = (
        "def auth(a, b):\n"
        "    if not (a and b):\n"
        "        return\n"
        "    grant_token()\n"
    )
    head_src = (
        "def auth(a, b):\n"
        "    if not a or not b:\n"
        "        return\n"
        "    grant_token()\n"
    )
    repo, base, mb, head = _build_repo(
        {"src/auth_dm.py": base_src},
        {"src/auth_dm.py": head_src},
        tmp_path / "repo3",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    base_policy = parse_policy_bytes(b"")
    policy = dataclasses.replace(
        base_policy,
        protected_guards={"token_rule": {"effects": ["grant_token"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    result = run_semantic(ctx)
    assert result.outcome == Outcome.PASS
    assert result.coverage == Coverage.COMPLETE
    assert not result.findings


@pytest.mark.invariant
def test_independent_replay_execution_confirms_divergence():
    """Directly verifies replay_witness execution captures divergence in concrete runtime."""
    base_src = (
        "def charge(account, amount):\n"
        "    if account.balance >= amount + 10:\n"
        "        execute_charge(account, amount)\n"
    )
    head_src = (
        "def charge(account, amount):\n"
        "    if account.balance >= amount:\n"
        "        execute_charge(account, amount)\n"
    )
    # Model where balance = 5, amount = 0 (5 >= 0 is True, 5 >= 0 + 10 is False)
    model = {"account.balance": 5, "amount": 0}
    phi_base = z3.Int("account.balance") >= z3.Int("amount") + 10
    phi_head = z3.Int("account.balance") >= z3.Int("amount")

    replay_res = replay_witness(
        base_src=base_src,
        head_src=head_src,
        fn_name="charge",
        defect_family="SEM-GUARD-WEAKENED",
        target="execute_charge",
        model_values=model,
        phi_base=phi_base,
        phi_head=phi_head,
        solver_model=None,
    )
    assert replay_res.confirmed is True
    assert "execute_charge" in replay_res.reason
    assert "calls" in replay_res.head_observation


@pytest.mark.invariant
def test_replay_mismatch_fails_closed():
    """If candidate witness does not reproduce divergence, replay fails and finding is prevented."""
    src = "def process(x):\n    call_sink(x)\n"
    # Both base and head are identical
    replay_res = replay_witness(
        base_src=src,
        head_src=src,
        fn_name="process",
        defect_family="SEM-GUARD-REMOVED",
        target="call_sink",
        model_values={"x": 10},
    )
    # Both called call_sink, so head_called and not base_called is FALSE
    assert replay_res.confirmed is False
    assert "divergence not observed" in replay_res.reason


@pytest.mark.invariant
def test_nested_early_return_reachability_defect(tmp_path: Path):
    """Nested early return removal allows non-admin path to reach protected effect."""
    base_src = (
        "def check(user, doc_id):\n"
        "    if user.role != 'admin':\n"
        "        if user.is_guest:\n"
        "            return\n"
        "        else:\n"
        "            return\n"
        "    delete_doc(doc_id)\n"
    )
    head_src = (
        "def check(user, doc_id):\n"
        "    if user.role != 'admin':\n"
        "        if user.is_guest:\n"
        "            return\n"
        "        # else branch removed: non-guest non-admins now fall through to delete_doc!\n"
        "    delete_doc(doc_id)\n"
    )
    repo, base, mb, head = _build_repo(
        {"src/nested.py": base_src},
        {"src/nested.py": head_src},
        tmp_path / "repo_nested",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    base_policy = parse_policy_bytes(b"")
    policy = dataclasses.replace(
        base_policy,
        protected_guards={"doc_rule": {"effects": ["delete_doc"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    result = run_semantic(ctx)
    assert result.outcome == Outcome.FAIL
    assert len(result.findings) == 1
    assert result.findings[0].defect_id == "SEM-GUARD-REMOVED"
    finding = result.findings[0]
    assert finding.evidence.payload["replay_confirmed"] is True
    assert "replay_result" in finding.evidence.payload
    replay_dict = finding.evidence.payload["replay_result"]
    assert replay_dict["confirmed"] is True
    assert "input_model" in replay_dict
    assert "base_observation" in replay_dict
    assert "head_observation" in replay_dict


@pytest.mark.invariant
def test_unsupported_expression_in_guard_fails_closed(tmp_path: Path):
    """Unsupported expression (& bitwise operator) in analyzed guard fails closed with Coverage.PARTIAL."""
    base_src = (
        "def auth_check(user):\n"
        "    if user.perms & 0x04:\n"
        "        disburse_funds(user)\n"
    )
    head_src = (
        "def auth_check(user):\n"
        "    if user.perms & 0x08:\n"
        "        disburse_funds(user)\n"
    )
    repo, base, mb, head = _build_repo(
        {"src/bitwise.py": base_src},
        {"src/bitwise.py": head_src},
        tmp_path / "repo_bitwise",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    base_policy = parse_policy_bytes(b"")
    policy = dataclasses.replace(
        base_policy,
        protected_guards={"fund_rule": {"effects": ["disburse_funds"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    result = run_semantic(ctx)
    assert result.outcome == Outcome.INCONCLUSIVE
    assert result.coverage == Coverage.PARTIAL
    assert "unsupported_syntax_version" in result.reason_codes
    assert any(g.reason_code == "unsupported_syntax_version" for g in result.coverage_gaps)


@pytest.mark.invariant
def test_unsupported_control_flow_in_guard_fails_closed(tmp_path: Path):
    """Unsupported control flow (while loop) in analyzed guard fails closed with Coverage.PARTIAL."""
    base_src = (
        "def sync_data(user):\n"
        "    while not user.is_ready:\n"
        "        pass\n"
        "    disburse_funds(user)\n"
    )
    head_src = (
        "def sync_data(user):\n"
        "    disburse_funds(user)\n"
    )
    repo, base, mb, head = _build_repo(
        {"src/loop.py": base_src},
        {"src/loop.py": head_src},
        tmp_path / "repo_loop",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    base_policy = parse_policy_bytes(b"")
    policy = dataclasses.replace(
        base_policy,
        protected_guards={"fund_rule": {"effects": ["disburse_funds"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    result = run_semantic(ctx)
    assert result.outcome == Outcome.INCONCLUSIVE
    assert result.coverage == Coverage.PARTIAL
    assert "semantic_alignment_unresolved" in result.reason_codes
    assert any(g.reason_code == "semantic_alignment_unresolved" for g in result.coverage_gaps)


@pytest.mark.invariant
def test_replay_sandbox_security_isolation():
    """Replay runner rejects source code attempting unsafe operations like import os."""
    unsafe_src = (
        "def attack():\n"
        "    import os\n"
        "    os.system('echo compromised')\n"
        "    do_effect()\n"
    )
    safe_src = (
        "def attack():\n"
        "    do_effect()\n"
    )
    replay_res = replay_witness(
        base_src=safe_src,
        head_src=unsafe_src,
        fn_name="attack",
        defect_family="SEM-GUARD-REMOVED",
        target="do_effect",
        model_values={},
    )
    assert replay_res.confirmed is False
    assert "safety violation" in replay_res.reason or "forbidden" in replay_res.reason


@pytest.mark.invariant
def test_symbolic_sat_alone_cannot_confirm_finding_yields_inconclusive(tmp_path: Path, monkeypatch):
    """Proves symbolic satisfiability alone cannot emit FAIL; unconfirmed replay yields INCONCLUSIVE."""
    base_src = (
        "def purge(user, item_id):\n"
        "    if not user.is_admin:\n"
        "        return\n"
        "    delete_item(item_id)\n"
    )
    head_src = (
        "def purge(user, item_id):\n"
        "    delete_item(item_id)\n"
    )
    repo, base, mb, head = _build_repo(
        {"src/purge.py": base_src},
        {"src/purge.py": head_src},
        tmp_path / "repo_unconfirmed",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    base_policy = parse_policy_bytes(b"")
    policy = dataclasses.replace(
        base_policy,
        protected_guards={"del_rule": {"effects": ["delete_item"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )

    # Monkeypatch replay_witness to simulate an unconfirmed / inconclusive replay
    from verifyci.checks.semantic import ReplayResult
    import verifyci.checks.semantic as sem_mod

    def mock_replay_unconfirmed(**kwargs):
        return ReplayResult(
            confirmed=False,
            reason="divergence not observed in concrete runtime execution",
            input_model={},
            source_identity="test",
            base_observation={},
            head_observation={},
        )

    monkeypatch.setattr(sem_mod, "replay_witness", mock_replay_unconfirmed)

    result = run_semantic(ctx)
    # Must fail closed to INCONCLUSIVE with partial coverage, never PASS or ungrounded FAIL
    assert result.outcome == Outcome.INCONCLUSIVE
    assert result.coverage == Coverage.PARTIAL
    assert "semantic_alignment_unresolved" in result.reason_codes
    assert any(g.reason_code == "semantic_alignment_unresolved" for g in result.coverage_gaps)


@pytest.mark.invariant
def test_replay_timeout_fails_closed_to_inconclusive(tmp_path: Path, monkeypatch):
    """Replay subprocess timeout triggers fail-closed INCONCLUSIVE verdict."""
    base_src = (
        "def check(user):\n"
        "    if user.is_admin:\n"
        "        do_action()\n"
    )
    head_src = (
        "def check(user):\n"
        "    do_action()\n"
    )
    repo, base, mb, head = _build_repo(
        {"src/act.py": base_src},
        {"src/act.py": head_src},
        tmp_path / "repo_timeout",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    base_policy = parse_policy_bytes(b"")
    policy = dataclasses.replace(
        base_policy,
        protected_guards={"act_rule": {"effects": ["do_action"], "paths": ["src/**.py"]}},
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )

    from verifyci.checks.semantic import ReplayResult
    import verifyci.checks.semantic as sem_mod

    def mock_replay_timeout(**kwargs):
        return ReplayResult(
            confirmed=False,
            reason="replay process timed out after 2.0s (resource limit exceeded)",
            input_model={},
            source_identity="test",
            base_observation={},
            head_observation={},
        )

    monkeypatch.setattr(sem_mod, "replay_witness", mock_replay_timeout)

    result = run_semantic(ctx)
    assert result.outcome == Outcome.INCONCLUSIVE
    assert result.coverage == Coverage.PARTIAL
    assert "semantic_alignment_unresolved" in result.reason_codes




@pytest.mark.invariant
def test_parser_failure_yields_inconclusive_coverage_gap(tmp_path: Path):
    """Syntax error in changed file must fail closed to INCONCLUSIVE with parse_error gap."""
    base_src = "def valid():\n    return True\n"
    head_src = "def broken(:\n    return True\n"
    repo, base, mb, head = _build_repo(
        {"src/syntax.py": base_src},
        {"src/syntax.py": head_src},
        tmp_path / "repo4",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    ctx = CheckContext(
        git=repo,
        policy=parse_policy_bytes(b""),
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    result = run_semantic(ctx)
    assert result.outcome == Outcome.INCONCLUSIVE
    assert result.coverage == Coverage.PARTIAL
    assert "parse_error" in result.reason_codes


@pytest.mark.invariant
def test_unsupported_language_fails_closed(tmp_path: Path):
    """Unsupported language (.rs) must fail closed to INCONCLUSIVE with Coverage.UNKNOWN."""
    base_src = "fn main() {}\n"
    head_src = "fn main() { println!(\"hello\"); }\n"
    repo, base, mb, head = _build_repo(
        {"src/main.rs": base_src},
        {"src/main.rs": head_src},
        tmp_path / "repo5",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    ctx = CheckContext(
        git=repo,
        policy=parse_policy_bytes(b""),
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    result = run_semantic(ctx)
    assert result.outcome == Outcome.INCONCLUSIVE
    assert result.coverage == Coverage.UNKNOWN
    assert "unsupported_language" in result.reason_codes


@pytest.mark.invariant
def test_unknown_decorator_fails_closed(tmp_path: Path):
    """Unrecognized decorator not in policy transparent_decorators yields unknown_decorator gap."""
    base_src = "def compute(x):\n    return x * 2\n"
    head_src = "@audit_logged\ndef compute(x):\n    return x * 2\n"
    repo, base, mb, head = _build_repo(
        {"src/dec.py": base_src},
        {"src/dec.py": head_src},
        tmp_path / "repo6",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    ctx = CheckContext(
        git=repo,
        policy=parse_policy_bytes(b""),
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    result = run_semantic(ctx)
    assert result.outcome == Outcome.INCONCLUSIVE
    assert result.coverage == Coverage.PARTIAL
    assert "unknown_decorator" in result.reason_codes


@pytest.mark.invariant
def test_transparent_decorator_policy_respected(tmp_path: Path):
    """Declared transparent decorator in policy is accepted without gap."""
    base_src = "def compute(x):\n    return x * 2\n"
    head_src = "@audit_logged\ndef compute(x):\n    return x * 2\n"
    repo, base, mb, head = _build_repo(
        {"src/dec.py": base_src},
        {"src/dec.py": head_src},
        tmp_path / "repo7",
    )
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(scope, git=repo, base_rev=base, head_rev=head, source_roots=())

    base_policy = parse_policy_bytes(b"")
    policy = dataclasses.replace(
        base_policy,
        transparent_decorators=("audit_logged",),
    )
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    result = run_semantic(ctx)
    # Since compute(x) has no effects or binding swaps, it's NOT_APPLICABLE or PASS
    assert result.outcome in (Outcome.PASS, Outcome.NOT_APPLICABLE)
    assert result.coverage == Coverage.COMPLETE
    assert "unknown_decorator" not in result.reason_codes
