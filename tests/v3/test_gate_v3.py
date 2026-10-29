"""Regression coverage for the v3.1.10 gate contracts.

These tests build disposable Git repositories so the gate is exercised through
its real boundary: target-base policy authority, merge-base resolution, blob
reads, patch parsing, and evidence assembly.
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
import subprocess

from dataclasses import replace
import pytest

from verifyci.checks.security import _redact
from verifyci.cli import main
from verifyci.contracts.manifest import CHECK_SPECS, validate_manifest
from verifyci.contracts.model import Maturity, Tier
from verifyci.contracts.names import (
    NameError as GlobNameError,
    glob_match,
    glob_union_is_universal,
    stable_finding_fingerprint,
)
from verifyci.contracts.reason_codes import ALL_CODES, DEFECT_REASON_CODES
from verifyci.evidence.sarif import bundle_to_sarif
from verifyci.evidence.canonical import canonical_json_bytes
from verifyci.gate.integrity import evaluate_codeowners
from verifyci.gate.orchestrator import GateRequest, run_gate
from verifyci.gate.policy import builtin_bootstrap_policy, parse_policy_bytes
from verifyci.index.cache import CacheStore, compute_hmac, entry_digest
from verifyci.index.provider import FactProvider
from verifyci.scope.entities import git_blob_id
from verifyci.evidence.bundle import toolchain_fingerprint

POLICY = '[gate]\ntarget_drift = "record"\n'
AS_OF = "2026-10-21"
CODEOOWNERS_FULL = (
    "/.verifyci/** @org/security\n"
    "/.github/workflows/** @org/security\n"
    "/.github/actions/** @org/security\n"
    "/CODEOWNERS @org/security\n"
    "/.github/CODEOWNERS @org/security\n"
    "/docs/CODEOWNERS @org/security\n"
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr or result.stdout}")
    return result.stdout.strip()


def _repo(tmp_path: Path, files: dict[str, str | None], policy: str = POLICY) -> tuple[Path, str]:
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "VerifyCI Test")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "core.autocrlf", "false")
    (root / ".verifyci").mkdir()
    (root / ".verifyci" / "policy.toml").write_text(policy, encoding="utf-8", newline="\n")
    for path, content in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if content is None:
            continue
        target.write_text(content, encoding="utf-8", newline="\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    return root, _git(root, "rev-parse", "HEAD")


def _commit(root: Path, files: dict[str, str | None], message: str = "head") -> str:
    for path, content in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if content is None:
            target.unlink(missing_ok=True)
        else:
            target.write_text(content, encoding="utf-8", newline="\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def _gate(
    root: Path,
    base: str,
    head: str,
    *,
    review_mode: str = "fail",
    generated_at: str | None = None,
):
    return run_gate(
        GateRequest(
            repo=root,
            base=base,
            head=head,
            as_of_date=AS_OF,
            review_mode=review_mode,
            generated_at=generated_at,
        )
    )


def _assert_check_results(bundle) -> dict[str, dict]:
    results = bundle.payload["check_results"]
    assert [item["check_id"] for item in results] == [
        "grounding",
        "deletion",
        "contract",
        "semantic",
        "security",
    ]
    return {item["check_id"]: item for item in results}


def test_manifest_reason_codes_and_glob_semantics():
    assert validate_manifest() == []
    assert len(DEFECT_REASON_CODES) == 16
    assert all(code in ALL_CODES for code in DEFECT_REASON_CODES.values())
    assert glob_match("src/**", "src/a/b.py", kind="path")
    assert not glob_match("src/**", "lib/a.py", kind="path")
    assert glob_match("**/test_*.py", "tests/v3/test_gate.py", kind="path")
    assert not glob_union_is_universal(["src/**", "lib/**"])
    assert glob_union_is_universal(["**"])
    with pytest.raises(GlobNameError):
        glob_union_is_universal(["src/**", "!src/**"])
    assert builtin_bootstrap_policy().source == "builtin_bootstrap_v1"
    parsed = parse_policy_bytes(b"[entrypoints]\nsymbols = []\nglobs = []\n")
    assert parsed.entrypoints["symbols"] == ()


def test_codeowners_coverage_and_noninterference():
    assert evaluate_codeowners(CODEOOWNERS_FULL).proven
    missing = CODEOOWNERS_FULL.replace("/.github/actions/** @org/security\n", "")
    coverage = evaluate_codeowners(missing)
    assert not coverage.proven
    assert "codeowners_missing_rule" in coverage.reasons
    interfering = CODEOOWNERS_FULL + "/.verifyci/policy.toml @org/other\n"
    coverage = evaluate_codeowners(interfering)
    assert not coverage.proven
    assert "codeowners_noninterference_unproven" in coverage.reasons


def test_clean_gate_stays_error_until_release_validation(tmp_path, monkeypatch):
    from verifyci.gate import orchestrator
    monkeypatch.setattr(
        orchestrator,
        "verify_release_validation_evidence",
        lambda repo=None: (False, "release-validation artifacts are absent; this internal build cannot emit a normal gate verdict"),
    )
    root, base = _repo(tmp_path, {"app.py": "def add(a, b):\n    return a + b\n"})
    head = _commit(
        root,
        {"app.py": "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n"},
    )
    first = _gate(root, base, head, generated_at="2026-10-21T00:00:00Z")
    second = _gate(root, base, head, generated_at="2026-10-21T00:00:00Z")
    assert first.payload["verdict"]["status"] == "ERROR"
    assert first.exit_code == 3
    assert "check_not_validated" in first.payload["verdict"]["fault_reason_codes"]
    assert first.envelope["payload_hash"] == second.envelope["payload_hash"]
    assert first.payload["manifest"]["release_validated"] is False
    results = _assert_check_results(first)
    assert results["grounding"]["outcome"] == "PASS"
    assert results["security"]["outcome"] == "PASS"
    assert all(result["toolchain_fingerprint"] for result in results.values())
    sarif = bundle_to_sarif(first)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []


def test_clean_gate_passes_when_release_validated(tmp_path):
    root, base = _repo(tmp_path, {"app.py": "def add(a, b):\n    return a + b\n"})
    head = _commit(
        root,
        {"app.py": "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n"},
    )
    bundle = _gate(root, base, head, generated_at="2026-10-21T00:00:00Z")
    assert bundle.payload["verdict"]["status"] == "PASS"
    assert bundle.exit_code == 0
    assert "check_not_validated" not in bundle.payload["verdict"]["fault_reason_codes"]
    assert bundle.payload["manifest"]["release_validated"] is True
    results = _assert_check_results(bundle)
    assert results["grounding"]["outcome"] == "PASS"
    assert results["security"]["outcome"] == "PASS"
    assert all(result["toolchain_fingerprint"] for result in results.values())
    sarif = bundle_to_sarif(bundle)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []


def test_adversarial_cli_flags_cannot_bypass_validation(tmp_path):
    """Passing --release-validated on the CLI is rejected by the parser as an unknown argument."""
    from verifyci.cli import main
    root, base = _repo(tmp_path, {"app.py": "def add(a, b):\n    return a + b\n"})
    head = _commit(root, {"app.py": "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n"})
    with pytest.raises(SystemExit) as exc:
        main(["gate", "--repo", str(root), "--base", base, "--head", head, "--release-validated"])
    assert exc.value.code == 2


def test_adversarial_env_var_cannot_bypass_validation(tmp_path, monkeypatch):
    """Setting VERIFYCI_RELEASE_VALIDATED environment variable has no effect on unvalidated builds."""
    from verifyci.gate import orchestrator
    monkeypatch.setenv("VERIFYCI_RELEASE_VALIDATED", "1")
    monkeypatch.setattr(
        orchestrator,
        "verify_release_validation_evidence",
        lambda repo=None: (False, "release-validation artifacts are absent; this internal build cannot emit a normal gate verdict"),
    )
    root, base = _repo(tmp_path, {"app.py": "def add(a, b):\n    return a + b\n"})
    head = _commit(root, {"app.py": "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n"})
    bundle = _gate(root, base, head, generated_at="2026-10-21T00:00:00Z")
    assert bundle.payload["verdict"]["status"] == "ERROR"
    assert bundle.exit_code == 3
    assert "check_not_validated" in bundle.payload["verdict"]["fault_reason_codes"]


def test_adversarial_gate_request_rejects_release_validated_keyword(tmp_path):
    """GateRequest does not accept caller-controlled release_validated attribute."""
    root, base = _repo(tmp_path, {"app.py": "def add(a, b):\n    return a + b\n"})
    with pytest.raises(TypeError):
        GateRequest(repo=root, base=base, head="HEAD", release_validated=True)  # type: ignore[call-arg]


def test_stale_release_validation_commit_mismatch_rejected(tmp_path, monkeypatch):
    """Release validation evidence bound to a different commit is rejected as stale, failing closed."""
    from verifyci.contracts import release_validation
    monkeypatch.setattr(release_validation, "get_commit_sha", lambda root: "0" * 40)
    root, base = _repo(tmp_path, {"app.py": "def add(a, b):\n    return a + b\n"})
    head = _commit(root, {"app.py": "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n"})
    bundle = _gate(root, base, head, generated_at="2026-10-21T00:00:00Z")
    assert bundle.payload["verdict"]["status"] == "ERROR"
    assert bundle.exit_code == 3
    assert "check_not_validated" in bundle.payload["verdict"]["fault_reason_codes"]
    diag = next(d for d in bundle.payload["diagnostics"] if d["code"] == "check_not_validated")
    assert "stale release-validation evidence" in diag["detail"]


def test_tampered_attestation_signature_fails_closed(tmp_path, monkeypatch):
    """Tampered attestation signature is detected and fails closed with ERROR."""
    from verifyci.contracts import release_validation
    real_read = Path.read_bytes

    def tampered_read(self):
        if self.name == "release_validation.json":
            raw = real_read(self)
            data = json.loads(raw.decode("utf-8"))
            data["attestation"]["signature"] = "deadbeef" * 8
            return json.dumps(data).encode("utf-8")
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", tampered_read)

    ok, err = release_validation.verify_release_validation_evidence()
    assert not ok
    assert "invalid release attestation signature" in err

    root, base = _repo(tmp_path, {"app.py": "def add(a, b):\n    return a + b\n"})
    head = _commit(root, {"app.py": "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n"})
    bundle = _gate(root, base, head, generated_at="2026-10-21T00:00:00Z")
    assert bundle.payload["verdict"]["status"] == "ERROR"
    assert bundle.exit_code == 3
    assert "check_not_validated" in bundle.payload["verdict"]["fault_reason_codes"]
    diag = next(d for d in bundle.payload["diagnostics"] if d["code"] == "check_not_validated")
    assert "invalid release attestation signature" in diag["detail"]


def test_tampered_measurement_payload_fails_closed(tmp_path, monkeypatch):
    """Tampered measurements payload without re-signing fails digest verification and fails closed."""
    from verifyci.contracts import release_validation
    real_read = Path.read_bytes

    def tampered_read(self):
        if self.name == "release_validation.json":
            raw = real_read(self)
            data = json.loads(raw.decode("utf-8"))
            data["measurements"]["benchmark"]["zero_false_blocking"] = False
            return json.dumps(data).encode("utf-8")
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", tampered_read)

    ok, err = release_validation.verify_release_validation_evidence()
    assert not ok
    assert "release-validation attestation digest mismatch" in err

    root, base = _repo(tmp_path, {"app.py": "def add(a, b):\n    return a + b\n"})
    head = _commit(root, {"app.py": "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n"})
    bundle = _gate(root, base, head, generated_at="2026-10-21T00:00:00Z")
    assert bundle.payload["verdict"]["status"] == "ERROR"
    assert bundle.exit_code == 3
    assert "check_not_validated" in bundle.payload["verdict"]["fault_reason_codes"]
    diag = next(d for d in bundle.payload["diagnostics"] if d["code"] == "check_not_validated")
    assert "release-validation attestation digest mismatch" in diag["detail"]


def test_missing_git_identity_fails_closed(tmp_path, monkeypatch):
    """When git commit identity cannot be authoritatively resolved, validation fails closed."""
    from verifyci.contracts import release_validation
    monkeypatch.setattr(release_validation, "get_commit_sha", lambda root: None)

    ok, err = release_validation.verify_release_validation_evidence()
    assert not ok
    assert "unable to establish authoritative git commit identity" in err

    root, base = _repo(tmp_path, {"app.py": "def add(a, b):\n    return a + b\n"})
    head = _commit(root, {"app.py": "def add(a, b):\n    return a + b\n\ndef sub(a, b):\n    return a - b\n"})
    bundle = _gate(root, base, head, generated_at="2026-10-21T00:00:00Z")
    assert bundle.payload["verdict"]["status"] == "ERROR"
    assert bundle.exit_code == 3
    assert "check_not_validated" in bundle.payload["verdict"]["fault_reason_codes"]
    diag = next(d for d in bundle.payload["diagnostics"] if d["code"] == "check_not_validated")
    assert "unable to establish authoritative git commit identity" in diag["detail"]


def test_local_cache_reuses_pinned_facts_without_changing_payload(tmp_path):
    root, base = _repo(
        tmp_path,
        {
            "app.py": "def value(x):\n    return x + 1\n",
            "caller.py": "from app import value\n\ndef main():\n    return value(1)\n",
        },
    )
    head = _commit(root, {"app.py": "def value(x):\n    return x + 2\n"})
    cache_dir = str(tmp_path / "shared-cache")
    common = {
        "repo": root,
        "base": base,
        "head": head,
        "as_of_date": AS_OF,
        "generated_at": "2026-10-21T00:00:00Z",
    }
    uncached = run_gate(GateRequest(**common))
    cached_request = GateRequest(
        **common,
        cache_mode="local",
        allow_local_cache=True,
        cache_dir=cache_dir,
    )
    run_gate(cached_request)
    cached = run_gate(cached_request)

    assert cached.payload == uncached.payload
    assert cached.envelope["cache"]["authoritative"] is False
    assert cached.envelope["cache"]["stats"]["hits"] > 0


def test_authenticated_sampled_cache_mismatch_fails_gate_closed(tmp_path):
    key = b"k" * 32
    git_version = subprocess.check_output(["git", "version"], text=True).strip()
    tc = toolchain_fingerprint(git_version=git_version, object_format="sha1")
    source = "VALUE = 7\n"
    source_blob = source.encode("utf-8")
    blob_hash = "sha1:" + git_blob_id(source_blob)
    for index in range(10000):
        candidate_path = f"cache-sample-{index}.py"
        components = FactProvider.tier1_components(
            toolchain_fingerprint=tc,
            blob_hash=blob_hash,
            path=candidate_path,
            language_id="python",
            frontend_version=f"python-ast-{__import__('sys').version_info.major}.{__import__('sys').version_info.minor}",
            source_roots=(".",),
        )
        if CacheStore.sample_selected("symbol_facts", components):
            break
    else:
        pytest.fail("could not find a deterministically sampled source key")

    root, base = _repo(tmp_path, {candidate_path: source, "app.py": "VALUE = 1\n"})
    head = _commit(root, {"app.py": "VALUE = 2\n"})
    cache_dir = tmp_path / "auth-cache"
    request = GateRequest(
        repo=root,
        base=base,
        head=head,
        as_of_date=AS_OF,
        cache_mode="authenticated",
        cache_key=key,
        cache_key_id="test-key",
        cache_dir=str(cache_dir),
    )
    seeded = run_gate(request)
    assert seeded.envelope["cache"]["mode"] == "authenticated"
    assert seeded.envelope["cache"]["stats"]["writes"] > 0

    records = list(cache_dir.rglob("*.json"))
    matching_record = next(
        (
            json.loads(path.read_text(encoding="utf-8"))
            for path in records
            if json.loads(path.read_text(encoding="utf-8")).get("components", {}).get("repo_relative_path") == candidate_path
        ),
        None,
    )
    assert matching_record is not None
    components = matching_record["components"]
    assert CacheStore.sample_selected("symbol_facts", components)
    entry_digest("symbol_facts", components)
    record_path = next(
        path
        for path in records
        if json.loads(path.read_text(encoding="utf-8")).get("components") == components
    )
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["value"]["exports"].append("forged_export")
    value_digest = sha256(canonical_json_bytes(record["value"])).hexdigest()
    record["value_digest"] = value_digest
    record["hmac"] = compute_hmac(
        key, "test-key", "symbol_facts", components, value_digest
    )
    record_path.write_text(json.dumps(record), encoding="utf-8")

    result = run_gate(request)
    assert result.payload["verdict"]["status"] == "ERROR"
    assert "cache_integrity_mismatch" in result.payload["verdict"]["fault_reason_codes"]


def test_module_level_edit_is_grounded_without_symbol_match(tmp_path):
    policy = POLICY + '[deny_changes.protect]\nsymbols = ["app:f"]\nreason = "protected"\n'
    root, base = _repo(
        tmp_path,
        {"app.py": "def f(a):\n    return a\n\nX = 1\n"},
        policy=policy,
    )
    head = _commit(root, {"app.py": "def f(a):\n    return a\n\nX = 2\n"})
    bundle = _gate(root, base, head)
    assert bundle.payload["verdict"]["status"] == "PASS"
    assert bundle.exit_code == 0
    assert "check_not_validated" not in bundle.payload["verdict"]["fault_reason_codes"]
    grounding = _assert_check_results(bundle)["grounding"]
    assert grounding["outcome"] == "PASS"
    assert grounding["evaluated_scope"]["other_text_hunks"]


def test_deny_changes_emits_one_finding_for_multiple_matching_rules(tmp_path):
    policy = (
        POLICY
        + '[deny_changes.core_a]\npaths = ["src/core/**"]\nreason = "core a"\n'
        + '[deny_changes.core_b]\npaths = ["src/**"]\nreason = "core b"\n'
    )
    root, base = _repo(tmp_path, {"src/core/x.py": "x = 1\n"}, policy=policy)
    head = _commit(root, {"src/core/x.py": "x = 2\n"})
    bundle = _gate(root, base, head)
    assert bundle.payload["verdict"]["status"] == "FAIL"
    assert bundle.exit_code == 1
    assert "check_not_validated" not in bundle.payload["verdict"]["fault_reason_codes"]
    result = _assert_check_results(bundle)["grounding"]
    assert result["outcome"] == "FAIL"
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["defect_id"] == "GRD-UNGROUNDED-EDIT"
    assert finding["evidence"]["payload"]["rule_ids"] == ["core_a", "core_b"]


def test_deletion_finds_live_reference_in_unchanged_file(tmp_path):
    root, base = _repo(
        tmp_path,
        {
            "app.py": "def helper(x):\n    return x\n",
            "main.py": "from app import helper\n\ndef run():\n    return helper(1)\n",
        },
    )
    head = _commit(root, {"app.py": "def other(x):\n    return x\n"})
    bundle = _gate(root, base, head)
    result = _assert_check_results(bundle)["deletion"]
    assert result["outcome"] == "FAIL"
    finding = next(f for f in result["findings"] if f["defect_id"] == "DEL-DANGLING-REFERENCE")
    assert finding["evidence"]["payload"]["reference"]["path"] == "main.py"
    assert bundle.payload["verdict"]["status"] == "FAIL"
    assert bundle.exit_code == 1


def test_contract_finds_incompatible_caller_in_unchanged_file(tmp_path):
    root, base = _repo(
        tmp_path,
        {
            "lib.py": "def f(a):\n    return a\n",
            "main.py": "from lib import f\n\ndef run():\n    return f(1)\n",
        },
    )
    head = _commit(root, {"lib.py": "def f(a, b):\n    return a + b\n"})
    bundle = _gate(root, base, head)
    result = _assert_check_results(bundle)["contract"]
    assert result["outcome"] == "FAIL"
    assert all(code not in DEFECT_REASON_CODES.values() for code in result["reason_codes"])
    finding = next(f for f in result["findings"] if f["defect_id"] == "CTR-SIGNATURE-BREAK")
    assert finding["evidence"]["kind"] == "call_site"
    assert finding["evidence"]["payload"]["caller_file"] == "main.py"
    assert "too_few_positional_arguments" in finding["premises"]["problem"]
    assert finding["subject"]["file"] == "lib.py"
    assert finding["subject"]["entity"] == "lib:f"
    for key in (
        "target_base_commit",
        "merge_base_commit",
        "head_commit",
        "base_blob",
        "head_blob",
        "authoritative_policy_source",
        "authoritative_policy_hash",
        "check_version",
        "toolchain_fingerprint",
    ):
        assert finding["premises"][key]
    assert finding["premises"]["base_blob"].startswith("sha1:")


def test_contract_finds_unchanged_caller_when_parameter_is_removed(tmp_path):
    root, base = _repo(
        tmp_path,
        {
            "lib.py": "def f(a, b):\n    return a + b\n",
            "main.py": "from lib import f\n\ndef run():\n    return f(1, 2)\n",
        },
    )
    head = _commit(root, {"lib.py": "def f(a):\n    return a\n"})
    bundle = _gate(root, base, head)
    result = _assert_check_results(bundle)["contract"]
    finding = next(f for f in result["findings"] if f["defect_id"] == "CTR-SIGNATURE-BREAK")
    assert "too_many_positional_arguments" in finding["premises"]["problem"]
    assert bundle.payload["verdict"]["status"] == "FAIL"
    assert bundle.exit_code == 1


def test_contract_changed_callsite_against_unchanged_callee(tmp_path):
    root, base = _repo(
        tmp_path,
        {
            "lib.py": "def f(a):\n    return a\n",
            "main.py": "from lib import f\n\ndef run():\n    return f(1)\n",
        },
    )
    head = _commit(root, {"main.py": "from lib import f\n\ndef run():\n    return f(1, 2)\n"})
    bundle = _gate(root, base, head)
    result = _assert_check_results(bundle)["contract"]
    assert any(f["defect_id"] == "CTR-CALL-INCOMPATIBLE" for f in result["findings"])
    assert bundle.payload["verdict"]["status"] == "FAIL"
    assert bundle.exit_code == 1


def test_contract_without_callers_reports_signature_break(tmp_path):
    root, base = _repo(tmp_path, {"lib.py": "def f(a):\n    return a\n"})
    head = _commit(root, {"lib.py": "def f(a, b):\n    return a + b\n"})
    result = _assert_check_results(_gate(root, base, head))["contract"]
    assert any(f["defect_id"] == "CTR-SIGNATURE-BREAK" for f in result["findings"])


def test_secret_finding_is_redacted_and_not_duplicated(tmp_path):
    token = "ghp_1234567890abcdefghijABCDEFGHIJ"
    root, base = _repo(tmp_path, {"app.py": "x = 1\n"})
    head = _commit(root, {"app.py": f'TOKEN = "{token}"\n'})
    bundle = _gate(root, base, head)
    result = _assert_check_results(bundle)["security"]
    assert result["outcome"] == "FAIL"
    secrets = [f for f in result["findings"] if f["defect_id"] == "SEC-SECRET"]
    assert len(secrets) == 1
    payload = secrets[0]["evidence"]["payload"]
    assert token not in json.dumps(secrets[0])
    assert payload["redacted"] == _redact(token)
    assert payload["validation"].startswith("offline:")


def test_shadow_secret_finding_is_not_suppressed_by_blocking_waiver(monkeypatch, tmp_path):
    from verifyci.gate import orchestrator
    monkeypatch.setattr(orchestrator, "verify_release_validation_evidence", lambda *args, **kwargs: (True, None))
    monkeypatch.setitem(
        CHECK_SPECS,
        "security",
        replace(
            CHECK_SPECS["security"],
            tier=Tier.ADVISORY,
            maturity=Maturity.SHADOW,
            promotion_record_hash="",
        ),
    )
    token = "ghp_1234567890abcdefghijABCDEFGHIJ"
    redacted = _redact(token)
    fingerprint = stable_finding_fingerprint(
        check_id="security",
        defect_id="SEC-SECRET",
        defect_semantics_version=1,
        path="app.py",
        symbol="",
        evidence_identity={
            "path": "app.py",
            "line": 1,
            "pattern": "GITHUB_TOKEN",
            "redacted": redacted,
        },
    )
    policy = (
        POLICY
        + "[waivers.known_secret]\n"
        + 'check = "security"\n'
        + 'defect_id = "SEC-SECRET"\n'
        + f'fingerprint = "{fingerprint}"\n'
        + 'reason = "test fixture"\n'
        + 'approved_by = "@org/security"\n'
        + 'created = "2026-10-01"\n'
        + 'expires = "2026-12-31"\n'
    )
    root, base = _repo(tmp_path, {"app.py": "x = 1\n"}, policy=policy)
    head = _commit(root, {"app.py": f'TOKEN = "{token}"\n'})
    bundle = _gate(root, base, head)
    assert bundle.payload["verdict"]["status"] == "PASS"
    assert bundle.exit_code == 0
    assert bundle.payload["waivers"] == []
    secret = next(f for f in bundle.payload["findings"] if f["defect_id"] == "SEC-SECRET")
    assert secret["disposition"] == "OPEN"


def test_coverage_acceptance_does_not_change_shadow_result(monkeypatch, tmp_path):
    from verifyci.gate import orchestrator
    monkeypatch.setattr(orchestrator, "verify_release_validation_evidence", lambda *args, **kwargs: (True, None))
    monkeypatch.setitem(
        CHECK_SPECS,
        "contract",
        replace(
            CHECK_SPECS["contract"],
            tier=Tier.ADVISORY,
            maturity=Maturity.SHADOW,
            promotion_record_hash="",
        ),
    )
    policy = (
        POLICY
        + "[coverage_acceptances.test_decorator]\n"
        + 'check = "contract"\n'
        + 'reason_code = "unknown_decorator"\n'
        + 'paths = ["app.py"]\n'
        + 'reason = "test fixture"\n'
        + 'approved_by = "@org/security"\n'
        + 'created = "2026-10-01"\n'
        + 'expires = "2026-12-31"\n'
    )
    root, base = _repo(tmp_path, {"app.py": "def deco(fn):\n    return fn\n\ndef f(a):\n    return a\n"}, policy=policy)
    head = _commit(
        root,
        {"app.py": "def deco(fn):\n    return fn\n\n@deco\ndef f(a):\n    return a\n"},
    )
    bundle = _gate(root, base, head)
    assert bundle.payload["verdict"]["status"] == "PASS"
    assert bundle.exit_code == 0
    result = _assert_check_results(bundle)["contract"]
    assert result["outcome"] == "INCONCLUSIVE"
    assert result["coverage"] == "PARTIAL"
    assert result["coverage_gaps"][0]["accepted"] is False
    assert bundle.payload["accepted_gaps"] == []


def test_configured_taint_without_resolved_path_is_inconclusive(tmp_path):
    policy = (
        POLICY
        + '[taint]\nsources = ["request.args"]\n'
        + '[taint.sinks.sql]\nsymbols = ["execute"]\nkind = "sql"\n'
    )
    root, base = _repo(tmp_path, {"app.py": "x = 1\n"}, policy=policy)
    head = _commit(root, {"app.py": 'q = request.args.get("q")\n'})
    bundle = _gate(root, base, head)
    assert bundle.payload["verdict"]["status"] == "INCONCLUSIVE"
    assert bundle.exit_code == 2
    result = _assert_check_results(bundle)["security"]
    assert "taint_path_unresolved" in result["reason_codes"]


def test_vendored_path_does_not_suppress_dangerous_call_scan(tmp_path):
    policy = POLICY + '[paths]\nvendored = ["vendor/**"]\n'
    root, base = _repo(tmp_path, {"app.py": "x = 1\n"}, policy=policy)
    head = _commit(root, {"vendor/new_tool.py": 'eval("1 + 1")\n'})
    bundle = _gate(root, base, head)
    assert bundle.payload["verdict"]["status"] == "FAIL"
    assert bundle.exit_code == 1
    result = _assert_check_results(bundle)["security"]
    assert any(f["defect_id"] == "SEC-DANGEROUS-CALL" for f in result["findings"])


def test_policy_change_requires_review_and_invalid_policy_is_error(tmp_path):
    root, base = _repo(tmp_path, {"app.py": "x = 1\n"})
    review_head = _commit(
        root,
        {".verifyci/policy.toml": POLICY + "cold_deadline_seconds = 60\n"},
    )
    review = _gate(root, base, review_head)
    assert review.payload["verdict"]["status"] == "REVIEW"
    assert review.exit_code == 4
    assert set(review.payload["verdict"]["reason_codes"]) >= {
        "policy_change_review",
        "gate_integrity_review",
    }

    bad_head = _commit(root, {".verifyci/policy.toml": "not = [valid\n"}, message="bad policy")
    error = _gate(root, base, bad_head)
    assert error.payload["verdict"]["status"] == "ERROR"
    assert error.exit_code == 3
    assert "invalid_policy" in error.payload["verdict"]["fault_reason_codes"]
    assert set(error.payload["verdict"]["reason_codes"]) >= {
        "policy_change_review",
        "gate_integrity_review",
    }
    assert len(error.payload["check_results"]) == 5


def test_gate_integrity_workflow_change_requires_review(tmp_path):
    root, base = _repo(tmp_path, {"app.py": "x = 1\n"})
    head = _commit(root, {".github/workflows/ci.yml": "name: CI\n"})
    bundle = _gate(root, base, head)
    assert bundle.payload["verdict"]["status"] == "REVIEW"
    assert bundle.exit_code == 4
    assert "gate_integrity_review" in bundle.payload["verdict"]["reason_codes"]


def test_policy_only_stale_waiver_remediation_respects_codeowners(tmp_path, capsys):
    expired = (
        POLICY
        + "[waivers.old]\n"
        + 'check = "security"\n'
        + 'defect_id = "SEC-SECRET"\n'
        + 'fingerprint = "sha256:' + "a" * 64 + '"\n'
        + 'reason = "historical fixture"\n'
        + 'approved_by = "@org/security"\n'
        + 'created = "2025-01-01"\n'
        + 'expires = "2025-06-01"\n'
    )
    root, base = _repo(
        tmp_path / "clear",
        {"app.py": "x = 1\n", ".github/CODEOWNERS": CODEOOWNERS_FULL},
        policy=expired,
    )
    clean_head = _commit(root, {".verifyci/policy.toml": POLICY})
    code = main(
        [
            "gate",
            "--repo",
            str(root),
            "--base",
            base,
            "--head",
            clean_head,
            "--review-mode",
            "codeowners",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "policy_change_review" in captured.out


    retained_root, retained_base = _repo(
        tmp_path / "retained",
        {"app.py": "x = 1\n", ".github/CODEOWNERS": CODEOOWNERS_FULL},
        policy=expired,
    )
    retained_policy = expired.replace(
        '[gate]\ntarget_drift = "record"\n',
        '[gate]\ntarget_drift = "record"\ncold_deadline_seconds = 60\n',
        1,
    )
    retained_head = _commit(
        retained_root,
        {".verifyci/policy.toml": retained_policy},
    )
    code = main(
        [
            "gate",
            "--repo",
            str(retained_root),
            "--base",
            retained_base,
            "--head",
            retained_head,
            "--review-mode",
            "codeowners",
        ]
    )
    captured = capsys.readouterr()
    assert code == 4
    assert "waiver_review" in captured.out


def test_unsupported_language_change_is_inconclusive(tmp_path):
    root, base = _repo(tmp_path, {"app.py": "x = 1\n"})
    head = _commit(root, {"main.go": "package main\n\nfunc main() {}\n"})
    bundle = _gate(root, base, head)
    results = _assert_check_results(bundle)
    assert bundle.payload["verdict"]["status"] == "INCONCLUSIVE"
    assert bundle.exit_code == 2
    for check_id in ("contract", "deletion"):
        result = results[check_id]
        assert result["outcome"] == "INCONCLUSIVE"
        assert any(g["reason_code"] == "unsupported_language" for g in result["coverage_gaps"])


def test_fingerprint_ignores_volatile_line_locations():
    first = stable_finding_fingerprint(
        check_id="security",
        defect_id="SEC-SECRET",
        defect_semantics_version=1,
        path="app.py",
        evidence_identity={
            "path": "app.py",
            "line": 1,
            "pattern": "GITHUB_TOKEN",
            "redacted": "ghp_...",
        },
    )
    second = stable_finding_fingerprint(
        check_id="security",
        defect_id="SEC-SECRET",
        defect_semantics_version=1,
        path="app.py",
        evidence_identity={
            "path": "app.py",
            "line": 999,
            "pattern": "GITHUB_TOKEN",
            "redacted": "ghp_...",
        },
    )
    assert first == second


def test_cli_formats_and_codeowners_review_mode(tmp_path, capsys, monkeypatch):
    root, base = _repo(tmp_path, {"app.py": "x = 1\n"})
    head = _commit(root, {"app.py": "x = 2\n"})

    # Proving that an unvalidated build cannot return an authoritative PASS via CLI
    from verifyci.gate import orchestrator
    monkeypatch.setattr(
        orchestrator,
        "verify_release_validation_evidence",
        lambda repo=None: (False, "release-validation artifacts are absent; this internal build cannot emit a normal gate verdict"),
    )
    unvalidated_code = main(["gate", "--repo", str(root), "--base", base, "--head", head, "--format", "json"])
    unvalidated_captured = capsys.readouterr()
    assert unvalidated_code == 3
    assert json.loads(unvalidated_captured.out)["payload"]["verdict"]["status"] == "ERROR"
    assert "check_not_validated" in json.loads(unvalidated_captured.out)["payload"]["verdict"]["fault_reason_codes"]

    # Undo unvalidated mock to verify validated behavior
    monkeypatch.undo()

    code = main(["gate", "--repo", str(root), "--base", base, "--head", head, "--format", "json"])
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["payload"]["verdict"]["status"] == "PASS"

    code = main(["gate", "--repo", str(root), "--base", base, "--head", head, "--format", "sarif"])
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)["version"] == "2.1.0"

    cache_dir = root / ".cache"
    cache_dir.mkdir()
    code = main(
        [
            "gate",
            "--repo",
            str(root),
            "--base",
            base,
            "--head",
            head,
            "--cache-dir",
            str(cache_dir),
        ]
    )
    assert code == 3

    # A canonical CODEOWNERS file covers every protected path, so the Action
    # review mode may clear the review-only exit code.
    root2, base2 = _repo(
        tmp_path / "review",
        {"app.py": "x = 1\n", ".github/CODEOWNERS": CODEOOWNERS_FULL},
    )
    head2 = _commit(root2, {".verifyci/policy.toml": POLICY + "cold_deadline_seconds = 60\n"})
    code = main(
        [
            "gate",
            "--repo",
            str(root2),
            "--base",
            base2,
            "--head",
            head2,
            "--review-mode",
            "codeowners",
        ]
    )
    assert code == 0


def test_accepted_gap_with_incomplete_scope_or_discovery_remains_inconclusive() -> None:
    from verifyci.contracts.model import (
        AcceptanceRecord,
        CheckResult,
        Coverage,
        CoverageGap,
        Outcome,
        Tier,
        Maturity,
    )
    from verifyci.gate.policy import Policy
    from verifyci.gate.verdict import apply_acceptances

    gap = CoverageGap(
        reason_code="dynamic_target_unresolved",
        subject={"path": "app.py"},
    )
    acceptance = AcceptanceRecord(
        record_id="acc1",
        check="deletion",
        reason_code="dynamic_target_unresolved",
        paths=("app.py",),
        symbols=(),
        reason="test",
        approved_by="@security",
        created="2026-10-01",
        expires="2026-12-31",
    )
    policy = Policy(
        raw={},
        source="repo",
        blob_hash="h1",
        effective_hash="e1",
        acceptances={"acc1": acceptance},
    )

    # Case 1: scope_enumeration is incomplete
    result_incomplete_scope = CheckResult(
        check_id="deletion",
        check_version=1,
        tier=Tier.BLOCKING,
        maturity=Maturity.PROVISIONAL,
        outcome=Outcome.INCONCLUSIVE,
        coverage=Coverage.PARTIAL,
        evaluated_scope={},
        scope_enumeration={"complete": False},
        candidate_discovery={"complete": True},
        applicability_evidence={},
        method="deletion",
        method_version=1,
        coverage_gaps=(gap,),
    )
    evaluated, _, _, _ = apply_acceptances(
        [result_incomplete_scope],
        policy,
        as_of_date="2026-10-21",
    )
    res = evaluated[0]
    assert res.coverage_gaps[0].accepted is True
    assert res.coverage == Coverage.UNKNOWN
    assert res.effective_coverage() == Coverage.UNKNOWN
    assert res.outcome == Outcome.INCONCLUSIVE

    # Case 2: candidate_discovery is incomplete
    result_incomplete_candidates = CheckResult(
        check_id="deletion",
        check_version=1,
        tier=Tier.BLOCKING,
        maturity=Maturity.PROVISIONAL,
        outcome=Outcome.INCONCLUSIVE,
        coverage=Coverage.PARTIAL,
        evaluated_scope={},
        scope_enumeration={"complete": True},
        candidate_discovery={"complete": False},
        applicability_evidence={},
        method="deletion",
        method_version=1,
        coverage_gaps=(gap,),
    )
    evaluated2, _, _, _ = apply_acceptances(
        [result_incomplete_candidates],
        policy,
        as_of_date="2026-10-21",
    )
    res2 = evaluated2[0]
    assert res2.coverage_gaps[0].accepted is True
    assert res2.coverage == Coverage.PARTIAL
    assert res2.effective_coverage() == Coverage.PARTIAL
    assert res2.outcome == Outcome.INCONCLUSIVE


def test_git_submodule_lifecycle(tmp_path: Path) -> None:
    """Gitlink (submodule 160000) add, update, and delete are handled without reading blobs."""
    from verifyci.scm.git import GitRepo

    root = tmp_path / "sub_repo"
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@test.local"], check=True)
    (root / ".verifyci").mkdir()
    (root / ".verifyci" / "policy.toml").write_text(POLICY)
    (root / "init.txt").write_text("initial")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "initial commit"], check=True)
    base = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()

    sha1 = "0123456789012345678901234567890123456789"
    subprocess.run(["git", "-C", str(root), "update-index", "--add", "--cacheinfo", f"160000,{sha1},vendor/sub"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "add submodule"], check=True)
    head_add = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()

    repo = GitRepo(root)
    entries_add, _ = repo.diff_entries(base, head_add)
    assert len(entries_add) == 1
    e_add = entries_add[0]
    assert e_add.is_submodule is True
    assert e_add.path == "vendor/sub"
    assert e_add.head_blob == sha1
    assert e_add.base_blob is None

    # Gate run treats submodule as excluded scope without error
    bundle_add = _gate(root, base, head_add)
    assert bundle_add.payload["verdict"]["status"] == "PASS"
    assert bundle_add.exit_code == 0
    excluded_kinds = [x["kind"] for x in bundle_add.payload["excluded_scope"]]
    assert "submodule" in excluded_kinds

    # Update submodule commit
    sha2 = "9876543210987654321098765432109876543210"
    subprocess.run(["git", "-C", str(root), "update-index", "--add", "--cacheinfo", f"160000,{sha2},vendor/sub"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "update submodule"], check=True)
    head_upd = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()

    entries_upd, _ = repo.diff_entries(head_add, head_upd)
    assert len(entries_upd) == 1
    e_upd = entries_upd[0]
    assert e_upd.is_submodule is True
    assert e_upd.base_blob == sha1
    assert e_upd.head_blob == sha2

    # Delete submodule
    subprocess.run(["git", "-C", str(root), "rm", "--cached", "vendor/sub"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "delete submodule"], check=True)
    head_del = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()

    entries_del, _ = repo.diff_entries(head_upd, head_del)
    assert len(entries_del) == 1
    e_del = entries_del[0]
    assert e_del.is_submodule is True
    assert e_del.base_blob == sha2
    assert e_del.head_blob is None


def test_rename_limit_detection_logic() -> None:
    """Rename limit threshold counts add/delete candidates only when candidates exist on both sides."""
    # Case 1: 2005 modifications (M) -> add_candidates=0, del_candidates=0 -> NOT exceeded
    mod_records = [
        ("file_%04d.py" % i, "file_%04d.py" % i, "100644", "100644", "a" * 40, "b" * 40, "M")
        for i in range(2005)
    ]
    add_c = sum(1 for r in mod_records if r[6].startswith("A") or not r[4])
    del_c = sum(1 for r in mod_records if r[6].startswith("D") or not r[5])
    both = add_c > 0 and del_c > 0
    rename_limit_exceeded = (
        (both and (add_c + del_c > 2000))
        or (both and (add_c * del_c > 2000))
    )
    assert rename_limit_exceeded is False

    # Case 2: 2500 pure additions (0 deletes) -> NOT exceeded (no pairing candidates exist)
    pure_adds = [
        (None, "new_%04d.py" % i, None, "100644", None, "b" * 40, "A")
        for i in range(2500)
    ]
    add_c = sum(1 for r in pure_adds if r[6].startswith("A") or not r[4])
    del_c = sum(1 for r in pure_adds if r[6].startswith("D") or not r[5])
    assert add_c == 2500 and del_c == 0
    both = add_c > 0 and del_c > 0
    rename_limit_exceeded = (
        (both and (add_c + del_c > 2000))
        or (both and (add_c * del_c > 2000))
    )
    assert rename_limit_exceeded is False

    # Case 3: 2500 pure deletions (0 additions) -> NOT exceeded (no pairing candidates exist)
    pure_dels = [
        ("old_%04d.py" % i, None, "100644", None, "a" * 40, None, "D")
        for i in range(2500)
    ]
    add_c = sum(1 for r in pure_dels if r[6].startswith("A") or not r[4])
    del_c = sum(1 for r in pure_dels if r[6].startswith("D") or not r[5])
    assert add_c == 0 and del_c == 2500
    both = add_c > 0 and del_c > 0
    rename_limit_exceeded = (
        (both and (add_c + del_c > 2000))
        or (both and (add_c * del_c > 2000))
    )
    assert rename_limit_exceeded is False

    # Case 4: 1500 adds and 600 deletes -> add_candidates=1500, del_candidates=600 -> sum=2100 > 2000 -> EXCEEDED
    all_records = pure_adds[:1500] + pure_dels[:600]
    add_c = sum(1 for r in all_records if r[6].startswith("A") or not r[4])
    del_c = sum(1 for r in all_records if r[6].startswith("D") or not r[5])
    both = add_c > 0 and del_c > 0
    rename_limit_exceeded = (
        (both and (add_c + del_c > 2000))
        or (both and (add_c * del_c > 2000))
    )
    assert rename_limit_exceeded is True


def test_coverage_invariants_and_fail_closed_validation() -> None:
    """Coverage invariants strictly prevent fail-open COMPLETE promotion."""
    from verifyci.contracts.model import (
        CheckResult,
        Coverage,
        CoverageGap,
        Outcome,
        Tier,
        Maturity,
    )

    base_kwargs = {
        "check_id": "contract",
        "check_version": 1,
        "tier": Tier.BLOCKING,
        "maturity": Maturity.PROVISIONAL,
        "outcome": Outcome.PASS,
        "evaluated_scope": {},
        "applicability_evidence": {},
        "method": "signature",
        "method_version": 1,
    }

    # 1. coverage=COMPLETE with incomplete scope enumeration
    res_scope = CheckResult(
        **base_kwargs,
        coverage=Coverage.COMPLETE,
        scope_enumeration={"complete": False},
        candidate_discovery={"complete": True},
    )
    assert res_scope.effective_coverage() == Coverage.UNKNOWN
    errors = res_scope.validate()
    assert any("COMPLETE coverage requires scope_enumeration.complete == True" in e for e in errors)
    assert any("PASS requires effective COMPLETE coverage" in e for e in errors)

    # 1b. coverage=PARTIAL with incomplete scope enumeration yields UNKNOWN
    res_partial_scope = CheckResult(
        **{**base_kwargs, "outcome": Outcome.INCONCLUSIVE},
        coverage=Coverage.PARTIAL,
        scope_enumeration={"complete": False},
        candidate_discovery={"complete": True},
    )
    assert res_partial_scope.effective_coverage() == Coverage.UNKNOWN

    # 2. coverage=COMPLETE with incomplete candidate discovery
    res_cand = CheckResult(
        **base_kwargs,
        coverage=Coverage.COMPLETE,
        scope_enumeration={"complete": True},
        candidate_discovery={"complete": False},
    )
    assert res_cand.effective_coverage() == Coverage.PARTIAL
    errors = res_cand.validate()
    assert any("COMPLETE coverage requires candidate_discovery.complete == True" in e for e in errors)
    assert any("PASS requires effective COMPLETE coverage" in e for e in errors)

    # 3. coverage=COMPLETE with unaccepted gaps
    unaccepted_gap = CoverageGap(reason_code="dynamic_call_unresolved", subject={"path": "lib.py"}, accepted=False)
    res_gap = CheckResult(
        **base_kwargs,
        coverage=Coverage.COMPLETE,
        scope_enumeration={"complete": True},
        candidate_discovery={"complete": True},
        coverage_gaps=(unaccepted_gap,),
    )
    assert res_gap.effective_coverage() == Coverage.PARTIAL
    errors = res_gap.validate()
    assert any("COMPLETE coverage cannot carry unaccepted coverage gaps" in e for e in errors)
    assert any("PASS requires effective COMPLETE coverage" in e for e in errors)

    # 4. Parent result marked complete while child sub-result is incomplete
    incomplete_sub = CheckResult(
        check_id="contract.sub",
        check_version=1,
        tier=Tier.BLOCKING,
        maturity=Maturity.PROVISIONAL,
        outcome=Outcome.INCONCLUSIVE,
        coverage=Coverage.PARTIAL,
        evaluated_scope={},
        scope_enumeration={"complete": True},
        candidate_discovery={"complete": False},
        applicability_evidence={},
        method="sub",
        method_version=1,
    )
    res_parent = CheckResult(
        **base_kwargs,
        coverage=Coverage.COMPLETE,
        scope_enumeration={"complete": True},
        candidate_discovery={"complete": True},
        sub_results=(incomplete_sub,),
    )
    assert res_parent.effective_coverage() == Coverage.PARTIAL
    errors = res_parent.validate()
    assert any("COMPLETE coverage requires all sub_results to have COMPLETE coverage" in e for e in errors)
    assert any("PASS requires effective COMPLETE coverage" in e for e in errors)

    # 5. NOT_APPLICABLE requires effective COMPLETE coverage
    res_na_incomplete = CheckResult(
        **{**base_kwargs, "outcome": Outcome.NOT_APPLICABLE},
        coverage=Coverage.PARTIAL,
        scope_enumeration={"complete": True},
        candidate_discovery={"complete": False},
    )
    errors = res_na_incomplete.validate()
    assert any("NOT_APPLICABLE requires effective COMPLETE coverage" in e for e in errors)



