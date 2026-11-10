"""Phase D remediation tests.

Covers:
- scripts/verifyci_workflow_guards.py CLI input validators (D1) incl. hostile input
- scripts/ci_test_selector.py base_ref + hostile test-name hardening (D7)
- Workflow wiring for the guard script (D2-D6) + YAML parseability (D8)

yaml (PyYAML) is a declared dev dependency and is used to parse workflow files.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts.ci_test_selector import validate_base_ref, validate_test_targets
from scripts.verifyci_workflow_guards import (
    require_evidence_commit,
    validate_branch,
    validate_hex_pubkey_pair,
    validate_image_tag,
    validate_rev,
    validate_run_id,
    validate_tag,
    validate_worker_image,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
GUARD_SCRIPT = REPO_ROOT / "scripts" / "verifyci_workflow_guards.py"

NEWLINE_INJECTIONS = [
    "",
    "\n",
    "x\ny",
    "x\r\ny",
    "x\nrm -rf /",
    "; rm -rf /",
    "$(echo pwned)",
    "`id`",
    "../",
    "../../etc/passwd",
    "a" * 10000,
    "\u202ereversed",
    "\u00e9nonascii",
    "x y",
    "x;y",
    "x|y",
    "x&y",
    "x>y",
    "\ttab",
]


# ---------------------------------------------------------------------------
# D1: guard validators — accept paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("validator", "value"),
    [
        (validate_branch, "evidence/1a2b3c4"),
        (validate_branch, "evidence/feat.x_y-1"),
        (validate_branch, "evidence/" + "a" * 80),
        (validate_run_id, "1234567890"),
        (validate_run_id, "0"),
        (validate_run_id, "9" * 20),
        (validate_image_tag, "latest"),
        (validate_image_tag, "v1.2.3"),
        (validate_image_tag, "A_b-c.d9"),
        (validate_image_tag, "a" * 64),
        (
            validate_worker_image,
            "ghcr.io/neutronzero/verifyci-worker@sha256:" + "ab" * 32,
        ),
        (validate_rev, "a" * 40),
        (validate_rev, "abcdef1"),
        (validate_rev, "f" * 64),
        (validate_rev, "v0.1.0"),
        (validate_rev, "v10"),
        (validate_rev, "v1.2.3-rc1"),
        (validate_tag, "v0.1.0"),
        (validate_tag, "v1.2.3-rc1"),
        (validate_tag, "v1" + "a" * 60),
    ],
)
def test_valid_inputs_accepted(validator, value):
    assert validator(value) == value


# ---------------------------------------------------------------------------
# D1: guard validators — hostile inputs rejected
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", NEWLINE_INJECTIONS)
def test_branch_rejects_hostile(value):
    with pytest.raises(ValueError):
        validate_branch(value)


@pytest.mark.parametrize("value", NEWLINE_INJECTIONS)
def test_run_id_rejects_hostile(value):
    with pytest.raises(ValueError):
        validate_run_id(value)


@pytest.mark.parametrize("value", NEWLINE_INJECTIONS)
def test_image_tag_rejects_hostile(value):
    with pytest.raises(ValueError):
        validate_image_tag(value)


@pytest.mark.parametrize("value", NEWLINE_INJECTIONS)
def test_worker_image_rejects_hostile(value):
    with pytest.raises(ValueError):
        validate_worker_image(value)


@pytest.mark.parametrize("value", NEWLINE_INJECTIONS)
def test_rev_rejects_hostile(value):
    with pytest.raises(ValueError):
        validate_rev(value)


@pytest.mark.parametrize("value", NEWLINE_INJECTIONS)
def test_tag_rejects_hostile(value):
    with pytest.raises(ValueError):
        validate_tag(value)


@pytest.mark.parametrize(
    "value",
    [
        "main",
        "release-authority",
        "refs/heads/main",
        "refs/",
        "evidence/../secrets",
        "evidence/a..b",
        "evidence/",
        "evidence/" + "a" * 81,
        "Evidence/abc",
        " evidence/abc",
        "evidence/abc ",
        "evidence/abc\ndef",
        "evidence/abc;touch /tmp/pwn",
        "evidence/$(pwn)",
    ],
)
def test_branch_denylist(value):
    with pytest.raises(ValueError):
        validate_branch(value)


def test_image_tag_rejects_registry_shape():
    # colon, slash and @ must be rejected: tag is used unquoted in docker tags
    for value in ("ghcr.io/x", "tag:latest", "tag@sha256:" + "ab" * 32, "a/b", "a@b"):
        with pytest.raises(ValueError):
            validate_image_tag(value)


def test_worker_image_requires_digest_pin():
    bad = [
        "ghcr.io/neutronzero/verifyci-worker:latest",
        "ghcr.io/neutronzero/verifyci-worker",
        "@sha256:" + "ab" * 32,
        "ghcr.io/x@sha256:" + "ab" * 31,
        "ghcr.io/x@sha256:" + "AB" * 32,
        "ghcr.io/x@md5:" + "ab" * 32,
        "ghcr.io/x@sha256:" + "ab" * 32 + "\n",
    ]
    for value in bad:
        with pytest.raises(ValueError):
            validate_worker_image(value)


def test_rev_rejects_non_hex_non_tag():
    bad = [
        "1.2.3",
        "-abcdef1",
        "v-1",
        "vx1",
        "V1.0.0",
        "g" * 40,
        "a" * 65,
        "a" * 6,
    ]
    for value in bad:
        with pytest.raises(ValueError):
            validate_rev(value)


def test_tag_rejects_non_version():
    bad = ["0.1.0", "v", "vx", "V1.0.0", "v1" + "a" * 61, "refs/tags/v1.0.0", "v1.0 "]
    for value in bad:
        with pytest.raises(ValueError):
            validate_tag(value)


# ---------------------------------------------------------------------------
# D1: --require-evidence-commit semantics (unit-level + CLI)
# ---------------------------------------------------------------------------

VALID_IMPL_FP = "sha256:" + "ab" * 32


def _write_evidence(tmp_path: Path, commit_sha: str, fingerprint: str = VALID_IMPL_FP) -> Path:
    rel = Path("evidence") / "release" / "release_validation.json"
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "schema": "verifyci.release_validation/v1",
                "status": "VALIDATED",
                "commit_sha": commit_sha,
                "implementation_fingerprint": fingerprint,
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def test_require_evidence_commit_match_ok(tmp_path):
    sha = "b" * 40
    _write_evidence(tmp_path, sha)
    assert require_evidence_commit(str(tmp_path), sha) is None


def test_require_evidence_commit_case_insensitive(tmp_path):
    _write_evidence(tmp_path, "A" * 40)
    assert require_evidence_commit(str(tmp_path), "a" * 40) is None


def test_require_evidence_commit_missing_file(tmp_path):
    with pytest.raises(ValueError):
        require_evidence_commit(str(tmp_path), "c" * 40)


def test_require_evidence_commit_bad_json(tmp_path):
    rel = Path("evidence") / "release" / "release_validation.json"
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        require_evidence_commit(str(tmp_path), "c" * 40)


def test_require_evidence_commit_mismatch(tmp_path):
    _write_evidence(tmp_path, "d" * 40)
    with pytest.raises(ValueError):
        require_evidence_commit(str(tmp_path), "e" * 40)


@pytest.mark.parametrize("bad_sha", ["", "abc123", "g" * 40, "a" * 39, "a" * 41, "a" * 40 + "\n"])
def test_require_evidence_commit_invalid_commit_arg(tmp_path, bad_sha):
    with pytest.raises(ValueError):
        require_evidence_commit(str(tmp_path), bad_sha)


@pytest.mark.parametrize("fp", ["md5:" + "ab" * 32, "", None])
def test_require_evidence_commit_fingerprint_must_be_sha256(tmp_path, fp):
    sha = "f" * 40
    _write_evidence(tmp_path, sha, fp)
    with pytest.raises(ValueError):
        require_evidence_commit(str(tmp_path), sha)


def test_require_evidence_commit_invalid_stored_commit(tmp_path):
    _write_evidence(tmp_path, "nothex")
    with pytest.raises(ValueError):
        require_evidence_commit(str(tmp_path), "f" * 40)


# ---------------------------------------------------------------------------
# D1: --verify-pubkey semantics
# ---------------------------------------------------------------------------


def test_verify_pubkey_equal_ok():
    assert validate_hex_pubkey_pair("ab" * 32, "AB" * 32) is None


def test_verify_pubkey_short_but_valid():
    assert validate_hex_pubkey_pair("ab" * 16, "ab" * 16) is None


@pytest.mark.parametrize(
    ("embedded", "pinned"),
    [
        ("", "ab" * 32),
        ("ab" * 32, ""),
        ("ab" * 32, "ac" * 32),  # mismatch
        ("a" * 33, "a" * 33),  # odd length (>= 32)
        ("ab" * 15, "ab" * 15),  # even but < 32 chars
        ("zz" * 32, "zz" * 32),  # non-hex
        ("ab" * 32, "ab" * 32 + "\n"),
        ("ab" * 32 + " ", "ab" * 32),
    ],
)
def test_verify_pubkey_rejects(embedded, pinned):
    with pytest.raises(ValueError):
        validate_hex_pubkey_pair(embedded, pinned)


# ---------------------------------------------------------------------------
# D1: CLI surface — exit 0 valid / exit 1 invalid with stderr reason
# ---------------------------------------------------------------------------


def _run_guard(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GUARD_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def test_cli_valid_branch_exit_zero():
    proc = _run_guard("--branch", "evidence/abc123")
    assert proc.returncode == 0, proc.stderr


@pytest.mark.parametrize(
    ("args",),
    [
        (("--branch", "main"),),
        (("--branch", "$(pwn)"),),
        (("--branch", "evidence/../../x"),),
        (("--branch", "refs/heads/release-authority"),),
        (("--run-id", "1;2"),),
        (("--run-id", "abc"),),
        (("--image-tag", "tag:latest"),),
        (("--image-tag", "x\ny"),),
        (("--worker-image", "ghcr.io/x:latest"),),
        (("--rev=-bad",),),
        (("--tag", "notaversion"),),
    ],
)
def test_cli_invalid_exit_one_with_stderr(args):
    proc = _run_guard(*args)
    assert proc.returncode == 1
    assert proc.stderr.strip(), "reason must go to stderr"


def test_cli_verify_pubkey_exit_zero_and_one():
    ok = _run_guard("--verify-pubkey", "ab" * 32, "AB" * 32)
    assert ok.returncode == 0, ok.stderr
    bad = _run_guard("--verify-pubkey", "ab" * 32, "ac" * 32)
    assert bad.returncode == 1
    assert bad.stderr.strip()


def test_cli_require_evidence_commit_roundtrip(tmp_path):
    sha = "e" * 40
    _write_evidence(tmp_path, sha)
    ok = _run_guard("--require-evidence-commit", str(tmp_path), "--commit", sha)
    assert ok.returncode == 0, ok.stderr
    bad = _run_guard("--require-evidence-commit", str(tmp_path), "--commit", "f" * 40)
    assert bad.returncode == 1
    assert bad.stderr.strip()


def test_cli_multiple_flags_all_validated():
    proc = _run_guard("--run-id", "123", "--image-tag", "latest")
    assert proc.returncode == 0, proc.stderr
    proc = _run_guard("--run-id", "123", "--image-tag", "bad tag")
    assert proc.returncode == 1


# ---------------------------------------------------------------------------
# D7: ci_test_selector hardening
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "base",
    [
        "origin/main",
        "origin/release-1.0",
        "abc123",
        "refs/remotes/origin/x",
        "a/b_c.d-e",
    ],
)
def test_base_ref_valid(base):
    assert validate_base_ref(base) == base


@pytest.mark.parametrize(
    "base",
    [
        "",
        "-oProxyCommand=evil",
        "--upload-pack=evil",
        "-x",
        "origin main",
        "origin/main\n",
        "origin/main; rm -rf /",
        "origin/main$(pwn)",
        "origin/main`id`",
        "origin/main|evil",
        "origin/main&evil",
        "a\tb",
        "a" * 10000,
        "\u00e9vil",
    ],
)
def test_base_ref_rejects_injection(base):
    with pytest.raises((ValueError, SystemExit)):
        validate_base_ref(base)


@pytest.mark.parametrize(
    "target",
    [
        "tests/v3/test evil newline.py",
        "tests/v3/evil\nnewline.py",
        "tests/v3/x; rm -rf .py",
        "tests/v3/$(pwned).py",
        "tests/v3/back`tick`.py",
        "tests/v3/\u00fcnicode.py",
        "tests/../escape.py",
        "tests/v3\n/evil.py",
    ],
)
def test_hostile_test_names_excluded_by_allowlist(target):
    with pytest.raises(ValueError):
        validate_test_targets([target])


def test_hostile_changed_file_never_selected(tmp_path, monkeypatch):
    # A hostile tests/*.py name that does not exist on disk must not be selected
    monkeypatch.chdir(tmp_path)
    from scripts.ci_test_selector import select_tests

    selected = select_tests(["tests/v3/x; rm -rf .py", "tests/v3/$(pwned).py"])
    for hostile in ("x; rm -rf .py", "$(pwned).py"):
        assert not any(hostile in t for t in selected)


def test_selector_cli_rejects_hostile_base(tmp_path):
    proc = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "ci_test_selector.py"),
            "--upload-pack=evil",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(tmp_path),
        timeout=60,
    )
    assert proc.returncode != 0
    assert proc.stdout.strip() == ""
    assert proc.stderr.strip()


# ---------------------------------------------------------------------------
# D8 + D2-D6: workflow wiring
# ---------------------------------------------------------------------------


def _load(name: str):
    text = (WORKFLOW_DIR / name).read_text(encoding="utf-8")
    return text, yaml.safe_load(text)


def _run_blocks(doc) -> list[str]:
    blocks = []
    for job in (doc.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                blocks.append(step["run"])
    return blocks


def _step_index(doc, needle: str) -> int:
    """Index of first step (any kind) whose run/uses text contains needle."""
    idx = 0
    for job in (doc.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            haystack = " ".join(
                str(v) for v in (step.get("run"), step.get("uses")) if isinstance(v, str)
            ) if isinstance(step, dict) else ""
            if needle in haystack:
                return idx
            idx += 1
    raise AssertionError(f"step containing {needle!r} not found")


def test_workflows_parse_with_yaml():
    for name in (
        "build_worker_image.yml",
        "release_measurements.yml",
        "publish_release_evidence.yml",
        "release.yml",
        "image_build_caller.yml",
    ):
        _, doc = _load(name)
        assert isinstance(doc, dict) and "jobs" in doc, name


def test_d2_build_worker_image_guard_before_push():
    text, doc = _load("build_worker_image.yml")
    blocks = _run_blocks(doc)
    guard_blocks = [b for b in blocks if "verifyci_workflow_guards.py --image-tag" in b]
    assert guard_blocks, "guard invocation for --image-tag must exist in a run block"
    assert any("set -euo pipefail" in b for b in guard_blocks)
    guard_idx = _step_index(doc, "verifyci_workflow_guards.py --image-tag")
    push_idx = _step_index(doc, "docker/build-push-action")
    assert guard_idx < push_idx, "tag validation must run before docker build/push"


def test_d3_release_measurements_worker_image_guard():
    _, doc = _load("release_measurements.yml")
    blocks = _run_blocks(doc)
    assert any("verifyci_workflow_guards.py --worker-image" in b for b in blocks)
    guard_idx = _step_index(doc, "verifyci_workflow_guards.py --worker-image")
    pull_idx = _step_index(doc, "docker pull")
    assert guard_idx < pull_idx, "worker-image validation must run before docker pull"


def test_d3_release_measurements_pinned_key_check():
    text, doc = _load("release_measurements.yml")
    blocks = _run_blocks(doc)
    assert any("verifyci_workflow_guards.py --verify-pubkey" in b for b in blocks)
    assert "vars.RELEASE_AUTHORITY_PUBLIC_KEY_HEX" in text
    # fail-closed: empty/missing var must fail — the guard enforces hex >= 32 chars
    pinned_blocks = [b for b in blocks if "--verify-pubkey" in b]
    assert pinned_blocks


def test_d4_publish_release_evidence_guards():
    text, doc = _load("publish_release_evidence.yml")
    blocks = _run_blocks(doc)
    for needle in (
        "verifyci_workflow_guards.py --branch",
        "verifyci_workflow_guards.py --run-id",
        "verifyci_workflow_guards.py --rev",
        "verifyci_workflow_guards.py --verify-pubkey",
    ):
        assert any(needle in b for b in blocks), needle
    assert "vars.RELEASE_AUTHORITY_PUBLIC_KEY_HEX" in text
    # branch validation must precede `git checkout -B`
    assert text.index("verifyci_workflow_guards.py --branch") < text.index(
        "git checkout -B"
    ), "--branch validation must run before git checkout -B"


def test_d4_publish_default_branch_shape_passes_guard():
    # default evidence branch: evidence/<40-hex candidate sha> must satisfy --branch
    from scripts.verifyci_workflow_guards import validate_branch

    assert validate_branch("evidence/" + "a" * 40) == "evidence/" + "a" * 40


def test_d5_release_environment_and_tag_guard():
    _, doc = _load("release.yml")
    create_release = doc["jobs"]["create-release"]
    assert create_release.get("environment") == "release"
    blocks = _run_blocks(doc)
    assert any("verifyci_workflow_guards.py --tag" in b for b in blocks)
    # push path strips refs/tags/ prefix before validation
    tag_blocks = [b for b in blocks if "verifyci_workflow_guards.py --tag" in b]
    assert any("refs/tags/" in b for b in tag_blocks)


def test_d5_release_requires_evidence_commit_push_only():
    _, doc = _load("release.yml")
    create_release = doc["jobs"]["create-release"]
    evidence_steps = [
        s
        for s in create_release.get("steps") or []
        if isinstance(s, dict)
        and isinstance(s.get("run"), str)
        and "verifyci_workflow_guards.py --require-evidence-commit" in s["run"]
    ]
    assert evidence_steps, "require-evidence-commit step must exist in create-release"
    step = evidence_steps[0]
    assert step.get("if") == "github.event_name == 'push'", (
        "evidence-commit gate must be push-tags only (dispatch residual is noted in workflow)"
    )


def test_d5_release_dispatch_residual_noted():
    text, _ = _load("release.yml")
    assert "residual" in text.lower(), (
        "dispatch-path residual (charset-only validation) must be documented in a workflow comment"
    )


def test_d6_no_secrets_inherit_and_only_github_token():
    caller_text, _ = _load("image_build_caller.yml")
    assert "secrets: inherit" not in caller_text
    callee_text, _ = _load("build_worker_image.yml")
    used_secrets = set(re.findall(r"secrets\.[A-Za-z_][A-Za-z0-9_]*", callee_text))
    assert used_secrets <= {"secrets.GITHUB_TOKEN"}, (
        f"callee uses non-implicit secrets: {used_secrets - {'secrets.GITHUB_TOKEN'}}"
    )
