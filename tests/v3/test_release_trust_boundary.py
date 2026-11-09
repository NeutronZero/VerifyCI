"""Adversarial tests for the M4 release-signing trust boundary.

These tests intentionally exercise the negative paths that must fail closed before
the release authority can sign: OIDC workflow identity, GitHub Actions provenance,
artifact archive integrity, and the workflow topology itself.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import time
import zipfile

import pytest
import yaml

REPO = "NeutronZero/VerifyCI"
CANDIDATE_SHA = "a" * 40
TRUSTED_SHA = "b" * 40
CANDIDATE_REF = "refs/heads/feat/v3.1.10-m4-security"
MEASUREMENT_WORKFLOW_PATH = ".github/workflows/release_measurements.yml"
ARTIFACT_ID = 771122
ARTIFACT_DIGEST = "sha256:" + "c" * 64

ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# OIDC helpers
# ---------------------------------------------------------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _generate_jwks():
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key().public_numbers()

    def uint_b64(value: int) -> str:
        return _b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "m4-test-kid",
                "n": uint_b64(pub.n),
                "e": uint_b64(pub.e),
            }
        ]
    }
    return priv, jwks


def _sign_jwt(priv, payload: dict) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    header = {"alg": "RS256", "kid": "m4-test-kid", "typ": "JWT"}
    h = _b64url(json.dumps(header).encode("utf-8"))
    p = _b64url(json.dumps(payload).encode("utf-8"))
    sig = priv.sign(f"{h}.{p}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64url(sig)}"


def _oidc_claims(**overrides):
    claims = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "verifyci-release-authority",
        "exp": time.time() + 300,
        "nbf": time.time() - 10,
        "iat": time.time() - 20,
        "repository": REPO,
        "repository_id": "1392600740",
        "repository_owner": "NeutronZero",
        "sha": CANDIDATE_SHA,
        "ref": CANDIDATE_REF,
        "ref_type": "branch",
        "event_name": "push",
        "run_id": "500",
        "run_attempt": "1",
        "job_workflow_ref": f"{REPO}/{MEASUREMENT_WORKFLOW_PATH}@refs/heads/release-authority",
        "job_workflow_sha": TRUSTED_SHA,
        "workflow_ref": f"{REPO}/.github/workflows/ci.yml@{CANDIDATE_REF}",
        "workflow_sha": CANDIDATE_SHA,
        "sub": f"repo:{REPO}:ref:{CANDIDATE_REF}",
    }
    claims.update(overrides)
    return claims


def _verify_oidc(token, jwks, **kwargs):
    from scripts.standalone_signer import verify_github_oidc_token

    return verify_github_oidc_token(
        token,
        REPO,
        CANDIDATE_SHA,
        "500",
        "1",
        jwks=jwks,
        expected_workflow_path=MEASUREMENT_WORKFLOW_PATH,
        expected_workflow_sha=TRUSTED_SHA,
        expected_ref=CANDIDATE_REF,
        current_time=time.time(),
        **kwargs,
    )


def test_oidc_accepts_exact_trusted_measurement_workflow_identity():
    priv, jwks = _generate_jwks()
    token = _sign_jwt(priv, _oidc_claims())
    claims, errors = _verify_oidc(token, jwks)
    assert errors == []
    assert claims is not None
    assert claims["job_workflow_sha"] == TRUSTED_SHA


def test_oidc_rejects_untrusted_workflow_sha_even_with_trusted_ref():
    priv, jwks = _generate_jwks()
    token = _sign_jwt(priv, _oidc_claims(job_workflow_sha="d" * 40))
    claims, errors = _verify_oidc(token, jwks)
    assert claims is None
    assert any("job_workflow_sha" in e for e in errors)


def test_oidc_rejects_workflow_path_prefix_confusion():
    priv, jwks = _generate_jwks()
    token = _sign_jwt(
        priv,
        _oidc_claims(
            job_workflow_ref=(
                f"{REPO}/{MEASUREMENT_WORKFLOW_PATH}.attacker@refs/heads/release-authority"
            )
        ),
    )
    claims, errors = _verify_oidc(token, jwks)
    assert claims is None
    assert any("job_workflow_ref" in e for e in errors)


def test_oidc_rejects_wrong_workflow_ref_suffix():
    priv, jwks = _generate_jwks()
    token = _sign_jwt(
        priv,
        _oidc_claims(
            job_workflow_ref=f"{REPO}/{MEASUREMENT_WORKFLOW_PATH}@refs/heads/attacker"
        ),
    )
    claims, errors = _verify_oidc(token, jwks)
    assert claims is None
    assert any("job_workflow_ref" in e for e in errors)


@pytest.mark.parametrize(
    "missing",
    ["job_workflow_ref", "job_workflow_sha", "ref", "sha", "run_id", "run_attempt"],
)
def test_oidc_rejects_missing_required_claims(missing):
    priv, jwks = _generate_jwks()
    claims = _oidc_claims()
    claims.pop(missing)
    token = _sign_jwt(priv, claims)
    result, errors = _verify_oidc(token, jwks)
    assert result is None
    assert errors


def test_oidc_rejects_candidate_workflow_identity():
    """A valid token from the candidate's own ci.yml cannot authorize signing."""
    priv, jwks = _generate_jwks()
    token = _sign_jwt(
        priv,
        _oidc_claims(
            job_workflow_ref=f"{REPO}/.github/workflows/ci.yml@{CANDIDATE_REF}",
            job_workflow_sha=CANDIDATE_SHA,
        ),
    )
    claims, errors = _verify_oidc(token, jwks)
    assert claims is None
    assert any("job_workflow_ref" in e or "job_workflow_sha" in e for e in errors)


# ---------------------------------------------------------------------------
# Provenance helpers
# ---------------------------------------------------------------------------
class _Response:
    def __init__(self, data: dict):
        self._data = json.dumps(data).encode("utf-8")

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def _valid_run():
    return {
        "id": 500,
        "run_attempt": 1,
        "head_sha": CANDIDATE_SHA,
        "head_branch": "feat/v3.1.10-m4-security",
        "path": ".github/workflows/ci.yml",
        "status": "completed",
        "conclusion": "success",
        "event": "push",
        "repository": {"full_name": REPO},
    }


def _valid_jobs():
    steps = [
        {"number": 1, "name": "Checkout Candidate Source", "status": "completed", "conclusion": "success"},
        {
            "number": 2,
            "name": "Verify Trusted Measurement Harness Integrity",
            "status": "completed",
            "conclusion": "success",
        },
        {"number": 3, "name": "Run Trusted Measurement Pipeline", "status": "completed", "conclusion": "success"},
        {
            "number": 4,
            "name": "Upload Release Measurements Artifact",
            "status": "completed",
            "conclusion": "success",
        },
    ]
    return {
        "total_count": 1,
        "jobs": [
            {
                "id": 9001,
                "name": "verifyci-measurements",
                "status": "completed",
                "conclusion": "success",
                "head_sha": CANDIDATE_SHA,
                "started_at": "2026-10-31T12:00:00Z",
                "completed_at": "2026-10-31T12:05:00Z",
                "steps": steps,
            }
        ],
    }


def _valid_artifacts():
    return {
        "total_count": 1,
        "artifacts": [
            {
                "id": ARTIFACT_ID,
                "name": "release-measurements",
                "size_in_bytes": 4096,
                "digest": ARTIFACT_DIGEST,
                "expired": False,
                "created_at": "2026-10-31T12:04:00Z",
                "workflow_run": {
                    "id": 500,
                    "head_sha": CANDIDATE_SHA,
                    "head_branch": "feat/v3.1.10-m4-security",
                },
            }
        ],
    }


def _mock_provenance(monkeypatch, run=None, jobs=None, artifacts=None, api_error=None):
    import scripts.standalone_signer as signer

    run_data = run if run is not None else _valid_run()
    jobs_data = jobs if jobs is not None else _valid_jobs()
    artifacts_data = artifacts if artifacts is not None else _valid_artifacts()

    def fake_urlopen(req, timeout=30):
        url = req.full_url
        if api_error and api_error in url:
            raise OSError(f"simulated API failure for {url}")
        if "/jobs" in url:
            return _Response(jobs_data)
        if "/artifacts" in url:
            return _Response(artifacts_data)
        if "/runs/" in url:
            return _Response(run_data)
        raise OSError(f"unexpected URL {url}")

    monkeypatch.setattr(signer.urllib.request, "urlopen", fake_urlopen)


def _verify_provenance(**overrides):
    from scripts.standalone_signer import verify_github_actions_provenance

    kwargs = {
        "expected_ref": CANDIDATE_REF,
        "expected_artifact_id": ARTIFACT_ID,
        "expected_artifact_digest": ARTIFACT_DIGEST,
        "artifact_zip_sha256": ARTIFACT_DIGEST,
    }
    kwargs.update(overrides)
    return verify_github_actions_provenance(
        REPO, "500", "1", CANDIDATE_SHA, "mock-token", **kwargs
    )


def test_provenance_accepts_complete_successful_upload(monkeypatch):
    _mock_provenance(monkeypatch)
    prov, errors = _verify_provenance()
    assert errors == []
    assert prov is not None
    assert prov["artifact_id"] == ARTIFACT_ID
    assert prov["artifact_digest"] == ARTIFACT_DIGEST
    assert prov["workflow_run_attempt"] == "1"


def test_provenance_rejects_missing_upload_step(monkeypatch):
    jobs = _valid_jobs()
    jobs["jobs"][0]["steps"] = [
        s for s in jobs["jobs"][0]["steps"] if s["name"] != "Upload Release Measurements Artifact"
    ]
    _mock_provenance(monkeypatch, jobs=jobs)
    prov, errors = _verify_provenance()
    assert prov is None
    assert any("Upload Release Measurements Artifact" in e for e in errors)


def test_provenance_rejects_failed_upload_step(monkeypatch):
    jobs = _valid_jobs()
    for step in jobs["jobs"][0]["steps"]:
        if step["name"] == "Upload Release Measurements Artifact":
            step["conclusion"] = "failure"
    _mock_provenance(monkeypatch, jobs=jobs)
    prov, errors = _verify_provenance()
    assert prov is None
    assert any("Upload Release Measurements Artifact" in e for e in errors)


def test_provenance_rejects_wrong_artifact_id(monkeypatch):
    _mock_provenance(monkeypatch)
    prov, errors = _verify_provenance(expected_artifact_id=ARTIFACT_ID + 1)
    assert prov is None
    assert any("artifact" in e.lower() for e in errors)


def test_provenance_rejects_wrong_artifact_digest(monkeypatch):
    _mock_provenance(monkeypatch)
    prov, errors = _verify_provenance(expected_artifact_digest="sha256:" + "e" * 64)
    assert prov is None
    assert any("digest" in e.lower() for e in errors)


def test_provenance_rejects_missing_api_digest(monkeypatch):
    artifacts = _valid_artifacts()
    artifacts["artifacts"][0].pop("digest")
    _mock_provenance(monkeypatch, artifacts=artifacts)
    prov, errors = _verify_provenance()
    assert prov is None
    assert any("digest" in e.lower() for e in errors)


def test_provenance_rejects_duplicate_artifact_names(monkeypatch):
    artifacts = _valid_artifacts()
    duplicate = dict(artifacts["artifacts"][0])
    duplicate["id"] = ARTIFACT_ID + 2
    artifacts["artifacts"].append(duplicate)
    artifacts["total_count"] = 2
    _mock_provenance(monkeypatch, artifacts=artifacts)
    prov, errors = _verify_provenance()
    assert prov is None
    assert any("duplicate" in e.lower() or "exactly one" in e.lower() for e in errors)


def test_provenance_rejects_expired_artifact(monkeypatch):
    artifacts = _valid_artifacts()
    artifacts["artifacts"][0]["expired"] = True
    _mock_provenance(monkeypatch, artifacts=artifacts)
    prov, errors = _verify_provenance()
    assert prov is None
    assert any("expired" in e.lower() for e in errors)


def test_provenance_rejects_wrong_run_attempt(monkeypatch):
    run = _valid_run()
    run["run_attempt"] = 2
    _mock_provenance(monkeypatch, run=run)
    prov, errors = _verify_provenance()
    assert prov is None
    assert any("attempt" in e.lower() for e in errors)


def test_provenance_rejects_artifact_from_another_run_or_commit(monkeypatch):
    artifacts = _valid_artifacts()
    artifacts["artifacts"][0]["workflow_run"]["id"] = 999
    artifacts["artifacts"][0]["workflow_run"]["head_sha"] = "f" * 40
    _mock_provenance(monkeypatch, artifacts=artifacts)
    prov, errors = _verify_provenance()
    assert prov is None
    assert errors


def test_provenance_rejects_incomplete_job_listing(monkeypatch):
    jobs = _valid_jobs()
    jobs["total_count"] = 2
    _mock_provenance(monkeypatch, jobs=jobs)
    prov, errors = _verify_provenance()
    assert prov is None
    assert any("incomplete" in e.lower() or "total_count" in e.lower() for e in errors)


def test_provenance_rejects_api_error(monkeypatch):
    _mock_provenance(monkeypatch, api_error="/jobs")
    prov, errors = _verify_provenance()
    assert prov is None
    assert any("API error" in e for e in errors)


# ---------------------------------------------------------------------------
# Artifact archive validation
# ---------------------------------------------------------------------------
def _write_zip(path: Path, entries: list[tuple[str, bytes]]):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return path


def test_artifact_archive_accepts_exact_expected_files(tmp_path):
    from scripts.standalone_signer import load_measurement_artifact

    archive = _write_zip(
        tmp_path / "a.zip",
        [("measurements.json", b'{"a":1}'), ("measurement_attestation.json", b'{"b":2}')],
    )
    digest = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
    measurements, attestation, errors = load_measurement_artifact(archive, expected_sha256=digest)
    assert errors == []
    assert measurements == b'{"a":1}'
    assert attestation == b'{"b":2}'


def test_artifact_archive_rejects_digest_mismatch(tmp_path):
    from scripts.standalone_signer import load_measurement_artifact

    archive = _write_zip(
        tmp_path / "a.zip",
        [("measurements.json", b"{}"), ("measurement_attestation.json", b"{}")],
    )
    measurements, attestation, errors = load_measurement_artifact(
        archive, expected_sha256="sha256:" + "0" * 64
    )
    assert measurements is None
    assert attestation is None
    assert any("digest" in e.lower() for e in errors)


def test_artifact_archive_rejects_unexpected_file(tmp_path):
    from scripts.standalone_signer import load_measurement_artifact

    archive = _write_zip(
        tmp_path / "a.zip",
        [
            ("measurements.json", b"{}"),
            ("measurement_attestation.json", b"{}"),
            ("candidate_payload.py", b"print('pwn')"),
        ],
    )
    _, _, errors = load_measurement_artifact(archive)
    assert any("unexpected" in e.lower() or "exactly" in e.lower() for e in errors)


def test_artifact_archive_rejects_missing_file(tmp_path):
    from scripts.standalone_signer import load_measurement_artifact

    archive = _write_zip(tmp_path / "a.zip", [("measurements.json", b"{}")])
    _, _, errors = load_measurement_artifact(archive)
    assert errors


def test_artifact_archive_rejects_duplicate_entries(tmp_path):
    from scripts.standalone_signer import load_measurement_artifact

    archive = _write_zip(
        tmp_path / "a.zip",
        [
            ("measurements.json", b"{}"),
            ("measurements.json", b'{"duplicate":true}'),
            ("measurement_attestation.json", b"{}"),
        ],
    )
    _, _, errors = load_measurement_artifact(archive)
    assert any("duplicate" in e.lower() for e in errors)


def test_artifact_archive_rejects_empty_file(tmp_path):
    from scripts.standalone_signer import load_measurement_artifact

    archive = _write_zip(
        tmp_path / "a.zip",
        [("measurements.json", b""), ("measurement_attestation.json", b"{}")],
    )
    _, _, errors = load_measurement_artifact(archive)
    assert any("empty" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# Workflow topology (static; GitHub remains the authority)
# ---------------------------------------------------------------------------
def _load_workflow(name: str) -> dict:
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))


def test_ci_uses_trusted_measurement_workflow_by_full_sha_and_passes_no_secret():
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    uses = []
    for job in workflow.get("jobs", {}).values():
        if isinstance(job, dict) and "uses" in job:
            uses.append(job["uses"])
    trusted = [
        u
        for u in uses
        if str(u).startswith("NeutronZero/VerifyCI/.github/workflows/release_measurements.yml@")
    ]
    assert len(trusted) == 1, f"expected one trusted measurement workflow, got {uses}"
    suffix = trusted[0].rsplit("@", 1)[1]
    assert len(suffix) == 40 and all(c in "0123456789abcdef" for c in suffix)
    assert "VERIFYCI_RELEASE_SIGNING_KEY" not in text
    assert "./.github/workflows/release_signing.yml" not in text


def test_signing_workflow_is_protected_and_never_checks_out_candidate():
    workflow = _load_workflow("release_signing.yml")
    # workflow_call is the old candidate-invokable shape; the trusted entrypoint is dispatch-only.
    triggers = workflow.get("on", workflow.get(True))
    assert "workflow_dispatch" in triggers
    assert "workflow_call" not in triggers

    job = next(iter(workflow["jobs"].values()))
    assert job["environment"] == "release"
    text = json.dumps(workflow)
    assert "candidate_sha\" required" in text or "candidate_sha" in text
    for step in job["steps"]:
        if "uses" in step:
            ref = step["uses"]
            if not ref.startswith("./"):
                assert len(ref.rsplit("@", 1)[-1]) == 40, f"unpinned action: {ref}"
    step_text = json.dumps(job)
    assert "uv sync" not in step_text
    assert "pip install" in step_text or "setup-python" in step_text
    # The signing job may download an artifact and trusted signer source, but must
    # never check out the candidate commit in the secret-bearing job.
    assert '"ref": "${{ inputs.candidate_sha }}"' not in step_text


def test_measurement_workflow_has_no_secret_and_exact_upload_step():
    workflow = _load_workflow("release_measurements.yml")
    triggers = workflow.get("on", workflow.get(True))
    assert "workflow_call" in triggers
    assert '"environment": "release"' not in json.dumps(workflow)
    # The signing key must never be referenced as a secret value. Defensive
    # "must be empty" assertions in the unprivileged job are permitted.
    assert "${{ secrets.VERIFYCI_RELEASE_SIGNING_KEY }}" not in json.dumps(workflow)
    step_names = [
        step.get("name")
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
    ]
    assert "Upload Release Measurements Artifact" in step_names
    assert "Run Trusted Measurement Pipeline" in step_names


# ---------------------------------------------------------------------------
# Component B: Git Tree Materialization Tests
# ---------------------------------------------------------------------------
def test_tree_materializer_rejects_escaping_symlink(tmp_path):
    from verifyci_release_trust.tree_materializer import TreeEntry, validate_tree_paths

    bad_entry = TreeEntry(mode="120000", entry_type="blob", object_sha="0"*40, rel_path="../etc/passwd")
    with pytest.raises(ValueError, match="forbidden traversal"):
        validate_tree_paths([bad_entry])


def test_tree_materializer_rejects_git_components():
    from verifyci_release_trust.tree_materializer import TreeEntry, validate_tree_paths

    bad_entry = TreeEntry(mode="100644", entry_type="blob", object_sha="0"*40, rel_path=".git/config")
    with pytest.raises(ValueError, match="forbidden .git component"):
        validate_tree_paths([bad_entry])


def test_tree_materializer_rejects_submodule():
    from verifyci_release_trust.tree_materializer import TreeEntry, validate_tree_paths

    bad_entry = TreeEntry(mode="160000", entry_type="commit", object_sha="0"*40, rel_path="submodule")
    with pytest.raises(ValueError, match="submodule"):
        validate_tree_paths([bad_entry])


# ---------------------------------------------------------------------------
# Component D: Strict Hostile-Input IPC Tests
# ---------------------------------------------------------------------------
def test_ipc_rejects_duplicate_json_keys():
    from verifyci_release_trust.ipc import parse_strict_ipc_payload

    bad_json = b'{"outcome": "PASS", "coverage": "FULL", "outcome": "FAIL", "reason_codes": [], "findings": []}'
    res = parse_strict_ipc_payload(bad_json, 0)
    assert res.data is None
    assert res.outcome == "INCONCLUSIVE"
    assert "duplicate JSON key" in (res.error or "")


def test_ipc_rejects_nan_and_infinity():
    from verifyci_release_trust.ipc import parse_strict_ipc_payload

    bad_nan = b'{"outcome": "PASS", "coverage": "FULL", "val": NaN, "reason_codes": [], "findings": []}'
    res_nan = parse_strict_ipc_payload(bad_nan, 0)
    assert res_nan.data is None
    assert "constant" in (res_nan.error or "").lower() or "malformed" in (res_nan.error or "").lower()

    bad_inf = b'{"outcome": "PASS", "coverage": "FULL", "val": Infinity, "reason_codes": [], "findings": []}'
    res_inf = parse_strict_ipc_payload(bad_inf, 0)
    assert res_inf.data is None


def test_ipc_rejects_invalid_utf8():
    from verifyci_release_trust.ipc import parse_strict_ipc_payload

    bad_bytes = b'{"outcome": "PASS\xff\xfe", "coverage": "FULL", "reason_codes": [], "findings": []}'
    res = parse_strict_ipc_payload(bad_bytes, 0)
    assert res.data is None
    assert "invalid utf-8" in (res.error or "").lower()


def test_ipc_rejects_deep_nesting():
    from verifyci_release_trust.ipc import parse_strict_ipc_payload

    nested = '{"a": ' * 12 + '{"outcome": "PASS", "coverage": "FULL", "reason_codes": [], "findings": []}' + '}' * 12
    res = parse_strict_ipc_payload(nested.encode("utf-8"), 0)
    assert res.data is None
    assert "nesting depth" in (res.error or "").lower()


def test_ipc_enforces_exit_code_consistency():
    from verifyci_release_trust.ipc import parse_strict_ipc_payload

    # PASS outcome with exit code 1 MUST be rejected
    pass_payload = b'{"outcome": "PASS", "coverage": "FULL", "reason_codes": [], "findings": []}'
    res_inconsistent = parse_strict_ipc_payload(pass_payload, 1)
    assert res_inconsistent.data is None
    assert "inconsistent" in (res_inconsistent.error or "").lower()

    # PASS outcome with exit code 0 is accepted
    res_consistent = parse_strict_ipc_payload(pass_payload, 0)
    assert res_consistent.data is not None
    assert res_consistent.outcome == "PASS"

    # FAIL outcome with exit code 1 is accepted
    fail_payload = b'{"outcome": "FAIL", "coverage": "FULL", "reason_codes": ["defect_found"], "findings": [{"defect_id": "SEC-SECRET"}]}'
    res_fail = parse_strict_ipc_payload(fail_payload, 1)
    assert res_fail.data is not None
    assert res_fail.outcome == "FAIL"


def test_ipc_rejects_trailing_multiple_objects():
    from verifyci_release_trust.ipc import parse_strict_ipc_payload

    multi = b'{"outcome": "PASS", "coverage": "FULL", "reason_codes": [], "findings": []} {"extra": true}'
    res = parse_strict_ipc_payload(multi, 0)
    assert res.data is None
    assert "trailing data" in (res.error or "").lower()


# ---------------------------------------------------------------------------
# Component C: Bounded Stream Reader Tests
# ---------------------------------------------------------------------------
def test_stream_drainer_accepts_exact_limit():
    import io
    from verifyci_release_trust.sandbox import StreamDrainer

    exact_bytes = b"x" * 1024
    stream = io.BytesIO(exact_bytes)
    drainer = StreamDrainer(stream, limit=1024)
    drainer.run()

    assert bytes(drainer.retained) == exact_bytes
    assert drainer.total_received == 1024
    assert drainer.overflow is False


def test_stream_drainer_flags_overflow_on_excess():
    import io
    from verifyci_release_trust.sandbox import StreamDrainer

    excess_bytes = b"x" * 1025
    stream = io.BytesIO(excess_bytes)
    drainer = StreamDrainer(stream, limit=1024)
    drainer.run()

    assert len(drainer.retained) == 1024
    assert drainer.total_received == 1025
    assert drainer.overflow is True


# ---------------------------------------------------------------------------
# Component E: Benchmark Oracle & Held-Out Tests
# ---------------------------------------------------------------------------
def test_authoritative_public_corpus_integrity():
    from verifyci_release_trust.evaluator import load_authoritative_public_cases

    cases = load_authoritative_public_cases(ROOT)
    assert len(cases) == 22


def test_grade_case_result_detects_false_blocking():
    from verifyci_release_trust.evaluator import grade_case_result

    control_case = {
        "case_id": "test_control",
        "expected": {"outcome": "PASS", "coverage": "FULL", "reason_codes": [], "findings": []},
    }
    candidate_blocked = {
        "outcome": "FAIL",
        "coverage": "FULL",
        "reason_codes": ["defect"],
        "findings": [{"defect_id": "SEC-SECRET"}],
    }
    ok, errors, metrics = grade_case_result(control_case, candidate_blocked)
    assert not ok
    assert any("false blocking" in e.lower() for e in errors)


def test_held_out_scenarios_deterministic_from_seed():
    from verifyci_release_trust.evaluator import generate_held_out_scenarios, load_authoritative_public_cases

    base_cases = load_authoritative_public_cases(ROOT)
    seed = "0123456789abcdef" * 4
    scenarios1, commit1, epoch1 = generate_held_out_scenarios(seed, base_cases, count=5)
    scenarios2, commit2, epoch2 = generate_held_out_scenarios(seed, base_cases, count=5)

    assert commit1 == commit2
    assert epoch1 == epoch2
    assert len(scenarios1) == 5
    assert scenarios1[0]["case_id"] == scenarios2[0]["case_id"]


# ---------------------------------------------------------------------------
# Component S & Evidence: Canonical JCS and Ed25519 Signing Envelope
# ---------------------------------------------------------------------------
def test_canonical_jcs_deterministic_ordering():
    from verifyci_release_trust.evidence import canonical_jcs_bytes

    d1 = {"z": 1, "a": 2, "m": {"y": 10, "b": 20}}
    d2 = {"a": 2, "m": {"b": 20, "y": 10}, "z": 1}
    assert canonical_jcs_bytes(d1) == canonical_jcs_bytes(d2)


def test_ed25519_envelope_signing_and_verification():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from verifyci_release_trust.signer import sign_release_payload, verify_release_envelope

    priv = ed25519.Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes_raw().hex()
    pub_hex = priv.public_key().public_bytes_raw().hex()

    payload = {"status": "VALIDATED", "candidate_sha": "f" * 40}
    envelope = sign_release_payload(payload, private_key_hex=priv_hex, key_id="test-key-v1")

    ok, err = verify_release_envelope(envelope, expected_public_key_hex=pub_hex, expected_key_id="test-key-v1")
    assert ok, f"verification failed: {err}"

    # Tampered payload must fail
    envelope["payload"]["status"] = "INVALID"
    tampered_ok, tampered_err = verify_release_envelope(envelope, expected_public_key_hex=pub_hex, expected_key_id="test-key-v1")
    assert not tampered_ok


# ---------------------------------------------------------------------------
# Component 6: Dual-Workflow OIDC Verification Tests
# ---------------------------------------------------------------------------
def test_oidc_dual_workflow_verification():
    from verifyci_release_trust.attestations import parse_and_verify_oidc_token

    priv, jwks = _generate_jwks()
    now = int(time.time())
    reusable_sha = "1" * 40
    caller_sha = "2" * 40
    cand_sha = "3" * 40

    claims = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "verifyci-release-authority",
        "repository": "NeutronZero/VerifyCI",
        "repository_id": "1392600740",
        "sha": cand_sha,
        "run_id": "999",
        "run_attempt": "1",
        "check_run_id": "88888",
        "job_workflow_sha": reusable_sha,
        "job_workflow_ref": f"NeutronZero/VerifyCI/.github/workflows/release_measurements.yml@{reusable_sha}",
        "workflow_sha": caller_sha,
        "workflow_ref": f"NeutronZero/VerifyCI/.github/workflows/ci.yml@{caller_sha}",
        "jti": "jwt-uuid-1",
        "iat": now - 120,
        "nbf": now - 120,
        "exp": now - 30,  # Expired token (historical evidence)
    }
    raw_jwt = _sign_jwt(priv, claims)

    res, errors = parse_and_verify_oidc_token(
        raw_jwt,
        jwks=jwks,
        expected_repo="NeutronZero/VerifyCI",
        expected_repo_id="1392600740",
        expected_candidate_sha=cand_sha,
        expected_reusable_workflow_sha=reusable_sha,
        expected_caller_workflow_sha=caller_sha,
        expected_run_id="999",
        expected_run_attempt="1",
        expected_check_run_id="88888",
        job_started_at=now - 200,
        job_completed_at=now - 50,
        artifact_created_at=now + 50,  # created >= exp + 60s
    )
    assert errors == []
    assert res is not None
    assert res.jti == "jwt-uuid-1"
    assert res.check_run_id == "88888"


def test_oidc_rejects_mismatched_caller_workflow_sha():
    from verifyci_release_trust.attestations import parse_and_verify_oidc_token

    priv, jwks = _generate_jwks()
    now = int(time.time())
    claims = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "verifyci-release-authority",
        "repository": "NeutronZero/VerifyCI",
        "repository_id": "1392600740",
        "sha": "a" * 40,
        "run_id": "999",
        "run_attempt": "1",
        "check_run_id": "88888",
        "job_workflow_sha": "b" * 40,
        "job_workflow_ref": f"NeutronZero/VerifyCI/.github/workflows/release_measurements.yml@{'b'*40}",
        "workflow_sha": "wrong_caller_sha" + "0" * 24,
        "workflow_ref": "NeutronZero/VerifyCI/.github/workflows/ci.yml@main",
        "jti": "jwt-uuid-2",
        "iat": now - 120,
        "nbf": now - 120,
        "exp": now - 30,
    }
    raw_jwt = _sign_jwt(priv, claims)
    res, errors = parse_and_verify_oidc_token(
        raw_jwt,
        jwks=jwks,
        expected_repo="NeutronZero/VerifyCI",
        expected_repo_id="1392600740",
        expected_candidate_sha="a" * 40,
        expected_reusable_workflow_sha="b" * 40,
        expected_caller_workflow_sha="expected_caller_sha" + "0" * 21,
        expected_run_id="999",
        expected_run_attempt="1",
        expected_check_run_id="88888",
    )
    assert res is None
    assert any("caller workflow_sha mismatch" in e for e in errors)


def test_measurement_workflow_has_precondition_gate():
    """Verify release_measurements.yml enforces precondition gate on release-authority."""
    import yaml
    wf_path = ROOT / ".github" / "workflows" / "release_measurements.yml"
    assert wf_path.is_file()
    content = wf_path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)
    meas_job = data.get("jobs", {}).get("verifyci-measurements", {})
    job_if = meas_job.get("if", "")
    assert "github.repository == 'NeutronZero/VerifyCI'" in job_if
    assert "github.ref == 'refs/heads/release-authority'" in job_if


def test_measurement_job_has_no_id_token_write():
    """Verify verifyci-measurements job does NOT grant id-token: write permissions."""
    import yaml
    wf_path = ROOT / ".github" / "workflows" / "release_measurements.yml"
    data = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
    meas_job = data.get("jobs", {}).get("verifyci-measurements", {})
    perms = meas_job.get("permissions", {})
    assert perms.get("id-token") != "write"
    assert "id-token" not in perms or perms["id-token"] != "write"


def test_trusted_attestation_job_has_no_candidate_checkout():
    """Verify trusted-attestation job checks out ONLY trusted-authority and not candidate-src."""
    import yaml
    wf_path = ROOT / ".github" / "workflows" / "release_measurements.yml"
    data = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
    att_job = data.get("jobs", {}).get("trusted-attestation", {})
    for step in att_job.get("steps", []):
        with_block = step.get("with", {})
        ref = with_block.get("ref", "")
        assert "inputs.candidate_sha" not in str(ref)


def test_evidence_bundle_preserves_6_digests_and_3_fingerprints():
    """Verify verifyci_release_trust.evidence produces all 6 digests and 3 fingerprints."""
    from verifyci_release_trust.evidence import build_evidence_bundle

    candidate_tree = {
        "candidate_root_git_tree_oid": "1" * 40,
        "candidate_tree_manifest_sha256": "sha256:" + "2" * 64,
        "candidate_source_archive_sha256": "sha256:" + "3" * 64,
    }
    worker_image = {
        "worker_image_digest": "sha256:" + "4" * 64,
        "worker_image_provenance_sha256": "sha256:" + "5" * 64,
    }
    raw_measurements = b'{"status":"PASS"}'
    raw_attestation = b'{"attestation":"OK"}'
    raw_validation = b'{"schema":"v3"}'

    bundle = build_evidence_bundle(
        candidate_tree=candidate_tree,
        worker_image=worker_image,
        raw_measurements=raw_measurements,
        raw_attestation=raw_attestation,
        raw_validation=raw_validation,
        candidate_impl_fingerprint="sha256:" + "a" * 64,
        trusted_harness_fingerprint="sha256:" + "b" * 64,
        trusted_supervisor_fingerprint="sha256:" + "c" * 64,
    )
    digests = bundle["digests"]
    assert "candidate_tree_manifest_sha256" in digests
    assert "candidate_source_archive_sha256" in digests
    assert "worker_image_digest" in digests
    assert "measurements_raw_sha256" in digests
    assert "attestation_raw_sha256" in digests
    assert "release_validation_raw_sha256" in digests
    assert len(digests) == 6

    fps = bundle["fingerprints"]
    assert "candidate_implementation_fingerprint" in fps
    assert "trusted_harness_fingerprint" in fps
    assert "trusted_supervisor_fingerprint" in fps
    assert len(fps) == 3


def test_attestation_timing_window_enforces_delay():
    """Verify verify_attestation_timing_window passes when publication is >= exp + 60s."""
    from verifyci_release_trust.attestations import verify_attestation_timing_window
    import datetime

    exp = 1_700_000_000
    # Published 65 seconds after expiration
    pub_dt = datetime.datetime.fromtimestamp(exp + 65, tz=datetime.timezone.utc)
    pub_iso = pub_dt.isoformat()
    ok, errors = verify_attestation_timing_window(pub_iso, exp, min_delay_seconds=60)
    assert ok is True
    assert errors == []


def test_attestation_timing_window_rejects_premature_publication():
    """Verify verify_attestation_timing_window rejects when publication is < exp + 60s."""
    from verifyci_release_trust.attestations import verify_attestation_timing_window
    import datetime

    exp = 1_700_000_000
    # Published only 20 seconds after expiration
    pub_dt = datetime.datetime.fromtimestamp(exp + 20, tz=datetime.timezone.utc)
    pub_iso = pub_dt.isoformat()
    ok, errors = verify_attestation_timing_window(pub_iso, exp, min_delay_seconds=60)
    assert ok is False
    assert any("published before mandatory delay" in e for e in errors)


def test_tree_materializer_rejects_path_traversal():
    """Verify TreeMaterializer rejects blob paths with parent traversal or absolute roots."""
    from verifyci_release_trust.tree_materializer import TreeMaterializer

    dest = ROOT / "evidence" / "temp_trav_test"
    dest.mkdir(parents=True, exist_ok=True)
    try:
        mat = TreeMaterializer(dest)
        with pytest.raises(ValueError, match="escaping destination"):
            mat._sanitize_and_validate_path("../outside.py")
        with pytest.raises(ValueError, match="escaping destination"):
            mat._sanitize_and_validate_path("/absolute/path.py")
    finally:
        import shutil
        shutil.rmtree(dest, ignore_errors=True)


def test_evidence_record_excludes_raw_oidc_jwt():
    """Verify evidence generation excludes raw OIDC JWT and includes only jti and digest."""
    from verifyci_release_trust.evidence import create_signed_evidence_payload

    raw_jwt = "header.payload.signature_canary_secret_12345"
    payload = create_signed_evidence_payload(
        commit_sha="a" * 40,
        manifest_hash="sha256:" + "b" * 64,
        candidate_fp="sha256:" + "c" * 64,
        harness_fp="sha256:" + "d" * 64,
        supervisor_fp="sha256:" + "e" * 64,
        measurements={},
        provenance={"ci_verified": True},
        oidc_jti="jwt-uuid-canonical",
        raw_oidc_jwt=raw_jwt,
    )
    payload_str = json.dumps(payload)
    assert raw_jwt not in payload_str
    assert payload["oidc_binding"]["jti"] == "jwt-uuid-canonical"
    assert "jwt_sha256" in payload["oidc_binding"]



def test_worker_ipc_accepts_canonical_coverage_and_not_applicable() -> None:
    from verifyci_release_trust.ipc import parse_strict_ipc_payload

    not_applicable = {
        "outcome": "NOT_APPLICABLE",
        "coverage": "COMPLETE",
        "reason_codes": [],
        "findings": [],
    }
    parsed = parse_strict_ipc_payload(json.dumps(not_applicable).encode("utf-8"), 4)
    assert parsed.error is None
    assert parsed.outcome == "NOT_APPLICABLE"
    assert parsed.data is not None

    passing = {
        "outcome": "PASS",
        "coverage": "COMPLETE",
        "reason_codes": [],
        "findings": [],
    }
    parsed_pass = parse_strict_ipc_payload(json.dumps(passing).encode("utf-8"), 0)
    assert parsed_pass.error is None
    assert parsed_pass.data is not None

    # Legacy worker spellings remain readable.
    legacy = {
        "outcome": "PASS",
        "coverage": "FULL",
        "reason_codes": [],
        "findings": [],
    }
    assert parse_strict_ipc_payload(json.dumps(legacy).encode("utf-8"), 0).error is None


def test_worker_ipc_rejects_exit_code_outcome_mismatch() -> None:
    from verifyci_release_trust.ipc import parse_strict_ipc_payload

    payload = {
        "outcome": "NOT_APPLICABLE",
        "coverage": "COMPLETE",
        "reason_codes": [],
        "findings": [],
    }
    parsed = parse_strict_ipc_payload(json.dumps(payload).encode("utf-8"), 3)
    assert parsed.error is not None
    assert parsed.outcome == "INCONCLUSIVE"
