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
    assert "environment" not in json.dumps(workflow)
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
