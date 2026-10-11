"""Tests for runtime model attestation and cross-encoder attestation enforcement.

Validates fail-closed behavior for model directory resolution, composite SHA-256
hashing, snapshot commit checking, and reranker fallback.
"""
from __future__ import annotations

import hashlib
import sys
import types
from pathlib import Path

from verifyci.retrieval.dense import SearchResult
from verifyci.retrieval.model_attestation import verify_runtime_model
from verifyci.retrieval.reranker import CrossEncoderReranker


def _create_mock_model_dir(base_path: Path, commit_name: str = "mock-commit-789") -> tuple[Path, str, dict[str, str]]:
    model_dir = base_path / commit_name
    model_dir.mkdir(parents=True, exist_ok=True)

    files_content = {
        "config.json": b'{"architectures": ["BertForSequenceClassification"], "num_labels": 1}',
        "model.safetensors": b"\x00\x01\x02\x03\x04mock_weights_binary_data",
        "tokenizer.json": b'{"version": "1.0", "truncation": null}',
    }

    per_file_hashes: dict[str, str] = {}
    h = hashlib.sha256()

    for name in sorted(files_content.keys()):
        p = model_dir / name
        p.write_bytes(files_content[name])
        per_file_hashes[name] = hashlib.sha256(files_content[name]).hexdigest()
        h.update(name.encode("utf-8") + b"\x00" + files_content[name])

    composite_sha256 = h.hexdigest()
    return model_dir, composite_sha256, per_file_hashes


def test_verify_mock_directory_known_files_and_sha256(tmp_path: Path):
    commit = "test-commit-abc123"
    model_dir, expected_sha, expected_files = _create_mock_model_dir(tmp_path, commit)

    ok, details = verify_runtime_model(
        str(model_dir),
        expected_snapshot_commit=commit,
        expected_snapshot_sha256=expected_sha,
    )

    assert ok is True
    assert details["verified"] is True
    assert details["snapshot_commit"] == commit
    assert details["snapshot_sha256"] == expected_sha
    assert details["files"] == expected_files
    assert details["snapshot_path"] == str(model_dir.resolve())
    assert details["expected_snapshot_commit"] == commit
    assert details["expected_snapshot_sha256"] == expected_sha
    assert "error" not in details


def test_verify_mock_directory_without_optional_expectations(tmp_path: Path):
    commit = "unconstrained-commit"
    model_dir, expected_sha, expected_files = _create_mock_model_dir(tmp_path, commit)

    ok, details = verify_runtime_model(str(model_dir))

    assert ok is True
    assert details["verified"] is True
    assert details["snapshot_commit"] == commit
    assert details["snapshot_sha256"] == expected_sha
    assert details["files"] == expected_files


def test_missing_directory_fails_closed(tmp_path: Path):
    missing_path = tmp_path / "nonexistent_model_dir"

    ok, details = verify_runtime_model(str(missing_path))

    assert ok is False
    assert details["verified"] is False
    assert "error" in details
    assert "Failed to resolve" in details["error"] or "could not be resolved" in details["error"]


def test_path_is_file_not_directory_fails_closed(tmp_path: Path):
    file_path = tmp_path / "regular_file.txt"
    file_path.write_text("not a directory", encoding="utf-8")

    ok, details = verify_runtime_model(str(file_path))

    assert ok is False
    assert details["verified"] is False
    assert "is not a directory" in details["error"]


def test_empty_directory_fails_closed(tmp_path: Path):
    empty_dir = tmp_path / "empty_model"
    empty_dir.mkdir()

    ok, details = verify_runtime_model(str(empty_dir))

    assert ok is False
    assert details["verified"] is False
    assert "contains no files" in details["error"]


def test_tampered_file_fails_closed(tmp_path: Path):
    commit = "commit-before-tampering"
    model_dir, original_sha, _ = _create_mock_model_dir(tmp_path, commit)

    # Tamper with model.safetensors
    (model_dir / "model.safetensors").write_bytes(b"tampered_bytes_malicious")

    ok, details = verify_runtime_model(
        str(model_dir),
        expected_snapshot_commit=commit,
        expected_snapshot_sha256=original_sha,
    )

    assert ok is False
    assert details["verified"] is False
    assert details["snapshot_sha256"] != original_sha
    assert "Snapshot SHA-256 mismatch" in details["error"]


def test_mismatched_snapshot_commit_fails_closed(tmp_path: Path):
    actual_commit = "actual-commit-111"
    model_dir, expected_sha, _ = _create_mock_model_dir(tmp_path, actual_commit)

    ok, details = verify_runtime_model(
        str(model_dir),
        expected_snapshot_commit="expected-different-commit-222",
        expected_snapshot_sha256=expected_sha,
    )

    assert ok is False
    assert details["verified"] is False
    assert "Snapshot commit mismatch" in details["error"]


def test_mismatched_snapshot_sha256_fails_closed(tmp_path: Path):
    commit = "commit-hash-333"
    model_dir, _, _ = _create_mock_model_dir(tmp_path, commit)

    bogus_sha = "0000000000000000000000000000000000000000000000000000000000000000"
    ok, details = verify_runtime_model(
        str(model_dir),
        expected_snapshot_commit=commit,
        expected_snapshot_sha256=bogus_sha,
    )

    assert ok is False
    assert details["verified"] is False
    assert "Snapshot SHA-256 mismatch" in details["error"]


def test_huggingface_hub_resolution_mocked(monkeypatch, tmp_path: Path):
    commit = "hf-snapshot-commit"
    model_dir, expected_sha, _ = _create_mock_model_dir(tmp_path, commit)

    # Mock huggingface_hub module
    mock_hf = types.ModuleType("huggingface_hub")

    def mock_snapshot_download(repo_id: str, local_files_only: bool = True):
        assert local_files_only is True
        if repo_id == "mock-org/test-model":
            return str(model_dir)
        raise RuntimeError(f"Unknown repo {repo_id}")

    mock_hf.snapshot_download = mock_snapshot_download
    monkeypatch.setitem(sys.modules, "huggingface_hub", mock_hf)

    ok, details = verify_runtime_model(
        "mock-org/test-model",
        expected_snapshot_commit=commit,
        expected_snapshot_sha256=expected_sha,
    )
    assert ok is True
    assert details["verified"] is True
    assert details["snapshot_commit"] == commit
    assert details["snapshot_sha256"] == expected_sha

    # Test HF lookup failure fails closed
    fail_ok, fail_details = verify_runtime_model("mock-org/unknown-model")
    assert fail_ok is False
    assert fail_details["verified"] is False
    assert "Failed to resolve local model snapshot" in fail_details["error"]


def test_cross_encoder_reranker_with_valid_attestation(monkeypatch, tmp_path: Path):
    commit = "valid-commit-999"
    model_dir, expected_sha, _ = _create_mock_model_dir(tmp_path, commit)

    class MockCrossEncoder:
        def __init__(self, model: str, local_files_only: bool = True):
            self.model = model
            self.local_files_only = local_files_only

        def predict(self, pairs: list[tuple[str, str]]):
            # Deterministic mock score
            return [0.95 for _ in pairs]

    mock_st = types.ModuleType("sentence_transformers")
    mock_st.CrossEncoder = MockCrossEncoder
    monkeypatch.setitem(sys.modules, "sentence_transformers", mock_st)

    reranker = CrossEncoderReranker(
        model=str(model_dir),
        expected_snapshot_commit=commit,
        expected_snapshot_sha256=expected_sha,
        enforce_attestation=True,
    )

    assert reranker.backend == "cross_encoder"
    assert reranker.model_attestation is not None
    assert reranker.model_attestation["verified"] is True
    assert reranker.model_attestation["snapshot_commit"] == commit
    assert reranker.model_attestation["snapshot_sha256"] == expected_sha

    results = [
        SearchResult(id="doc_1", score=0.1, metadata={"text": "document text content"}),
    ]
    reranked = reranker.rerank("query", results)
    assert len(reranked) == 1
    assert reranked[0].id == "doc_1"
    assert reranked[0].score == 0.95


def test_cross_encoder_reranker_enforced_invalid_attestation_falls_back_to_offline(
    monkeypatch, tmp_path: Path
):
    commit = "actual-commit-555"
    model_dir, expected_sha, _ = _create_mock_model_dir(tmp_path, commit)

    # Even if sentence_transformers is available, attestation failure must block loading
    loaded_cross_encoder = False

    class SpyCrossEncoder:
        def __init__(self, *args, **kwargs):
            nonlocal loaded_cross_encoder
            loaded_cross_encoder = True

    mock_st = types.ModuleType("sentence_transformers")
    mock_st.CrossEncoder = SpyCrossEncoder
    monkeypatch.setitem(sys.modules, "sentence_transformers", mock_st)

    reranker = CrossEncoderReranker(
        model=str(model_dir),
        expected_snapshot_commit="wrong-commit",
        expected_snapshot_sha256=expected_sha,
        enforce_attestation=True,
    )

    assert loaded_cross_encoder is False
    assert reranker.backend == "offline"
    assert reranker.model_attestation is not None
    assert reranker.model_attestation["verified"] is False
    assert "Snapshot commit mismatch" in reranker.model_attestation["error"]

    # Reranking works offline
    results = [
        SearchResult(id="auth", score=0.1, metadata={"text": "auth login handler"}),
        SearchResult(id="db", score=0.9, metadata={"text": "database sql query"}),
    ]
    reranked = reranker.rerank("auth login", results)
    assert reranked[0].id == "auth"


def test_cross_encoder_reranker_unenforced_attestation_records_failure_and_attempts_load(
    monkeypatch, tmp_path: Path
):
    commit = "commit-777"
    model_dir, expected_sha, _ = _create_mock_model_dir(tmp_path, commit)

    loaded_cross_encoder = False

    class MockCrossEncoder:
        def __init__(self, *args, **kwargs):
            nonlocal loaded_cross_encoder
            loaded_cross_encoder = True

        def predict(self, pairs):
            return [0.77 for _ in pairs]

    mock_st = types.ModuleType("sentence_transformers")
    mock_st.CrossEncoder = MockCrossEncoder
    monkeypatch.setitem(sys.modules, "sentence_transformers", mock_st)

    reranker = CrossEncoderReranker(
        model=str(model_dir),
        expected_snapshot_commit="wrong-commit-sha",
        expected_snapshot_sha256=expected_sha,
        enforce_attestation=False,
    )

    assert loaded_cross_encoder is True
    assert reranker.backend == "cross_encoder"
    assert reranker.model_attestation is not None
    assert reranker.model_attestation["verified"] is False
    assert "Snapshot commit mismatch" in reranker.model_attestation["error"]


def test_cross_encoder_reranker_default_init_is_offline():
    reranker = CrossEncoderReranker()
    assert reranker.backend == "offline"
    assert reranker.model_attestation is None


def test_enforced_attestation_without_pin_fails_closed(monkeypatch, tmp_path: Path):
    """Enforce attestation without expected_snapshot_sha256 pin must fail closed and remain offline."""
    commit = "unpinned-commit"
    model_dir, _, _ = _create_mock_model_dir(tmp_path, commit)

    loaded_cross_encoder = False

    class SpyCrossEncoder:
        def __init__(self, *args, **kwargs):
            nonlocal loaded_cross_encoder
            loaded_cross_encoder = True

    mock_st = types.ModuleType("sentence_transformers")
    mock_st.CrossEncoder = SpyCrossEncoder
    monkeypatch.setitem(sys.modules, "sentence_transformers", mock_st)

    # 1. verify_runtime_model with require_pin=True fails without expected_snapshot_sha256
    ok, details = verify_runtime_model(str(model_dir), require_pin=True)
    assert ok is False
    assert details["verified"] is False
    assert "requires a trusted expected_snapshot_sha256 pin" in details["error"]

    # 2. CrossEncoderReranker with enforce_attestation=True and no expected_snapshot_sha256 cannot select cross_encoder
    reranker = CrossEncoderReranker(
        model=str(model_dir),
        enforce_attestation=True,
        expected_snapshot_sha256=None,
    )
    assert loaded_cross_encoder is False
    assert reranker.backend == "offline"
    assert reranker.model_attestation is not None
    assert reranker.model_attestation["verified"] is False
    assert "Enforced attestation requires expected_snapshot_sha256 pin" in reranker.model_attestation["error"]


def test_verified_snapshot_path_is_passed_to_loader(monkeypatch, tmp_path: Path):
    """Confirm the verified snapshot path (not the model identifier) is explicitly passed to CrossEncoder."""
    commit = "verified-commit-999"
    model_dir, expected_sha, _ = _create_mock_model_dir(tmp_path, commit)

    passed_model_arg = None
    passed_local_files_only = None

    class CaptureCrossEncoder:
        def __init__(self, model_name, local_files_only=False):
            nonlocal passed_model_arg, passed_local_files_only
            passed_model_arg = model_name
            passed_local_files_only = local_files_only

        def predict(self, pairs):
            return [0.88 for _ in pairs]

    mock_st = types.ModuleType("sentence_transformers")
    mock_st.CrossEncoder = CaptureCrossEncoder
    monkeypatch.setitem(sys.modules, "sentence_transformers", mock_st)

    # Mock snapshot_download to return our mock model directory
    mock_hf = types.ModuleType("huggingface_hub")
    mock_hf.snapshot_download = lambda model_id, local_files_only=True: str(model_dir)
    monkeypatch.setitem(sys.modules, "huggingface_hub", mock_hf)

    model_identifier = "some-org/some-model-id"
    reranker = CrossEncoderReranker(
        model=model_identifier,
        expected_snapshot_commit=commit,
        expected_snapshot_sha256=expected_sha,
        enforce_attestation=True,
    )

    assert reranker.backend == "cross_encoder"
    # Crucial assertion: passed_model_arg MUST be the verified local snapshot directory, NOT the model identifier!
    assert passed_model_arg == str(model_dir.resolve())
    assert passed_model_arg != model_identifier
    assert passed_local_files_only is True
    assert reranker.loaded_snapshot_path == str(model_dir.resolve())
