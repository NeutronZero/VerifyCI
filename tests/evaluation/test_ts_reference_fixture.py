from __future__ import annotations

import hashlib
import json
from pathlib import Path

EXPECTED_FIXTURE_SHA256 = "fc2cb1c8637fd04a864aa4d3622352585608349c3533ed7bafbddf9bb214975a"

FIXTURE_PATH = Path("tests/fixtures/ts_reference_set_v1.json")
SRC_DIR = Path("tests/fixtures/ts_reference_src")


def test_ts_reference_fixture_sha256_immutability():
    """Fixture bytes must match the hardcoded SHA-256 constant exactly."""
    assert FIXTURE_PATH.is_file(), f"Fixture file not found: {FIXTURE_PATH}"
    data = FIXTURE_PATH.read_bytes().replace(b"\r\n", b"\n")
    actual_hash = hashlib.sha256(data).hexdigest()
    assert (
        actual_hash == EXPECTED_FIXTURE_SHA256
    ), f"Fixture SHA-256 mismatch: expected {EXPECTED_FIXTURE_SHA256}, got {actual_hash}"


def test_ts_reference_fixture_schema_and_integrity():
    """Verify fixture schema, 20 TS / 5 JS ratio, and file existence."""
    content = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

    assert "_doc" in content and isinstance(content["_doc"], str)
    assert content.get("version") == 1
    assert "call_sites" in content
    sites = content["call_sites"]
    assert len(sites) == 25

    ts_count = sum(1 for s in sites if s.get("language") == "typescript")
    js_count = sum(1 for s in sites if s.get("language") == "javascript")
    assert ts_count == 20, f"Expected 20 TypeScript sites, got {ts_count}"
    assert js_count == 5, f"Expected 5 JavaScript sites, got {js_count}"

    for i, s in enumerate(sites):
        caller_file = s.get("caller_file")
        caller_line = s.get("caller_line")
        callee_sym = s.get("expected_callee_symbol")
        callee_file = s.get("expected_callee_file")
        lang = s.get("language")

        assert caller_file, f"site[{i}] missing caller_file"
        assert isinstance(caller_line, int) and caller_line > 0, f"site[{i}] invalid caller_line"
        assert callee_sym, f"site[{i}] missing expected_callee_symbol"
        assert callee_file, f"site[{i}] missing expected_callee_file"
        assert lang in ("typescript", "javascript"), f"site[{i}] invalid language {lang}"

        # Prefixed path verification
        assert (
            caller_file.startswith("swr/") or caller_file.startswith("got/")
        ), f"site[{i}] caller_file must be prefixed with swr/ or got/: {caller_file}"
        assert (
            callee_file.startswith("swr/") or callee_file.startswith("got/")
        ), f"site[{i}] expected_callee_file must be prefixed with swr/ or got/: {callee_file}"

        # Existence in vendored sources
        caller_path = SRC_DIR / caller_file
        callee_path = SRC_DIR / callee_file
        assert caller_path.is_file(), f"Vendored caller file missing: {caller_path}"
        assert callee_path.is_file(), f"Vendored callee file missing: {callee_path}"


def test_ts_reference_third_party_licenses():
    license_file = SRC_DIR / "THIRD_PARTY_LICENSES.md"
    assert license_file.is_file(), "THIRD_PARTY_LICENSES.md missing"
    text = license_file.read_text(encoding="utf-8")
    assert "vercel/swr" in text
    assert "sindresorhus/got" in text
    assert "MIT License" in text
