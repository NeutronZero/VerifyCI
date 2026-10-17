"""Adversarial boundary and security invariant verification tests."""

from __future__ import annotations

import pytest

from verifyci.contracts.attestation import is_path_traversal
from verifyci.contracts.verdict import (
    FindingReason,
    Severity,
    VerificationFinding,
    VerificationVerdict,
)
from verifyci.core.diff_parser import DiffFileEntry, parse_unified_diff
from verifyci.core.engine import VerificationKernel
from verifyci.core.security import scan_dangerous_calls
from verifyci.extensions.wasm_sandbox import (
    WasmFuelExhaustedError,
    WasmSandboxCapabilityError,
    WasmtimeSandboxAdapter,
)


# =========================================================================
# 1. Path Traversal & Escaping Repository Root
# =========================================================================

def test_is_path_traversal_detection() -> None:
    # Direct traversal
    assert is_path_traversal("../../etc/shadow")
    assert is_path_traversal("../secret.py")
    assert is_path_traversal("foo/../../escaped.py")
    assert is_path_traversal("a/b/c/../../../../root.py")

    # Absolute paths
    assert is_path_traversal("/etc/passwd")
    assert is_path_traversal("\\Windows\\System32\\cmd.exe")
    assert is_path_traversal("C:\\Windows\\System32")
    assert is_path_traversal("D:/data/secret")

    # URL-encoded traversal
    assert is_path_traversal("%2e%2e/etc/passwd")
    assert is_path_traversal("foo/%2f/bar")

    # Null bytes & empty
    assert is_path_traversal("foo\x00bar.py")
    assert is_path_traversal("")

    # Valid in-repo paths
    assert not is_path_traversal("src/core/engine.py")
    assert not is_path_traversal("tests/test_basic.py")
    assert not is_path_traversal("./src/utils.py")
    assert not is_path_traversal("a/b/../b/c.py")


def test_kernel_blocks_path_traversal_diff() -> None:
    diff_text = """diff --git a/../../etc/shadow b/../../etc/shadow
--- a/../../etc/shadow
+++ b/../../etc/shadow
@@ -1,1 +1,1 @@
-root:*:18000:0:99999:7:::
+root:$6$tampered:18000:0:99999:7:::
"""
    entries = parse_unified_diff(diff_text)
    assert len(entries) == 1
    assert entries[0].file_path == "../../etc/shadow"

    kernel = VerificationKernel()
    cert = kernel.verify_entries(entries)

    assert cert.verdict == VerificationVerdict.FAIL
    assert any(f.rule_id == "VC-POLICY-PATH-TRAVERSAL" for f in cert.payload.findings)
    assert any(f.reason == FindingReason.POLICY_VIOLATION for f in cert.payload.findings)
    assert any(f.severity == Severity.CRITICAL for f in cert.payload.findings)


# =========================================================================
# 2. Malformed Diffs & Robust Parsing
# =========================================================================

def test_malformed_diff_corrupt_headers() -> None:
    # Corrupt hunk header and truncated content
    corrupt_diff = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -corrupted,offset @@
+def broken(
"""
    entries = parse_unified_diff(corrupt_diff)
    # Parser should not crash; it extracts whatever file entry it can
    assert len(entries) == 1

    kernel = VerificationKernel()
    cert = kernel.verify_entries(entries)
    # Candidate source contains syntax error -> FAIL (fail closed)
    assert cert.verdict == VerificationVerdict.FAIL
    assert any(f.reason == FindingReason.AST_SYNTAX_ERROR for f in cert.payload.findings)


def test_malformed_diff_random_binary_garbage() -> None:
    garbage = "Random garbage\nwith no diff structure\x00\xff\xfe at all!\n"
    entries = parse_unified_diff(garbage)
    assert len(entries) == 0

    kernel = VerificationKernel()
    cert = kernel.verify_entries(entries)
    # Empty entries verify cleanly
    assert cert.verdict == VerificationVerdict.PASS


# =========================================================================
# 3. Secret Leakage Prevention in Exceptions & Crash Messages
# =========================================================================

def test_extension_crash_secret_sanitization() -> None:
    raw_secret = "ghp_1234567890abcdef1234567890abcdef1234"

    def leaking_extension_checker(entry: DiffFileEntry, base_srcs: dict) -> list[VerificationFinding]:
        raise RuntimeError(f"Database auth failed with secret token: {raw_secret}")

    entry = DiffFileEntry(file_path="src/dummy.py", head_source="x = 1\n")
    kernel = VerificationKernel(extension_checkers=[leaking_extension_checker])
    cert = kernel.verify_entries([entry])

    assert cert.verdict == VerificationVerdict.INCONCLUSIVE
    findings = [f for f in cert.payload.findings if f.rule_id == "VC-EXTENSION-CHECKER-CRASH"]
    assert len(findings) == 1

    crash_finding = findings[0]
    # The raw secret MUST NOT appear anywhere in the finding message
    assert raw_secret not in crash_finding.message
    # Deterministic redaction mask MUST be present
    assert "[REDACTED_SECRET:" in crash_finding.message


# =========================================================================
# 4. Malicious & Invalid Extension Results
# =========================================================================

def test_extension_returning_invalid_types_fails_closed() -> None:
    # Extension returns an integer instead of a list of findings
    def bad_extension_1(entry: DiffFileEntry, base_srcs: dict):
        return 42

    entry = DiffFileEntry(file_path="src/dummy.py", head_source="x = 1\n")
    kernel = VerificationKernel(extension_checkers=[bad_extension_1])
    cert = kernel.verify_entries([entry])

    assert cert.verdict == VerificationVerdict.INCONCLUSIVE
    assert any(f.rule_id == "VC-EXTENSION-CHECKER-CRASH" for f in cert.payload.findings)


def test_extension_returning_malformed_finding_fails_closed() -> None:
    # Extension returns an invalid object inside the sequence
    def bad_extension_2(entry: DiffFileEntry, base_srcs: dict):
        return [{"invalid": "dictionary"}]

    entry = DiffFileEntry(file_path="src/dummy.py", head_source="x = 1\n")
    kernel = VerificationKernel(extension_checkers=[bad_extension_2])
    cert = kernel.verify_entries([entry])

    assert cert.verdict == VerificationVerdict.INCONCLUSIVE
    assert any(f.rule_id == "VC-EXTENSION-CHECKER-CRASH" for f in cert.payload.findings)


# =========================================================================
# 5. Wasmtime Sandbox Memory Limits & Host Isolation
# =========================================================================

def test_wasm_sandbox_rejects_unauthorized_host_imports() -> None:
    # Module attempting to import external host execution capability
    wat_with_imports = """
    (module
        (import "env" "exec" (func $host_exec (param i32)))
        (func (export "run")
            i32.const 0
            call $host_exec)
    )
    """
    adapter = WasmtimeSandboxAdapter()
    with pytest.raises(WasmSandboxCapabilityError) as exc_info:
        adapter.execute_plugin("malicious_importer", wat_with_imports)

    assert "unauthorized host imports" in str(exc_info.value)
    assert "env::exec" in str(exc_info.value)


def test_wasm_sandbox_enforces_memory_limits() -> None:
    # Module requesting 2 pages (128 KiB) when memory_limit_bytes is set to 64 KiB (1 page)
    wat_large_mem = """
    (module
        (memory 2)
        (func (export "run") (result i32)
            i32.const 42)
    )
    """
    adapter = WasmtimeSandboxAdapter()
    # 65536 bytes = 1 page
    with pytest.raises(WasmSandboxCapabilityError) as exc_info:
        adapter.execute_plugin("big_mem", wat_large_mem, memory_limit_bytes=65536)

    assert "memory limit" in str(exc_info.value).lower()


# =========================================================================
# 6. Advanced Alias & Dynamic Call Security
# =========================================================================

def test_dangerous_call_assigned_eval_alias() -> None:
    code = """
def execute_payload(payload: str):
    my_eval = eval
    return my_eval(payload)
"""
    findings = scan_dangerous_calls("src/app.py", code, exclude_tests=False)
    assert len(findings) == 1
    assert findings[0].verdict == VerificationVerdict.FAIL
    assert findings[0].reason == FindingReason.DANGEROUS_CALL
    assert "eval" in findings[0].message


def test_dangerous_call_assigned_os_system_alias() -> None:
    code = """
import os

def run_command(cmd: str):
    executor = os.system
    executor(cmd)
"""
    findings = scan_dangerous_calls("src/app.py", code, exclude_tests=False)
    assert len(findings) == 1
    assert findings[0].verdict == VerificationVerdict.FAIL
    assert "os.system" in findings[0].message


def test_dangerous_call_star_import_subprocess() -> None:
    code = """
from subprocess import *

def spawn_job(arg: str):
    run(["echo", arg])
"""
    findings = scan_dangerous_calls("src/app.py", code, exclude_tests=False)
    assert len(findings) == 1
    assert findings[0].verdict == VerificationVerdict.FAIL
    assert "subprocess.run" in findings[0].message


def test_dangerous_call_star_import_os_with_assigned_alias() -> None:
    code = """
from os import *

def cleanup():
    sys_fn = system
    sys_fn("rm -rf /tmp/test")
"""
    findings = scan_dangerous_calls("src/app.py", code, exclude_tests=False)
    assert len(findings) == 1
    assert findings[0].verdict == VerificationVerdict.FAIL
    assert "os.system" in findings[0].message


def test_dangerous_call_annotated_assignment_alias() -> None:
    code = """
import os
from typing import Callable

def dispatch():
    runner: Callable = os.system
    runner("echo hello")
"""
    findings = scan_dangerous_calls("src/app.py", code, exclude_tests=False)
    assert len(findings) == 1
    assert findings[0].verdict == VerificationVerdict.FAIL
    assert "os.system" in findings[0].message
