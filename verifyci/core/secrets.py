"""Multi-tier secret and high-entropy credential scanner with guaranteed redaction."""

from __future__ import annotations

import ast
import math
import re
from typing import Sequence

from verifyci.contracts.verdict import (
    FindingReason,
    Severity,
    VerificationFinding,
    VerificationVerdict,
)
from verifyci.core.canonical import content_digest_hex, redact_secrets, redact_token

_KNOWN_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS_KEY", re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}")),
    ("GITHUB_TOKEN", re.compile(r"ghp_[A-Za-z0-9_]{36}")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT_TOKEN", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("URI_CREDENTIAL", re.compile(r"[a-zA-Z0-9+.-]+://[^:\s]+:([^@\s]+)@[^\s]+")),
)

_SECRET_VAR_NAMES = re.compile(r"(?i)(?:secret|password|passwd|api_key|token|auth_key|private_key)")
_PLACEHOLDER_VALUES = {
    "placeholder",
    "example",
    "changeme",
    "your_key_here",
    "mysecretpassword",
    "dummy",
    "test",
    "fake",
    "null",
    "none",
}


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for count in (data.count(c) for c in set(data)):
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_placeholder(val: str) -> bool:
    """Detect common test placeholders to avoid false positives."""
    clean = val.strip().lower()
    if clean in _PLACEHOLDER_VALUES:
        return True
    return any(p in clean for p in ("your_", "replace_", "example", "changeme"))


class SecretTaintVisitor(ast.NodeVisitor):
    """AST visitor detecting credential assignments and high-entropy string literals."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.findings: list[VerificationFinding] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check target variable names: e.g. api_key = "..."
        for target in node.targets:
            if isinstance(target, ast.Name) and _SECRET_VAR_NAMES.search(target.id):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    if len(val) >= 6 and not is_placeholder(val):
                        self._add_finding(
                            rule_id="VC-SECRET-CREDENTIAL-ASSIGNMENT",
                            name=target.id,
                            raw_secret=val,
                            lineno=node.lineno,
                            desc=f"Hardcoded credential assigned to variable '{target.id}'",
                        )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        # Check string constants for known token patterns or high entropy
        if isinstance(node.value, str) and len(node.value) >= 16:
            val = node.value
            if not is_placeholder(val):
                for rule_name, pat in _KNOWN_SECRET_PATTERNS:
                    match = pat.search(val)
                    if match:
                        matched_str = match.group(0)
                        self._add_finding(
                            rule_id=f"VC-SECRET-{rule_name}",
                            name=rule_name,
                            raw_secret=matched_str,
                            lineno=getattr(node, "lineno", 1),
                            desc=f"Known credential token pattern ({rule_name}) detected",
                        )
                        return

                # High-entropy thresholding
                entropy = shannon_entropy(val)
                if entropy > 4.5 and len(set(val)) >= 8:
                    self._add_finding(
                        rule_id="VC-SECRET-HIGH-ENTROPY",
                        name="HIGH_ENTROPY_LITERAL",
                        raw_secret=val,
                        lineno=getattr(node, "lineno", 1),
                        desc=f"High-entropy literal (H={entropy:.2f}) detected",
                    )
        self.generic_visit(node)

    def _add_finding(
        self,
        rule_id: str,
        name: str,
        raw_secret: str,
        lineno: int,
        desc: str,
    ) -> None:
        masked = redact_token(raw_secret)
        finding_id = content_digest_hex(f"secret:{self.file_path}:{lineno}:{rule_id}")[:16]
        self.findings.append(
            VerificationFinding(
                finding_id=finding_id,
                rule_id=rule_id,
                severity=Severity.CRITICAL,
                verdict=VerificationVerdict.FAIL,
                reason=FindingReason.SECRET_LEAK,
                message=f"{desc} at line {lineno}: {masked}",
                file_path=self.file_path,
                start_line=lineno,
                end_line=lineno,
                details={"secret_type": name, "redacted_mask": masked},
            )
        )


def scan_secrets_in_source(file_path: str, source: str) -> list[VerificationFinding]:
    """Scan source code for secrets and credentials with guaranteed redaction."""
    findings: list[VerificationFinding] = []

    # 1. Non-AST line regex scan (applicable to all languages and files)
    for idx, line in enumerate(source.splitlines(), start=1):
        for rule_name, pat in _KNOWN_SECRET_PATTERNS:
            match = pat.search(line)
            if match:
                raw_token = match.group(0)
                if not is_placeholder(raw_token):
                    masked = redact_token(raw_token)
                    findings.append(
                        VerificationFinding(
                            finding_id=content_digest_hex(f"secret_regex:{file_path}:{idx}:{rule_name}")[:16],
                            rule_id=f"VC-SECRET-{rule_name}",
                            severity=Severity.CRITICAL,
                            verdict=VerificationVerdict.FAIL,
                            reason=FindingReason.SECRET_LEAK,
                            message=f"Credential pattern ({rule_name}) detected at line {idx}: {masked}",
                            file_path=file_path,
                            start_line=idx,
                            end_line=idx,
                            details={"secret_type": rule_name, "redacted_mask": masked},
                        )
                    )

    # 2. Python AST-based taint and entropy scanning
    if file_path.endswith(".py"):
        try:
            tree = ast.parse(source, filename=file_path)
            visitor = SecretTaintVisitor(file_path)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError:
            pass

    return findings


def sanitize_message(text: str) -> str:
    """Sanitize secrets and credentials from message strings, exceptions, and logs."""
    patterns = [pat for _, pat in _KNOWN_SECRET_PATTERNS]
    return redact_secrets(text, patterns)
