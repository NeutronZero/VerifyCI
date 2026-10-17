"""Multi-tier secret and high-entropy credential scanner with guaranteed redaction."""

from __future__ import annotations

import ast
import base64
import math
import re

from verifyci.contracts.verdict import (
    FindingReason,
    Severity,
    VerificationFinding,
    VerificationVerdict,
)
from verifyci.core.canonical import content_digest_hex, redact_secrets, redact_token

_KNOWN_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS_KEY", re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{82})\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,120}\b")),
    ("STRIPE_KEY", re.compile(r"\b[rs]k_live_[0-9a-zA-Z]{16,99}\b")),
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-|live-)?[A-Za-z0-9_-]{12,120}\b")),
    ("GOOGLE_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{30,50}\b")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    (
        "URI_CREDENTIAL",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb\+srv|mongodb|redis|rediss|amqps?|mssql|sqlserver|ftps?|ssh|ldap|jdbc)://[^\s:/@]{1,64}:[^\s@]{4,128}@[^\s]{3,}"
        ),
    ),
)

_SECRET_VAR_NAMES = re.compile(r"(?i)(?:secret|password|passwd|api_key|token|auth_key|private_key|deploy_key)")
_PLACEHOLDER_PREFIXES = ("your_", "replace_", "example", "changeme", "enter_", "mock_", "dummy_")
_PLACEHOLDER_EXACT = {
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
    "<secret>",
    "your-api-key",
}


def eval_string_binop(node: ast.AST) -> str | None:
    """Evaluate static string additions in AST."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = eval_string_binop(node.left)
        right = eval_string_binop(node.right)
        if left is not None and right is not None:
            return left + right
    return None


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
    if clean in _PLACEHOLDER_EXACT:
        return True
    return any(clean.startswith(p) or p in clean for p in _PLACEHOLDER_PREFIXES)


def is_benign_text_or_data(val: str) -> bool:
    """Filter out non-secret base64 payloads and inline assets."""
    if val.startswith("data:image/") or val.startswith("data:application/"):
        return True
    if len(val) > 20 and len(val) % 4 == 0 and re.match(r"^[A-Za-z0-9+/]+={0,2}$", val):
        try:
            decoded = base64.b64decode(val).decode("utf-8")
            if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in decoded):
                if " " in decoded:
                    return True
        except Exception:
            pass
    return False


def check_encoded_secret(val: str) -> tuple[str, str] | None:
    """Detect hex or base64-encoded secret payloads."""
    # 1. Hex decoding
    if len(val) >= 32 and len(val) % 2 == 0 and re.match(r"^[0-9a-fA-F]+$", val):
        try:
            decoded = bytes.fromhex(val).decode("utf-8", errors="ignore")
            for name, pat in _KNOWN_SECRET_PATTERNS:
                m = pat.search(decoded)
                if m and not is_placeholder(m.group(0)):
                    return name, m.group(0)
        except Exception:
            pass
    # 2. Base64 decoding
    if len(val) >= 20 and len(val) % 4 == 0 and re.match(r"^[A-Za-z0-9+/]+={0,2}$", val):
        try:
            decoded = base64.b64decode(val).decode("utf-8", errors="ignore")
            for name, pat in _KNOWN_SECRET_PATTERNS:
                m = pat.search(decoded)
                if m and not is_placeholder(m.group(0)):
                    return name, m.group(0)
        except Exception:
            pass
    return None


def is_test_path(file_path: str) -> bool:
    norm = file_path.replace("\\", "/").lower()
    return (
        norm.startswith("tests/")
        or "/tests/" in norm
        or norm.startswith("test/")
        or "/test/" in norm
        or "/fixtures/" in norm
    )


def _create_secret_finding(
    file_path: str,
    lineno: int,
    rule_id: str,
    secret_type: str,
    raw_secret: str,
    desc: str,
) -> VerificationFinding:
    masked = redact_token(raw_secret)
    finding_id = content_digest_hex(f"secret:{file_path}:{lineno}:{rule_id}:{masked}")[:16]
    return VerificationFinding(
        finding_id=finding_id,
        rule_id=rule_id,
        severity=Severity.CRITICAL,
        verdict=VerificationVerdict.FAIL,
        reason=FindingReason.SECRET_LEAK,
        message=f"{desc} at line {lineno}: {masked}",
        file_path=file_path,
        start_line=lineno,
        end_line=lineno,
        details={"secret_type": secret_type, "redacted_mask": masked},
    )


class SecretTaintVisitor(ast.NodeVisitor):
    """AST visitor detecting credential assignments, string concatenations, and encoded secrets."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.is_test = is_test_path(file_path)
        self.findings: list[VerificationFinding] = []

    def visit_BinOp(self, node: ast.BinOp) -> None:
        val = eval_string_binop(node)
        if val is not None and not is_placeholder(val):
            enc = check_encoded_secret(val)
            if enc:
                name, decoded_token = enc
                self.findings.append(
                    _create_secret_finding(
                        self.file_path,
                        getattr(node, "lineno", 1),
                        f"VC-SECRET-ENCODED-{name}",
                        f"ENCODED_{name}",
                        val,
                        f"Encoded credential token ({name}) in concatenated expression",
                    )
                )
                return
            for name, pat in _KNOWN_SECRET_PATTERNS:
                m = pat.search(val)
                if m and not is_placeholder(m.group(0)):
                    self.findings.append(
                        _create_secret_finding(
                            self.file_path,
                            getattr(node, "lineno", 1),
                            f"VC-SECRET-{name}",
                            name,
                            m.group(0),
                            f"Known credential token pattern ({name}) in concatenated expression",
                        )
                    )
                    return
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and _SECRET_VAR_NAMES.search(target.id):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    lineno = getattr(node, "lineno", 1)
                    enc = check_encoded_secret(val)
                    if enc:
                        name, decoded_token = enc
                        self.findings.append(
                            _create_secret_finding(
                                self.file_path,
                                lineno,
                                f"VC-SECRET-ENCODED-{name}",
                                f"ENCODED_{name}",
                                val,
                                f"Encoded credential token ({name}) assigned to variable '{target.id}'",
                            )
                        )
                        continue
                    if not is_placeholder(val) and not is_benign_text_or_data(val) and not self.is_test:
                        if len(val) >= 16 and shannon_entropy(val) >= 3.5:
                            self.findings.append(
                                _create_secret_finding(
                                    self.file_path,
                                    lineno,
                                    "VC-SECRET-CREDENTIAL-ASSIGNMENT",
                                    target.id,
                                    val,
                                    f"Hardcoded high-entropy credential assigned to variable '{target.id}'",
                                )
                            )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and len(node.value) >= 16:
            val = node.value
            lineno = getattr(node, "lineno", 1)
            enc = check_encoded_secret(val)
            if enc:
                name, decoded_token = enc
                self.findings.append(
                    _create_secret_finding(
                        self.file_path,
                        lineno,
                        f"VC-SECRET-ENCODED-{name}",
                        f"ENCODED_{name}",
                        val,
                        f"Encoded credential token ({name}) detected",
                    )
                )
                return

            if not is_placeholder(val):
                for rule_name, pat in _KNOWN_SECRET_PATTERNS:
                    match = pat.search(val)
                    if match:
                        matched_str = match.group(0)
                        if self.is_test and "mock" in matched_str.lower():
                            continue
                        self.findings.append(
                            _create_secret_finding(
                                self.file_path,
                                lineno,
                                f"VC-SECRET-{rule_name}",
                                rule_name,
                                matched_str,
                                f"Known credential token pattern ({rule_name}) detected",
                            )
                        )
                        return

                if not self.is_test and not is_benign_text_or_data(val):
                    entropy = shannon_entropy(val)
                    if entropy >= 4.5 and len(set(val)) >= 8 and len(val) >= 20:
                        self.findings.append(
                            _create_secret_finding(
                                self.file_path,
                                lineno,
                                "VC-SECRET-HIGH-ENTROPY",
                                "HIGH_ENTROPY_LITERAL",
                                val,
                                f"High-entropy literal (H={entropy:.2f}) detected",
                            )
                        )
        self.generic_visit(node)


def scan_secrets_in_source(file_path: str, source: str) -> list[VerificationFinding]:
    """Scan source code for secrets and credentials with guaranteed redaction."""
    findings: list[VerificationFinding] = []
    is_test = is_test_path(file_path)

    # 1. Non-AST regex scan (applicable to all file types)
    for idx, line in enumerate(source.splitlines(), start=1):
        line_clean = line.strip()
        for rule_name, pat in _KNOWN_SECRET_PATTERNS:
            match = pat.search(line)
            if match:
                raw_token = match.group(0)
                if not is_placeholder(raw_token):
                    if is_test and "mock" in raw_token.lower():
                        continue
                    findings.append(
                        _create_secret_finding(
                            file_path,
                            idx,
                            f"VC-SECRET-{rule_name}",
                            rule_name,
                            raw_token,
                            f"Credential pattern ({rule_name}) detected",
                        )
                    )

        # Config / env assignment scan (non-Python files: .env, yaml, ini, etc.)
        if not file_path.endswith(".py") and "=" in line_clean and not line_clean.startswith("#"):
            k, _, v = line_clean.partition("=")
            k, v = k.strip(), v.strip().strip("'\"")
            if _SECRET_VAR_NAMES.search(k) and not is_placeholder(v):
                if len(v) >= 12 and (shannon_entropy(v) >= 3.2 or any(c in "!@#$%^&*()_+" for c in v)):
                    if not is_test:
                        findings.append(
                            _create_secret_finding(
                                file_path,
                                idx,
                                "VC-SECRET-CONFIG-ASSIGNMENT",
                                k,
                                v,
                                f"Credential assignment in config line for '{k}'",
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
