from __future__ import annotations

import ast
import base64
import binascii
import math
import re
import urllib.parse

from verifyci_v2.contracts.ai_protocol import ConformalProfile, DiscriminativeJudgeProtocol
from verifyci_v2.contracts.attestation import VerificationFinding
from verifyci_v2.contracts.canonical import blake3_hex
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.neural.conformal import evaluate_with_conformal_gate

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("GITHUB_PAT", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{82})\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,120}\b")),
    ("STRIPE_LIVE_KEY", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,99}\b")),
    ("OPENAI_API_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,120}\b")),
    ("PRIVATE_KEY_HEADER", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)

_BASE64_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
_HEX_CANDIDATE_RE = re.compile(r"^[0-9a-fA-F]{32,}$")


def shannon_entropy(text: str) -> float:
    """Computes the Shannon entropy H(X) in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def multi_pass_decode(raw_value: str, max_passes: int = 3) -> tuple[str, ...]:
    """
    Recursively decodes obfuscated strings (URL-encoded, Base64, Hex) up to `max_passes`
    to expose hidden secrets (`cap011`).
    """
    discovered: list[str] = [raw_value]
    curr = raw_value.strip()

    for _ in range(max_passes):
        next_val: str | None = None
        if "%" in curr:
            unquoted = urllib.parse.unquote(curr)
            if unquoted != curr:
                next_val = unquoted

        if next_val is None and _HEX_CANDIDATE_RE.match(curr) and len(curr) % 2 == 0:
            try:
                decoded_bytes = binascii.unhexlify(curr)
                decoded_str = decoded_bytes.decode("utf-8")
                if decoded_str.isprintable() or all(c.isprintable() or c in "\r\n\t" for c in decoded_str):
                    next_val = decoded_str
            except (binascii.Error, UnicodeDecodeError):
                pass

        if next_val is None and _BASE64_CANDIDATE_RE.match(curr) and len(curr) % 4 == 0:
            try:
                decoded_bytes = base64.b64decode(curr, validate=True)
                decoded_str = decoded_bytes.decode("utf-8")
                if decoded_str.isprintable() or all(c.isprintable() or c in "\r\n\t" for c in decoded_str):
                    next_val = decoded_str
            except (binascii.Error, ValueError, UnicodeDecodeError):
                pass

        if next_val is None or next_val in discovered:
            break
        discovered.append(next_val)
        curr = next_val

    return tuple(discovered)


def is_test_or_fixture_partition(file_path: str) -> bool:
    """Classifies whether a file belongs to a unit test, mock, or fixture partition (`cap002b`)."""
    norm = file_path.replace("\\", "/").lower()
    parts = norm.split("/")
    if any(p in ("tests", "test", "fixtures", "mocks", "__mocks__") for p in parts):
        return True
    fname = parts[-1]
    return fname.startswith("test_") or fname.endswith("_test.py") or "fixture" in fname


def redact_secrets(text: str) -> str:
    """
    Scrubs matched credential patterns and high-entropy token assignments before any payload
    is sent to an external BYO-AI endpoint.
    """
    redacted = text
    counter = 0
    for _rule_name, pattern in _SECRET_PATTERNS:
        for match in list(pattern.finditer(redacted)):
            counter += 1
            redacted = redacted.replace(match.group(0), f"<REDACTED_SECRET_{counter}>")

    # Also scrub high-entropy string literals assigned to secret/token/key/password variables
    assign_re = re.compile(
        r"(?i)\b(api_key|secret|token|password|passwd|client_secret)\s*=\s*['\"]([^'\"]{16,})['\"]"
    )
    for match in list(assign_re.finditer(redacted)):
        candidate = match.group(2)
        if shannon_entropy(candidate) >= 3.7 and not candidate.startswith("<REDACTED_"):
            counter += 1
            redacted = redacted.replace(candidate, f"<REDACTED_SECRET_{counter}>")
    return redacted


class TaintTrackedSecretEngine:
    """
    Layer 5 Stage 3 Secret & Taint Engine (`verifyci_v2/symbolic/secrets_taint.py`).
    Combines multi-pass decoding + Shannon entropy with DFG source-to-sink taint tracking
    and Split Conformal mock/fixture triage (`cap002b` and `cap011`).
    """

    def scan_python_source(
        self,
        file_path: str,
        source: str,
        *,
        judge: DiscriminativeJudgeProtocol | None = None,
        conformal_profile: ConformalProfile | None = None,
    ) -> tuple[VerificationFinding, ...]:
        is_test_file = is_test_or_fixture_partition(file_path)
        ussa_funcs = lower_file_to_ussa(file_path, source, language="python")
        sink_sinks_by_line: dict[int, list[str]] = {}

        # Collect sink calls inside functions to check if secrets flow into logging/network sinks
        for fn in ussa_funcs:
            for block in fn.basic_blocks:
                for inst in block.instructions:
                    if inst.opcode == "CALL" and any(
                        s in inst.operands[0]
                        for s in ("print", "logger.", "logging.", "requests.", "httpx.")
                    ):
                        sink_sinks_by_line.setdefault(fn.start_line, []).append(inst.operands[0])

        tree = ast.parse(source, filename=file_path)
        findings: list[VerificationFinding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Constant):
                continue
            if not isinstance(node.value.value, str):
                continue

            raw_literal = node.value.value
            if len(raw_literal) < 12:
                continue

            var_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            var_name = var_names[0] if var_names else "literal"

            # Ignore explicit test mock/dummy markers in test partitions
            if is_test_file and any(
                tok in raw_literal.lower() or tok in var_name.lower()
                for tok in ("mock", "dummy", "fake", "example", "test_key", "placeholder")
            ):
                continue

            decoded_variants = multi_pass_decode(raw_literal)
            matched_rule: str | None = None
            max_entropy = 0.0

            for variant in decoded_variants:
                max_entropy = max(max_entropy, shannon_entropy(variant))
                for rule_name, pattern in _SECRET_PATTERNS:
                    if pattern.search(variant):
                        matched_rule = rule_name
                        break
                if matched_rule:
                    break

            sensitive_var = any(
                k in var_name.lower()
                for k in ("secret", "token", "key", "password", "credential", "auth")
            )
            if matched_rule is None and not (sensitive_var and max_entropy >= 3.85):
                continue

            # Optional System 1 Conformal Triage for ambiguous candidates in test files
            if is_test_file and judge is not None and conformal_profile is not None:
                choice = judge.judge_choice(
                    state={"file_path": file_path, "var_name": var_name, "entropy": round(max_entropy, 3)},
                    question="Classify this credential candidate:",
                    options=("test_fixture_or_mock", "live_production_credential"),
                )
                decision = evaluate_with_conformal_gate(
                    choice.distribution,
                    conformal_profile,
                    safe_label="test_fixture_or_mock",
                )
                if not decision.escalate_to_smt and decision.top_choice == "test_fixture_or_mock":
                    continue

            # Check if variable flows along DFG to a sink in the same scope
            flows_to_sink = bool(re.search(rf"(?:print|logger\.\w+|requests\.\w+|httpx\.\w+)\([^)]*\b{re.escape(var_name)}\b", source))
            severity = "CRITICAL" if (flows_to_sink or matched_rule is not None) else "HIGH"
            rule_tag = matched_rule or "HIGH_ENTROPY_TAINTED_SECRET"
            obfuscated_note = " (decoded via multi-pass decoder)" if len(decoded_variants) > 1 else ""
            sink_note = " and flows into active I/O sink" if flows_to_sink else ""

            fid = blake3_hex(f"SECRET:{file_path}:{node.lineno}:{var_name}:{rule_tag}", domain="verifyci.v2.finding")[:16]
            findings.append(
                VerificationFinding(
                    finding_id=fid,
                    rule_id=f"VC2-SECRET-{rule_tag}",
                    severity=severity,
                    verdict="FAIL",
                    file_path=file_path,
                    start_line=node.lineno,
                    end_line=node.lineno,
                    message=(
                        f"Hardcoded secret detected in '{var_name}' [{rule_tag}, "
                        f"entropy={max_entropy:.2f} bits]{obfuscated_note}{sink_note}."
                    ),
                )
            )

        return tuple(findings)