"""Secret, dangerous-call, and fail-closed taint sub-analyses."""

from __future__ import annotations

import base64
import json
import math
import re
from typing import Any, Mapping, Sequence

from verifyci.checks.base import (
    CheckContext,
    gap,
    make_finding,
    make_result,
    unsupported_scope_gaps,
)
from verifyci.contracts.manifest import CHECK_SPECS
from verifyci.contracts.model import (
    CheckResult,
    Coverage,
    CoverageGap,
    EvidenceKind,
    Outcome,
)
from verifyci.contracts.names import glob_match, path_matches_any


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS_KEY", re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{82})\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,120}\b")),
    ("SLACK_WEBHOOK", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,14}/B[0-9A-Za-z_]{8,14}/[0-9A-Za-z_]{20,36}")),
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
    "placeholder", "example", "changeme", "your_key_here", "mysecretpassword",
    "dummy", "test", "fake", "null", "none", "<secret>", "your-api-key",
}
_BUILTIN_DANGEROUS = {
    "eval": re.compile(r"\beval\s*\("),
    "exec": re.compile(r"\bexec\s*\("),
    "compile": re.compile(r"\bcompile\s*\("),
    "os.system": re.compile(r"\bos\.system\s*\("),
    "subprocess": re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\("),
    "pickle.loads": re.compile(r"\bpickle\.loads\s*\("),
    "yaml.load": re.compile(r"\byaml\.load\s*\("),
    "innerHTML": re.compile(r"\.innerHTML\s*="),
}
_TAINT_SOURCE_RE = re.compile(
    r"(?:request\.(?:args|form|json|data|values|get_json)|input\s*\(|sys\.argv|os\.environ|location\.(?:search|hash)|req\.(?:query|body|params))"
)
_TAINT_SINK_RE = re.compile(
    r"(?:execute\s*\(|executemany\s*\(|subprocess\.|os\.system\s*\(|open\s*\(|\.innerHTML\s*=|eval\s*\(|exec\s*\(|pickle\.loads\s*\()"
)


def _redact(token: str) -> str:
    if len(token) <= 8:
        return "***"
    return f"{token[:4]}…{token[-2:]} (len={len(token)})"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    out = 0.0
    for count in (value.count(ch) for ch in set(value)):
        p = count / len(value)
        out -= p * math.log2(p)
    return out


def _is_placeholder(value: str, extra: Sequence[str] = ()) -> bool:
    clean = value.strip().lower()
    if clean in _PLACEHOLDER_EXACT:
        return True
    if clean in {item.strip().lower() for item in extra}:
        return True
    return any(clean.startswith(prefix) or prefix in clean for prefix in _PLACEHOLDER_PREFIXES)


def _valid_secret(kind: str, token: str) -> tuple[bool, str]:
    if kind == "AWS_KEY":
        return len(token) == 20 and token[:4] in {"AKIA", "ABIA", "ACCA", "ASIA"}, "aws_access_key_format"
    if kind == "GITHUB_TOKEN":
        return (token.startswith("github_pat_") and len(token) >= 82) or (len(token) >= 24), "github_token_format"
    if kind == "SLACK_TOKEN":
        return len(token) >= 20, "slack_token_format"
    if kind == "SLACK_WEBHOOK":
        return token.startswith("https://hooks.slack.com/services/"), "slack_webhook_format"
    if kind == "STRIPE_KEY":
        return token.startswith(("sk_live_", "rk_live_")), "stripe_live_key_format"
    if kind == "OPENAI_KEY":
        return token.startswith("sk-") and len(token) >= 20, "openai_key_format"
    if kind == "GOOGLE_KEY":
        return token.startswith("AIza") and len(token) >= 35, "google_api_key_format"
    if kind == "PRIVATE_KEY":
        return "PRIVATE KEY-----" in token, "pem_private_key_structure"
    if kind == "JWT_TOKEN":
        parts = token.split(".")
        if len(parts) != 3:
            return False, "jwt_structure"
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8"))
            return isinstance(header, dict) and "alg" in header, "jwt_structure"
        except Exception:
            return False, "jwt_structure"
    if kind == "URI_CREDENTIAL":
        return "://" in token and "@" in token, "uri_credential_structure"
    return len(token) >= 12, "generic_length_charset"


def _changed_head_lines(context: CheckContext) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for entry in context.entries:
        if not entry.head_path or entry.is_binary or entry.is_submodule or entry.is_symlink:
            continue
        if entry.is_added:
            count = len(entry.head_source.splitlines())
            out.setdefault(entry.head_path, set()).update(range(1, count + 1))
            continue
        lines = out.setdefault(entry.head_path, set())
        for hunk in entry.hunks:
            for line in range(hunk.new_start, hunk.new_end() + 1):
                lines.add(line)
    return out


def _sub_result(
    context: CheckContext,
    *,
    suffix: str,
    outcome: Outcome,
    coverage: Coverage,
    evaluated_scope: Mapping[str, Any],
    scope_enumeration: Mapping[str, Any],
    candidate_discovery: Mapping[str, Any],
    applicability_evidence: Mapping[str, Any],
    reason_codes: Sequence[str] = (),
    coverage_gaps: Sequence[CoverageGap] = (),
    findings: Sequence[Any] = (),
    diagnostics: Sequence[Mapping[str, Any]] = (),
) -> CheckResult:
    spec = CHECK_SPECS["security"]
    return CheckResult(
        check_id=f"security.{suffix}",
        check_version=1,
        tier=spec.tier,
        maturity=spec.maturity,
        outcome=outcome,
        coverage=coverage,
        evaluated_scope=dict(evaluated_scope),
        scope_enumeration=dict(scope_enumeration),
        candidate_discovery=dict(candidate_discovery),
        applicability_evidence=dict(applicability_evidence),
        method=f"security.{suffix}",
        method_version=1,
        reason_codes=tuple(reason_codes),
        coverage_gaps=tuple(coverage_gaps),
        findings=tuple(findings),
        diagnostics=tuple(dict(d) for d in diagnostics),
        toolchain_fingerprint=context.toolchain_fingerprint,
    )


def _secret_sub(context: CheckContext) -> CheckResult:
    changed = _changed_head_lines(context)
    text_entries = [
        entry for entry in context.entries
        if (entry.head_path or entry.base_path)
        and not entry.is_binary
        and not entry.is_submodule
        and not entry.is_symlink
    ]
    if not text_entries:
        return _sub_result(
            context,
            suffix="secrets",
            outcome=Outcome.NOT_APPLICABLE,
            coverage=Coverage.COMPLETE,
            evaluated_scope={"files": []},
            scope_enumeration={"complete": True},
            candidate_discovery={"complete": True},
            applicability_evidence={"changed_text_files": 0},
        )

    findings = []
    gaps: list[CoverageGap] = []
    ambiguous = 0
    scanned_lines = 0
    for entry in context.entries:
        path = entry.head_path
        if not path or entry.is_binary or entry.is_submodule or entry.is_symlink:
            continue
        if path_matches_any(context.policy.secret_allowlist_paths, path):
            continue
        line_numbers = changed.get(path, set())
        for line_number, line in enumerate(entry.head_source.splitlines(), start=1):
            if line_number not in line_numbers:
                continue
            scanned_lines += 1
            known_secret_found = False
            for kind, pattern in _SECRET_PATTERNS:
                for match in pattern.finditer(line):
                    raw = match.group(0)
                    if _is_placeholder(raw, context.policy.secret_placeholders):
                        continue
                    valid, validation = _valid_secret(kind, raw)
                    if not valid:
                        ambiguous += 1
                        gaps.append(
                            gap(
                                "secret_candidate_ambiguous",
                                {
                                    "check_id": "security.secrets",
                                    "path": path,
                                    "line": line_number,
                                    "pattern": kind,
                                },
                            )
                        )
                        continue
                    redacted = _redact(raw)
                    known_secret_found = True
                    findings.append(
                        make_finding(
                            context=context,
                            check_id="security",
                            defect_id="SEC-SECRET",
                            subject={"path": path, "line": line_number, "symbol": ""},
                            premises={
                                "pattern": kind,
                                "validation": validation,
                                "liveness_checked": False,
                            },
                            evidence_kind=EvidenceKind.SECRET_VALIDATION,
                            evidence_payload={
                                "identity": {
                                    "path": path,
                                    "line": line_number,
                                    "pattern": kind,
                                    "redacted": redacted,
                                },
                                "path": path,
                                "line": line_number,
                                "pattern": kind,
                                "redacted": redacted,
                                "validation": f"offline:{validation}",
                                "liveness_checked": False,
                            },
                            message=(
                                f"{kind} credential material detected at {path}:{line_number}; "
                                "format-validated offline, liveness not checked"
                            ),
                            remediation="Remove the credential, rotate it, and use a secret manager.",
                        )
                    )
                    break
            # Generic high-entropy assignment in changed text.
            stripped = line.strip()
            if not known_secret_found and "=" in stripped and not stripped.startswith("#"):
                key, _, value = stripped.partition("=")
                value = value.strip().strip("'\"")
                if (
                    _SECRET_VAR_NAMES.search(key)
                    and len(value) >= 16
                    and not _is_placeholder(value, context.policy.secret_placeholders)
                ):
                    if _entropy(value) >= 3.5:
                        redacted = _redact(value)
                        findings.append(
                            make_finding(
                                context=context,
                                check_id="security",
                                defect_id="SEC-SECRET",
                                subject={"path": path, "line": line_number, "symbol": ""},
                                premises={"pattern": "HIGH_ENTROPY_ASSIGNMENT", "validation": "entropy"},
                                evidence_kind=EvidenceKind.SECRET_VALIDATION,
                                evidence_payload={
                                    "identity": {
                                        "path": path,
                                        "line": line_number,
                                        "pattern": "HIGH_ENTROPY_ASSIGNMENT",
                                        "redacted": redacted,
                                    },
                                    "path": path,
                                    "line": line_number,
                                    "pattern": "HIGH_ENTROPY_ASSIGNMENT",
                                    "redacted": redacted,
                                    "validation": "offline:entropy_and_context",
                                    "liveness_checked": False,
                                },
                                message=(
                                    f"high-entropy credential-like assignment at {path}:{line_number}; "
                                    "liveness not checked"
                                ),
                                remediation="Remove the credential, rotate it, and use a secret manager.",
                            )
                        )

    if findings:
        outcome = Outcome.FAIL
    elif gaps:
        outcome = Outcome.INCONCLUSIVE
    else:
        outcome = Outcome.PASS
    coverage = Coverage.COMPLETE if not gaps else Coverage.PARTIAL
    return _sub_result(
        context,
        suffix="secrets",
        outcome=outcome,
        coverage=coverage,
        evaluated_scope={"files": sorted(changed), "lines": scanned_lines},
        scope_enumeration={"complete": True, "changed_text_files": len(changed)},
        candidate_discovery={"complete": not gaps, "ambiguous_candidates": ambiguous},
        applicability_evidence={"changed_text_files": len(changed)},
        reason_codes=tuple(sorted({g.reason_code for g in gaps})),
        coverage_gaps=gaps,
        findings=findings,
    )


def _dangerous_sub(context: CheckContext) -> CheckResult:
    changed = _changed_head_lines(context)
    findings = []
    checked = 0
    custom = {
        rule_id: tuple(rule.get("symbols", ()))
        for rule_id, rule in context.policy.forbidden_calls.items()
    }
    for entry in context.entries:
        path = entry.head_path
        if not path or entry.is_binary or entry.is_submodule or entry.is_symlink:
            continue
        for line_number, line in enumerate(entry.head_source.splitlines(), start=1):
            if line_number not in changed.get(path, set()):
                continue
            if line.lstrip().startswith("#"):
                continue
            checked += 1
            matched: list[tuple[str, str]] = []
            for name, pattern in _BUILTIN_DANGEROUS.items():
                if pattern.search(line):
                    matched.append((name, name))
            for rule_id, symbols in custom.items():
                for symbol in symbols:
                    simple = symbol.split(":")[-1].rsplit(".", 1)[-1]
                    if re.search(rf"\b{re.escape(simple)}\s*\(", line):
                        matched.append((rule_id, symbol))
            for rule_id, symbol in matched:
                findings.append(
                    make_finding(
                        context=context,
                        check_id="security",
                        defect_id="SEC-DANGEROUS-CALL",
                        subject={"path": path, "line": line_number, "symbol": symbol},
                        premises={"rule_id": rule_id, "resolved_callee": symbol},
                        evidence_kind=EvidenceKind.CALL_SITE,
                        evidence_payload={
                            "identity": {
                                "path": path,
                                "line": line_number,
                                "rule_id": rule_id,
                                "callee": symbol,
                            },
                            "path": path,
                            "line": line_number,
                            "rule_id": rule_id,
                            "callee": symbol,
                            "span": {"start": line_number, "end": line_number},
                        },
                        message=f"policy-forbidden call {symbol} introduced at {path}:{line_number}",
                        remediation="Use a safe alternative or obtain an explicit policy exception.",
                    )
                )
    if findings:
        outcome = Outcome.FAIL
    elif checked == 0:
        outcome = Outcome.NOT_APPLICABLE
    else:
        outcome = Outcome.PASS
    return _sub_result(
        context,
        suffix="dangerous_calls",
        outcome=outcome,
        coverage=Coverage.COMPLETE,
        evaluated_scope={"files": sorted(changed), "checked_lines": checked},
        scope_enumeration={"complete": True, "checked_lines": checked},
        candidate_discovery={"complete": True, "checked_lines": checked},
        applicability_evidence={"checked_lines": checked, "rules": sorted(context.policy.forbidden_calls)},
        reason_codes=(),
        findings=findings,
    )


def _taint_excluded(policy, path: str) -> bool:
    for key in ("generated", "vendored", "binary"):
        for pattern in policy.path_classes.get(key, ()):
            if glob_match(pattern, path, kind="path"):
                return True
    return False


def _taint_sub(context: CheckContext) -> CheckResult:
    if not context.policy.taint_sources or not context.policy.taint_sinks:
        return _sub_result(
            context,
            suffix="taint",
            outcome=Outcome.NOT_APPLICABLE,
            coverage=Coverage.COMPLETE,
            evaluated_scope={},
            scope_enumeration={"complete": True, "configured": False},
            candidate_discovery={"complete": True},
            applicability_evidence={"configured": False},
        )
    changed = _changed_head_lines(context)
    findings = []
    gaps = unsupported_scope_gaps(
        context,
        "security.taint",
        exclude_path=lambda path: _taint_excluded(context.policy, path),
    )
    relevant = 0
    unresolved = 0
    for entry in context.entries:
        path = entry.head_path
        if not path or entry.is_binary or entry.is_submodule or entry.is_symlink:
            continue
        if path.rsplit(".", 1)[-1].lower() not in ("py", "ts", "tsx", "js", "jsx"):
            continue
        if _taint_excluded(context.policy, path):
            continue
        for line_number, line in enumerate(entry.head_source.splitlines(), start=1):
            if line_number not in changed.get(path, set()):
                continue
            has_source = bool(_TAINT_SOURCE_RE.search(line))
            has_sink = bool(_TAINT_SINK_RE.search(line))
            if not has_source and not has_sink:
                continue
            relevant += 1
            if has_source and has_sink:
                findings.append(
                    make_finding(
                        context=context,
                        check_id="security",
                        defect_id="SEC-TAINT-TO-SINK",
                        subject={"path": path, "line": line_number, "symbol": ""},
                        premises={"source": _TAINT_SOURCE_RE.search(line).group(0), "sink": _TAINT_SINK_RE.search(line).group(0)},
                        evidence_kind=EvidenceKind.TAINT_PATH,
                        evidence_payload={
                            "identity": {"path": path, "line": line_number, "kind": "same_line"},
                            "path": path,
                            "source": {"line": line_number, "text": _TAINT_SOURCE_RE.search(line).group(0)},
                            "sink": {"line": line_number, "text": _TAINT_SINK_RE.search(line).group(0)},
                            "edges": [{"line": line_number, "justification": "same expression"}],
                        },
                        message=f"untrusted input reaches a dangerous sink at {path}:{line_number}",
                        remediation="Validate, parameterize, or sanitize the input before the sink.",
                    )
                )
            else:
                # A source or sink alone needs inter-line analysis that this
                # implementation does not claim.  Fail closed.
                unresolved += 1
    if unresolved:
        gaps.append(
            gap(
                "taint_path_unresolved",
                {"check_id": "security.taint", "reason": "source_or_sink_without_resolved_path"},
            )
        )
    if findings:
        outcome = Outcome.FAIL
    elif gaps:
        outcome = Outcome.INCONCLUSIVE
    elif relevant == 0:
        outcome = Outcome.NOT_APPLICABLE
    else:
        outcome = Outcome.PASS
    if any(g.reason_code in ("unsupported_language", "parse_error") for g in gaps):
        coverage = Coverage.UNKNOWN
    else:
        coverage = Coverage.COMPLETE if not gaps else Coverage.PARTIAL
    return _sub_result(
        context,
        suffix="taint",
        outcome=outcome,
        coverage=coverage,
        evaluated_scope={"relevant_lines": relevant},
        scope_enumeration={"complete": not gaps, "relevant_lines": relevant},
        candidate_discovery={"complete": not gaps, "relevant_lines": relevant, "unresolved": unresolved},
        applicability_evidence={"configured": True, "relevant_lines": relevant},
        reason_codes=tuple(sorted({g.reason_code for g in gaps})),
        coverage_gaps=gaps,
        findings=findings,
    )


_PRECEDENCE = {
    Outcome.ERROR: 5,
    Outcome.FAIL: 4,
    Outcome.INCONCLUSIVE: 3,
    Outcome.PASS: 2,
    Outcome.NOT_APPLICABLE: 1,
}
_COVERAGE_ORDER = {Coverage.UNKNOWN: 3, Coverage.PARTIAL: 2, Coverage.COMPLETE: 1}


def run(context: CheckContext) -> CheckResult:
    subs = [_secret_sub(context), _dangerous_sub(context), _taint_sub(context)]
    invalid = False
    for sub in subs:
        if sub.validate():
            invalid = True
    if invalid:
        return make_result(
            context=context,
            check_id="security",
            outcome=Outcome.ERROR,
            coverage=Coverage.UNKNOWN,
            evaluated_scope={"sub_results": [s.check_id for s in subs]},
            scope_enumeration={"complete": False, "reason_code": "invalid_check_result"},
            candidate_discovery={"complete": False, "reason_code": "invalid_check_result"},
            applicability_evidence={},
            reason_codes=("invalid_check_result",),
            diagnostics=({"code": "invalid_check_result", "detail": "security sub-result failed validation"},),
            sub_results=subs,
        )
    outcome = max((s.outcome for s in subs), key=lambda o: _PRECEDENCE[o])
    applicable = [s for s in subs if s.outcome != Outcome.NOT_APPLICABLE]
    if applicable:
        coverage = max((s.coverage for s in applicable), key=lambda c: _COVERAGE_ORDER[c])
    else:
        coverage = Coverage.COMPLETE
    findings = []
    seen: set[str] = set()
    for sub in subs:
        for finding in sub.findings:
            key = finding.fingerprint or f"{finding.defect_id}:{finding.subject}"
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    gaps = [g for sub in subs for g in sub.coverage_gaps]
    reason_codes = sorted({code for sub in subs for code in sub.reason_codes})
    diagnostics = [d for sub in subs for d in sub.diagnostics]
    return make_result(
        context=context,
        check_id="security",
        outcome=outcome,
        coverage=coverage,
        evaluated_scope={"sub_results": {s.check_id: s.evaluated_scope for s in subs}},
        scope_enumeration={"complete": all(s.scope_enumeration.get("complete", False) for s in subs)},
        candidate_discovery={"complete": all(s.candidate_discovery.get("complete", False) for s in subs)},
        applicability_evidence={"sub_results": {s.check_id: s.applicability_evidence for s in subs}},
        reason_codes=tuple(reason_codes),
        coverage_gaps=gaps,
        findings=findings,
        diagnostics=diagnostics,
        sub_results=subs,
    )


__all__ = ["run"]
