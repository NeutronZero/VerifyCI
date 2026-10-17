"""VerificationKernel: Minimal, deterministic, fail-closed verification engine."""

from __future__ import annotations

import ast
from typing import Callable, Mapping, Sequence

from verifyci.contracts.attestation import (
    ATTESTATION_DIGEST_DOMAIN,
    CanonicalAttestationPayload,
    VerificationCertificate,
    is_path_traversal,
)
from verifyci.contracts.capabilities import CapabilityDeclaration
from verifyci.contracts.verdict import (
    FindingReason,
    Severity,
    VerificationFinding,
    VerificationVerdict,
    derive_verdict,
)
from verifyci.core.canonical import content_digest_hex
from verifyci.core.diff_parser import DiffFileEntry
from verifyci.core.imports import check_unresolved_imports
from verifyci.core.provenance import verify_removal_provenance
from verifyci.core.secrets import sanitize_message, scan_secrets_in_source
from verifyci.core.security import scan_dangerous_calls

ExtensionChecker = Callable[[DiffFileEntry, Mapping[str, str]], Sequence[VerificationFinding]]


def repair_empty_bodies(source: str) -> str:
    """Add 'pass' to block headers that partial diff hunks left bodiless."""
    lines = source.splitlines()
    out: list[str] = []
    for idx, line in enumerate(lines):
        out.append(line)
        stripped = line.strip()
        is_block_header = (
            stripped.startswith("def ") or stripped.startswith("class ")
        ) and stripped.endswith(":")
        if not is_block_header:
            continue
        following = lines[idx + 1] if idx + 1 < len(lines) else ""
        if following.strip() and following[:1].isspace():
            continue
        indent = line[: len(line) - len(line.lstrip())]
        out.append(f"{indent}    pass")
    return "\n".join(out) + "\n"


def parseable_source(file_path: str, source: str) -> tuple[str, VerificationFinding | None]:
    """Attempt parsing source, repairing valid partial hunk fragments where possible."""
    try:
        ast.parse(source, filename=file_path)
        return source, None
    except SyntaxError as first_err:
        syntax_err = first_err

    # Try dedenting
    import textwrap

    dedented = textwrap.dedent(source)
    try:
        ast.parse(dedented, filename=file_path)
        return dedented, None
    except SyntaxError:
        pass

    # Try repairing empty block headers
    repaired = repair_empty_bodies(dedented)
    try:
        ast.parse(repaired, filename=file_path)
        return repaired, None
    except SyntaxError:
        pass

    # Try wrapping function fragment
    wrapped = "def __vc_fragment__():\n" + textwrap.indent(dedented, "    ") + "\n"
    try:
        ast.parse(wrapped, filename=file_path)
        return wrapped, None
    except SyntaxError:
        pass

    # Truly unparseable syntax error -> FAIL
    lineno = syntax_err.lineno or 1
    finding = VerificationFinding(
        finding_id=content_digest_hex(f"syntax_error:{file_path}:{lineno}")[:16],
        rule_id="VC-SYNTAX-AST-PARSE-ERROR",
        severity=Severity.CRITICAL,
        verdict=VerificationVerdict.FAIL,
        reason=FindingReason.AST_SYNTAX_ERROR,
        message=f"Syntax error in candidate source '{file_path}': {syntax_err}",
        file_path=file_path,
        start_line=lineno,
        end_line=lineno,
    )
    return source, finding


class VerificationKernel:
    """Minimal secure verification kernel with zero heavyweight dependencies (slotted model)."""

    __slots__ = (
        "base_commit_sha",
        "base_sources",
        "block_on_unresolved_imports",
        "extension_checkers",
        "head_commit_sha",
        "policy_hash",
        "required_capabilities",
    )

    def __init__(
        self,
        base_sources: Mapping[str, str] | None = None,
        base_commit_sha: str = "none",
        head_commit_sha: str = "none",
        policy_hash: str = "default_policy",
        extension_checkers: Sequence[ExtensionChecker] = (),
        required_capabilities: Sequence[CapabilityDeclaration] = (),
        block_on_unresolved_imports: bool = False,
    ) -> None:
        self.base_sources = dict(base_sources or {})
        self.base_commit_sha = base_commit_sha
        self.head_commit_sha = head_commit_sha
        self.policy_hash = policy_hash
        self.extension_checkers = tuple(extension_checkers)
        self.required_capabilities = tuple(required_capabilities)
        self.block_on_unresolved_imports = block_on_unresolved_imports

    def verify_entries(self, entries: Sequence[DiffFileEntry]) -> VerificationCertificate:
        """Run all verification checks across changed file entries and produce attestation certificate."""
        findings: list[VerificationFinding] = []
        verified_files: list[str] = []

        for entry in entries:
            verified_files.append(entry.file_path)
            findings.extend(self._verify_file_entry(entry))

        # Check required capabilities
        for cap in self.required_capabilities:
            cap_finding = cap.evaluate_finding()
            if cap_finding is not None:
                findings.append(cap_finding)

        # Derive final verdict enforcing precedence: FAIL > INCONCLUSIVE > PASS
        verdict, rationale = derive_verdict(findings)

        # Build deterministic canonical attestation payload
        payload = CanonicalAttestationPayload(
            base_commit_sha=self.base_commit_sha,
            head_commit_sha=self.head_commit_sha,
            files=tuple(verified_files),
            policy_hash=self.policy_hash,
            verdict=verdict,
            findings=tuple(findings),
        )

        digest = payload.compute_digest()

        return VerificationCertificate(
            digest=digest,
            digest_algorithm=ATTESTATION_DIGEST_DOMAIN,
            verdict=verdict,
            payload=payload,
            rationale=rationale,
            execution_metadata={
                "files_count": len(verified_files),
                "findings_count": len(findings),
            },
        )

    def _verify_file_entry(self, entry: DiffFileEntry) -> list[VerificationFinding]:
        findings: list[VerificationFinding] = []
        file_path = entry.file_path

        # 0. Path traversal validation
        if is_path_traversal(file_path) or (entry.old_file_path and is_path_traversal(entry.old_file_path)):
            finding_id = content_digest_hex(f"path_traversal:{file_path}")[:16]
            findings.append(
                VerificationFinding(
                    finding_id=finding_id,
                    rule_id="VC-POLICY-PATH-TRAVERSAL",
                    severity=Severity.CRITICAL,
                    verdict=VerificationVerdict.FAIL,
                    reason=FindingReason.POLICY_VIOLATION,
                    message=f"Path traversal detected in diff file path '{file_path}'",
                    file_path=file_path,
                )
            )
            return findings

        # 1. Non-Python added lines secret scan
        if not file_path.endswith(".py"):
            findings.extend(scan_secrets_in_source(file_path, "\n".join(entry.added_lines)))
            return findings

        # 2. Syntax validation / fragment normalization
        head_src, syntax_finding = parseable_source(file_path, entry.head_source)
        if syntax_finding is not None:
            findings.append(syntax_finding)
            return findings

        # 3. Secret and credential scanning (regex + entropy + AST taint)
        findings.extend(scan_secrets_in_source(file_path, head_src))

        # 4. Dangerous dynamic call detection
        findings.extend(scan_dangerous_calls(file_path, head_src))

        # 5. Removal provenance check
        findings.extend(verify_removal_provenance(entry, self.base_sources))

        # 6. Unresolved external imports
        findings.extend(
            check_unresolved_imports(
                file_path,
                entry.added_lines,
                is_blocking=self.block_on_unresolved_imports,
            )
        )

        # 7. Execute pluggable extension checkers with fail-closed safety
        for checker in self.extension_checkers:
            try:
                ext_findings = checker(entry, self.base_sources)
                if not isinstance(ext_findings, (list, tuple)):
                    raise TypeError(f"Extension checker returned non-sequence: {type(ext_findings).__name__}")
                for f in ext_findings:
                    if not isinstance(f, VerificationFinding):
                        raise TypeError(f"Extension finding is not VerificationFinding: {type(f).__name__}")
                    if not isinstance(f.verdict, VerificationVerdict):
                        raise ValueError(f"Extension finding has invalid verdict: {f.verdict}")
                    findings.append(f)
            except Exception as exc:
                # Extension crash or malformed result fails closed to INCONCLUSIVE, never silent PASS
                safe_exc = sanitize_message(str(exc))
                finding_id = content_digest_hex(f"ext_crash:{file_path}:{safe_exc}")[:16]
                findings.append(
                    VerificationFinding(
                        finding_id=finding_id,
                        rule_id="VC-EXTENSION-CHECKER-CRASH",
                        severity=Severity.HIGH,
                        verdict=VerificationVerdict.INCONCLUSIVE,
                        reason=FindingReason.CAPABILITY_UNAVAILABLE,
                        message=f"Extension checker failed closed on '{file_path}': {safe_exc}",
                        file_path=file_path,
                    )
                )

        return findings
