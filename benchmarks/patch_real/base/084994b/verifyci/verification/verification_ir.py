import time
import uuid

from verifyci.contracts.verification_ir import (
    VerificationReport, CheckResult, BlastRadiusResult,
)


def build_semi_check(cert, files: list[str], entities: list,
                     diff: str | None = None) -> CheckResult:
    """Build the semi-formal CheckResult, appending a suffix-grounding
    ambiguity note when one diff path matched entities under several stored
    paths. Single shared constructor so the tripwire can't rot in one of
    the three call sites (executor, MCP, CLI).

    Suffix-only grounding is weaker than exact-path grounding: when a
    diff file grounds but no stored entity carries its exact normalized
    path (or several stored paths collide on it), the check reports
    established=False, so policy routes to INCONCLUSIVE — a
    suffix-grounded diff can decline, never PASS.

    A file whose content the diff does not carry (binary, or mode-only)
    is the same inability class: when it shares a diff with groundable
    text, the text half must not earn a PASS that hides the unreadable
    half. established=False here makes the mixed text+binary case route
    to INCONCLUSIVE rather than PASS. (diff=None callers — legacy unit
    tests — skip the check; the production call sites pass it.)
    """
    from verifyci.verification.diffmap import (
        find_ambiguous_files, map_files_to_entity_ids, normalize_path,
        uninspectable_files,
    )
    explanation = cert.conclusion.reasoning
    ambiguous = find_ambiguous_files(files, entities or [])
    if ambiguous:
        details = ", ".join(f"{f} ({len(p)} paths)" for f, p in sorted(ambiguous.items()))
        explanation = f"{explanation}; suffix-ambiguous grounding: {details}"
    ent_paths = {normalize_path(getattr(e, "file_path", "") or "")
                 for e in entities or []}
    try:
        mapping = map_files_to_entity_ids(files, entities or [])
    except Exception:  # noqa: BLE001
        mapping = {}
    suffix_only = sorted(
        f for f in files
        if mapping.get(f) and normalize_path(f) not in ent_paths
    )
    if suffix_only:
        explanation = (f"{explanation}; suffix-only grounding "
                       f"(no exact stored path): {', '.join(suffix_only)}")
    opaque: list[str] = []
    if diff is not None:
        opaque = sorted(uninspectable_files(diff))
        if opaque:
            explanation = (f"{explanation}; opaque change (content not in "
                           f"diff): {', '.join(opaque)}")
    established = not ambiguous and not suffix_only and not opaque
    return CheckResult(
        check_id="semi_formal",
        passed=cert.certificate_verified,
        score=cert.confidence,
        evidence=[e.file_path for e in cert.evidence],
        explanation=explanation,
        established=established,
        # The certificate travels with the check so policy can tell
        # inability (unverified cert → INCONCLUSIVE) from rejection
        # (failed check on a verified cert → FAIL). Without it every
        # grounding failure read as a rejection.
        certificate=cert,
    )


def build_verification_report(
    task_id: str,
    policy_id: str,
    checks: list[CheckResult],
    blast_radius: BlastRadiusResult,
) -> VerificationReport:
    return VerificationReport(
        report_id=str(uuid.uuid4()),
        task_id=task_id,
        policy_id=policy_id,
        checks=checks,
        blast_radius=blast_radius,
        timestamp=time.time(),
    )
