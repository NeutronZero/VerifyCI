"""Gate orchestration: Git truth, policy binding, checks, and evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from hashlib import sha256
import os
import platform
import re
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from verifyci.checks import contract, deletion, grounding, security, semantic
from verifyci.checks.base import (
    CheckContext,
    budget_exhausted_result,
    error_result,
    inconclusive_gap_result,
)
from verifyci.runtime.budget import DEFAULT_BUDGET, WorkBudget
from verifyci.runtime.scheduler import run_deterministic_batch
from verifyci.contracts.manifest import (
    CHECK_ORDER,
    CHECK_SPECS,
    CACHE_SCHEMA_VERSION,
    CODE_EXTENSIONS,
    manifest_hash,
    release_summary,
    validate_manifest,
)
from verifyci.contracts.release_validation import verify_release_validation_evidence
from verifyci.contracts.model import (
    CheckResult,
    DiffEntry,
    EvidenceBundle,
    Policy,
    Tier,
    Verdict,
)
from verifyci.contracts.names import normalize_repo_path
from verifyci.contracts.reason_codes import GAPS, is_fault_code
from verifyci.evidence.bundle import build_bundle, build_payload, toolchain_fingerprint
from verifyci.contracts.canonical import canonical_json_bytes
from verifyci.gate.integrity import (
    CodeownersCoverage,
    gate_integrity,
    load_codeowners,
    policy_changed,
)
from verifyci.gate.policy import (
    BUILTIN_BOOTSTRAP_HASH,
    POLICY_PATH,
    PolicyError,
    ProposedReview,
    builtin_bootstrap_policy,
    load_policy_at,
    review_proposed_policy,
)
from verifyci.gate.verdict import aggregate, apply_acceptances, apply_waivers
from verifyci.index.cache import CacheStore
from verifyci.index.provider import CacheIntegrityMismatch, FactProvider
from verifyci.scm.git import GitError, GitRepo
from verifyci.scope.entities import ChangedScope, build_changed_scope
from verifyci.scope.repository import augment_scope_with_repository as _augment_scope_with_repository


_CHECK_RUNNERS: dict[str, Callable[[CheckContext], CheckResult]] = {
    "grounding": grounding.run,
    "deletion": deletion.run,
    "contract": contract.run,
    "semantic": semantic.run,
    "security": security.run,
}


@dataclass(frozen=True, slots=True)
class GateRequest:
    repo: str | Path
    base: str
    head: str = "HEAD"
    merge_base: str | None = None
    as_of_date: str | None = None
    review_mode: str = "fail"
    candidate_build: bool = False
    generated_at: str | None = None
    cache_mode: str = "none"
    allow_local_cache: bool = False
    cache_dir: str | None = None
    cache_key: bytes | None = None
    cache_key_id: str = "k1"
    cache_read_only: bool = False
    jobs: int = 1
    budget: WorkBudget = DEFAULT_BUDGET


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _scope_empty() -> ChangedScope:
    return ChangedScope(
        base_facts={},
        head_facts={},
        changed_entities=frozenset(),
        base_entities=frozenset(),
        head_entities=frozenset(),
    )


def validate_cache_location(repo: Path, cache_dir: str | None) -> tuple[str, str] | None:
    """Return an error tuple if an explicit cache_dir resides inside the repository working tree."""
    if cache_dir is None:
        return None
    resolved = Path(cache_dir).expanduser().resolve(strict=False)
    root = repo.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError:
        return None
    return ("invalid_cache_location", "cache directory must be outside the working tree")


@dataclass
class _GateState:
    request: GateRequest
    started: float
    as_of_date: str
    git: GitRepo | None = None
    toolchain: str = ""
    object_format: str = ""
    target_base: str = ""
    merge_base: str = ""
    head: str = ""
    entries: list[DiffEntry] = field(default_factory=list)
    integrity_paths: tuple[str, ...] = ()
    policy: Policy | None = None
    proposed: ProposedReview | None = None
    review_reasons: set[str] = field(default_factory=set)
    extra_faults: set[str] = field(default_factory=set)
    invalid_policy_detail: str = ""
    codeowners: CodeownersCoverage = field(
        default_factory=lambda: CodeownersCoverage(proven=False, reasons=("not_evaluated",))
    )
    target_drift: bool = False


def _fatal_from_state(
    state: _GateState,
    *,
    code: str,
    detail: str,
    policy: Policy | None = None,
    review_reasons: Iterable[str] | None = None,
) -> EvidenceBundle:
    return _fatal_bundle(
        request=state.request,
        git=state.git,
        code=code,
        detail=detail,
        toolchain=state.toolchain,
        object_format=state.object_format,
        as_of_date=state.as_of_date,
        review_reasons=state.review_reasons if review_reasons is None else review_reasons,
        policy=state.policy if policy is None else policy,
        entries=state.entries,
        target_base=state.target_base,
        merge_base=state.merge_base,
        head=state.head,
        started=state.started,
        integrity_paths=state.integrity_paths,
        target_drift=state.target_drift,
    )


def _assumptions(*, codeowners: CodeownersCoverage, policy: Policy) -> list[dict[str, Any]]:
    assumptions: list[dict[str, Any]] = [
        {
            "id": "required_workflow_not_verified",
            "detail": "the gate does not prove that the required workflow is protected by branch protection",
        },
        {
            "id": "branch_protection_not_verified",
            "detail": "the gate does not inspect repository branch-protection settings",
        },
        {
            "id": "target_freshness_not_verified",
            "detail": "the target ref is resolved at run time; not a linearizability proof",
        },
        {
            "id": "cache_key_isolation_not_verified",
            "detail": "cache authentication and key isolation are deployment properties",
        },
        {
            "id": "release_validation_not_established",
            "detail": "this build is an implementation candidate, not a release-validated artifact",
        },
    ]
    if not codeowners.proven:
        assumptions.append(
            {
                "id": "codeowners_coverage_missing",
                "detail": "active target-base CODEOWNERS could not be proven to cover every protected path",
                "reasons": list(codeowners.reasons),
            }
        )
    else:
        assumptions.append(
            {
                "id": "codeowners_owner_validity_not_verified",
                "detail": "CODEOWNERS rules are parsed, but owner existence and team membership are not verified",
            }
        )
    if policy.protected_guards or policy.protected_errors:
        assumptions.append(
            {
                "id": "semantic_replay_limitations",
                "detail": (
                    "solver-backed semantic findings are blocking; witness replay cannot "
                    "import modules, so traces that require imports remain unconfirmed"
                ),
            }
        )
    return assumptions


def _fatal_bundle(
    *,
    request: GateRequest,
    git: GitRepo | None,
    code: str,
    detail: str,
    toolchain: str = "",
    object_format: str = "",
    as_of_date: str = "",
    review_reasons: Iterable[str] = (),
    policy: Policy | None = None,
    entries: Sequence[DiffEntry] = (),
    target_base: str = "",
    merge_base: str = "",
    head: str = "",
    started: float | None = None,
    integrity_paths: Sequence[str] = (),
    target_drift: bool = False,
) -> EvidenceBundle:
    effective_policy = policy or builtin_bootstrap_policy()
    context = CheckContext(
        git=git,
        policy=effective_policy,
        entries=tuple(entries),
        scope=_scope_empty(),
        as_of_date=as_of_date or request.as_of_date or _today(),
        object_format=object_format,
        target_base_commit=target_base,
        merge_base_commit=merge_base,
        head_commit=head,
        toolchain_fingerprint=toolchain,
        source_roots=(),
        rename_limit_exceeded=False,
    )
    if is_fault_code(code) or code not in GAPS:
        results = [
            error_result(context=context, check_id=check_id, detail=detail, reason_code=code, diagnostic_code=code)
            for check_id in CHECK_ORDER
        ]
    else:
        # Environmental limits (oversized blobs, rename/revision limits) are not
        # internal faults: report INCONCLUSIVE with the real gap code.
        results = [
            inconclusive_gap_result(context=context, check_id=check_id, reason_code=code, detail=detail)
            for check_id in CHECK_ORDER
        ]
    verdict = aggregate(
        results,
        review_reasons=review_reasons,
        extra_faults=(code,) if is_fault_code(code) else (),
    )
    payload = _build_gate_payload(
        request=request,
        context=context,
        results=results,
        verdict=verdict,
        findings=[],
        waivers=[],
        accepted_gaps=[],
        diagnostics=[{"code": code, "detail": detail}],
        review_reasons=tuple(review_reasons),
        policy=effective_policy,
        entries=entries,
        target_base=target_base,
        merge_base=merge_base,
        head=head,
        object_format=object_format,
        integrity_paths=integrity_paths,
        codeowners=CodeownersCoverage(proven=False, reasons=("not_evaluated",)),
        proposed=None,
        target_drift=target_drift,
        review_cleared=False,
    )
    duration_ms = int((time.monotonic() - started) * 1000) if started is not None else 0
    return build_bundle(
        payload,
        generated_at=request.generated_at,
        duration_ms=duration_ms,
        cache={
            "mode": request.cache_mode,
            "authoritative": request.cache_mode != "local",
            "stats": {},
            "sampled_recomputations": [],
        },
        environment={"python": platform.python_version(), "platform": platform.system()},
    )


def _build_gate_payload(
    *,
    request: GateRequest,
    context: CheckContext,
    results: Sequence[CheckResult],
    verdict,
    findings: Sequence[Mapping[str, Any]],
    waivers: Sequence[Mapping[str, Any]],
    accepted_gaps: Sequence[Mapping[str, Any]],
    diagnostics: Sequence[Mapping[str, Any]],
    review_reasons: Sequence[str],
    policy: Policy,
    entries: Sequence[DiffEntry],
    target_base: str,
    merge_base: str,
    head: str,
    object_format: str,
    integrity_paths: Sequence[str],
    codeowners: CodeownersCoverage,
    proposed: ProposedReview | None,
    target_drift: bool,
    review_cleared: bool,
    extra_faults: Sequence[str] = (),
    is_release_validated: bool = False,
) -> dict[str, Any]:
    inputs = {
        "target_ref": request.base,
        "target_base_commit": target_base or None,
        "merge_base_commit": merge_base or None,
        "head_commit": head or None,
        "object_format": object_format or None,
        "target_drift": target_drift,
        "as_of_date": context.as_of_date,
        "changed_files": [normalize_repo_path(e.path) for e in entries if e.path],
        "files": [
            {
                "status": e.status,
                "base_path": e.base_path,
                "head_path": e.head_path,
                "base_blob": f"{object_format}:{e.base_blob}" if e.base_blob else None,
                "head_blob": f"{object_format}:{e.head_blob}" if e.head_blob else None,
                "base_mode": e.base_mode,
                "head_mode": e.head_mode,
            }
            for e in entries
        ],
    }
    pr_policy_changed = policy_changed(entries)
    policy_payload = {
        "authoritative_blob_hash": policy.blob_hash,
        "authoritative_policy_source": policy.source,
        "effective_policy_hash": policy.effective_hash,
        "proposed_policy_hash": proposed.policy.effective_hash if proposed else None,
        "proposed_blob_hash": proposed.policy.blob_hash if proposed else None,
        "proposed_policy_valid": proposed is not None,
        "pr_changed": pr_policy_changed,
        "policy_change_review": pr_policy_changed,
        "waiver_ids": sorted(policy.waivers),
        "acceptance_ids": sorted(policy.acceptances),
    }
    inputs["policy"] = policy_payload
    inputs["gate_integrity"] = {"changed_paths": list(integrity_paths)}
    scope = {
        "changed_files": len(entries),
        "changed_entities": len(context.scope.changed_entities),
        "unmapped_hunks": len(context.scope.unmapped_hunks),
        "checks": {
            result.check_id: {
                "outcome": result.outcome.value,
                "coverage": result.coverage.value,
                "evaluated_scope": dict(result.evaluated_scope),
            }
            for result in results
        },
    }
    excluded: list[dict[str, Any]] = []
    if target_drift:
        excluded.append(
            {
                "kind": "target_changes_since_merge_base",
                "detail": "merge base differs from target base; target-base policy is authoritative",
            }
        )
    for entry in entries:
        path = entry.path
        if entry.is_binary:
            excluded.append({"kind": "binary", "path": path})
        if entry.is_submodule:
            excluded.append({"kind": "submodule", "path": path})
        if entry.is_lfs:
            excluded.append(
                {
                    "kind": "lfs_content_unavailable",
                    "path": path,
                    "reason_code": "lfs_content_unavailable",
                }
            )
    for item in accepted_gaps:
        excluded.append(
            {
                "kind": "accepted_gap",
                "acceptance_id": item.get("id"),
                "check": item.get("check"),
                "reason_code": item.get("reason_code"),
                "subject": item.get("subject"),
            }
        )
    return build_payload(
        inputs=inputs,
        scope=scope,
        check_results=results,
        findings=findings,
        waivers=waivers,
        accepted_gaps=accepted_gaps,
        diagnostics=list(diagnostics)
        + [
            {"code": "review_reason", "reason_code": code}
            for code in review_reasons
        ],
        assumptions=_assumptions(codeowners=codeowners, policy=context.policy),
        excluded_scope=excluded,
        verdict=verdict,
        toolchain=context.toolchain_fingerprint,
        policy=policy_payload,
        gate_integrity={
            "changed_paths": list(integrity_paths),
            "policy_changed": pr_policy_changed,
            "codeowners": codeowners.to_dict(),
            "review_cleared": review_cleared,
            "proposed_policy_review": (
                {
                    "review_reasons": list(proposed.review_reasons),
                    "superseded_entries": sorted(proposed.superseded_entries),
                }
                if proposed
                else None
            ),
            "extra_faults": list(extra_faults),
        },
        manifest_extra={
            "release_validated": is_release_validated,
            "manifest_hash": manifest_hash(),
            "check_specs": [CHECK_SPECS[c].to_dict() for c in CHECK_ORDER],
            "builtin_policy_hashes": {"builtin_bootstrap_v1": BUILTIN_BOOTSTRAP_HASH},
            "release_summary": release_summary(),
        },
    )


_CODE_SUFFIXES = CODE_EXTENSIONS


def _safe_detail(exc: BaseException) -> str:
    """Scrub a caught exception into a safe diagnostic detail string."""
    message = str(exc)
    message = re.sub(r"[A-Za-z]:\\[^\s\"']+", "<path>", message)
    message = re.sub(r"(?<![\w])/[^\s\"']{8,}", "<path>", message)
    message = "".join(ch for ch in message if ch.isprintable() or ch in " \t")
    return f"{type(exc).__name__}: {message}".strip()[:200]


def _run_checks(
    context: CheckContext, deadline: float | None = None, jobs: int = 1
) -> list[CheckResult]:
    def _execute_check(check_id: str) -> CheckResult:
        if deadline is not None and time.monotonic() > deadline:
            return budget_exhausted_result(context, check_id)
        runner = _CHECK_RUNNERS[check_id]
        try:
            return runner(context)
        except Exception as exc:  # fail closed; preserve the traceback as a diagnostic
            return error_result(
                context=context,
                check_id=check_id,
                detail=_safe_detail(exc),
                reason_code="internal_fault",
                diagnostic_code="internal_fault",
            )

    return run_deterministic_batch(list(CHECK_ORDER), _execute_check, max_workers=jobs)


def run_gate(request: GateRequest) -> EvidenceBundle:
    started = time.monotonic()
    as_of = request.as_of_date or _today()
    try:
        date.fromisoformat(as_of)
    except ValueError:
        return _fatal_bundle(
            request=request,
            git=None,
            code="invalid_policy",
            detail=f"invalid as_of date {as_of!r}",
            started=started,
        )
    manifest_errors = validate_manifest()
    if manifest_errors:
        return _fatal_bundle(
            request=request,
            git=None,
            code="manifest_mismatch",
            detail="; ".join(manifest_errors),
            started=started,
            as_of_date=as_of,
        )
    state = _GateState(request=request, started=started, as_of_date=as_of)
    try:
        try:
            repo_path = Path(request.repo)
            if not repo_path.is_dir():
                raise GitError(
                    "invalid_repository",
                    f"repository path does not exist or is not a directory: {request.repo!r}",
                )
            state.git = GitRepo(repo_path)
            git_dir_check = state.git.run(["rev-parse", "--git-dir"])
            if git_dir_check.returncode != 0:
                classified = state.git.classify_failure(git_dir_check)
                if classified.code == "invalid_repository":
                    raise classified
                raise GitError("invalid_repository", classified.detail or f"not a git repository: {request.repo!r}")
        except GitError:
            raise
        except Exception as exc:
            raise GitError(
                "invalid_repository",
                f"failed to initialize git repository {request.repo!r}: {exc}",
            ) from exc
        git = state.git
        git_version_result = git.run(["version"])
        git_version = git_version_result.stdout.decode("utf-8", "replace").strip() if git_version_result.returncode == 0 else ""
        state.object_format = git.object_format()
        state.toolchain = toolchain_fingerprint(git_version=git_version, object_format=state.object_format)
        state.target_base = git.resolve_commit(request.base)
        state.head = git.resolve_commit(request.head)
        state.merge_base = git.merge_base(state.target_base, state.head, request.merge_base)
        state.target_drift = state.merge_base != state.target_base
        state.entries, rename_limit_exceeded = git.diff_entries(state.merge_base, state.head)
        state.integrity_paths, _policy_changed = gate_integrity(state.entries)
        if state.integrity_paths:
            state.review_reasons.add("gate_integrity_review")
        if _policy_changed:
            state.review_reasons.add("policy_change_review")
        state.codeowners = load_codeowners(git, state.target_base)[2]

        authoritative = load_policy_at(git, state.target_base)
        head_policy = git.read_path_at(state.head, POLICY_PATH)
        if authoritative is None:
            if head_policy is None:
                raise PolicyError("invalid_policy", "target base has no .verifyci/policy.toml and the PR does not add one")
            state.proposed = review_proposed_policy(
                builtin_bootstrap_policy(),
                head_policy,
                as_of_date=as_of,
            )
            state.policy = builtin_bootstrap_policy()
            state.review_reasons.update(state.proposed.review_reasons)
            state.review_reasons.add("policy_change_review")
        else:
            state.policy = authoritative
            if _policy_changed:
                if head_policy is None:
                    state.review_reasons.add("policy_change_review")
                else:
                    try:
                        state.proposed = review_proposed_policy(
                            authoritative,
                            head_policy,
                            as_of_date=as_of,
                        )
                        state.review_reasons.update(state.proposed.review_reasons)
                    except PolicyError as exc:
                        state.extra_faults.add("invalid_policy")
                        state.review_reasons.update({"policy_change_review", "gate_integrity_review"})
                        state.proposed = None
                        state.invalid_policy_detail = exc.detail
        policy = state.policy
        source_roots = tuple(policy.path_classes.get("source_roots", ())) or (".",)
        effective_cache_mode = request.cache_mode
        cache_reason: str | None = None
        if effective_cache_mode == "local" and not request.allow_local_cache:
            raise GitError("invalid_cache_location", "local cache requires --allow-local-cache")
        if effective_cache_mode == "authenticated" and not request.cache_key:
            effective_cache_mode = "none"
            cache_reason = "cache_key_unavailable"
        common_dir_result = git.run(["rev-parse", "--git-common-dir"], check=True)
        common_dir_text = common_dir_result.stdout.decode("utf-8", "replace").strip()
        common_dir = Path(common_dir_text)
        if not common_dir.is_absolute():
            common_dir = git.repo / common_dir
        cache_dir = Path(request.cache_dir).expanduser() if request.cache_dir else common_dir / "verifyci-cache" / "v3"
        if not cache_dir.is_absolute():
            cache_dir = git.repo / cache_dir
        cache_dir = cache_dir.resolve(strict=False)
        if request.cache_dir:
            if loc_err := validate_cache_location(git.repo, str(cache_dir)):
                raise GitError(loc_err[0], loc_err[1])
        remote_result = git.run(["config", "--get", "remote.origin.url"])
        remote_identity = remote_result.stdout.decode("utf-8", "replace").strip()
        repository_identity = os.environ.get("GITHUB_REPOSITORY") or remote_identity or str(common_dir.resolve(strict=False))
        namespace = sha256(
            canonical_json_bytes(
                {
                    "repository": repository_identity,
                    "key_id": request.cache_key_id,
                    "toolchain_fingerprint": state.toolchain,
                    "cache_schema_version": CACHE_SCHEMA_VERSION,
                }
            )
        ).hexdigest()
        cache_dir = cache_dir / namespace
        cache_store = CacheStore(
            cache_dir,
            mode=effective_cache_mode,
            key=request.cache_key if effective_cache_mode == "authenticated" else None,
            key_id=request.cache_key_id,
            read_only=request.cache_read_only,
        )
        fact_provider = FactProvider(cache_store)
        scope = build_changed_scope(
            state.entries,
            source_roots=source_roots,
            rename_limit_exceeded=rename_limit_exceeded,
            fact_provider=fact_provider,
            toolchain_fingerprint=state.toolchain,
            object_format=state.object_format,
            budget=request.budget,
        )
        cold = policy.gate.get("cold_deadline_seconds")
        deadline = (
            started + float(cold)
            if isinstance(cold, (int, float)) and cold > 0
            else None
        )
        scope = _augment_scope_with_repository(
            scope,
            git=git,
            base_rev=state.target_base,
            head_rev=state.head,
            source_roots=source_roots,
            fact_provider=fact_provider,
            toolchain_fingerprint=state.toolchain,
            object_format=state.object_format,
            budget=request.budget,
            jobs=request.jobs,
        )
        context = CheckContext(
            git=git,
            policy=policy,
            entries=tuple(state.entries),
            scope=scope,
            as_of_date=as_of,
            object_format=state.object_format,
            target_base_commit=state.target_base,
            merge_base_commit=state.merge_base,
            head_commit=state.head,
            toolchain_fingerprint=state.toolchain,
            source_roots=source_roots,
            rename_limit_exceeded=rename_limit_exceeded,
            budget=request.budget,
            deadline=deadline,
        )
        results = _run_checks(context, deadline, jobs=request.jobs)

        results, applied_waivers, waiver_reviews, waiver_diagnostics = apply_waivers(
            results, policy, as_of_date=as_of
        )
        state.review_reasons.update(waiver_reviews)
        results, accepted_gaps, acceptance_reviews, acceptance_diagnostics = apply_acceptances(
            results, policy, as_of_date=as_of
        )
        state.review_reasons.update(acceptance_reviews)

        is_release_validated, val_diag = verify_release_validation_evidence()
        is_candidate_unvalidated = request.candidate_build and not is_release_validated
        if is_candidate_unvalidated:
            state.review_reasons.add("candidate_build_unvalidated")

        release_faults = set()
        if not is_release_validated and not request.candidate_build:
            release_faults.add("check_not_validated")

        inconclusive_reasons = {"candidate_build_unvalidated"} if is_candidate_unvalidated else set()
        drift_mode = str(policy.gate.get("target_drift", "record"))

        verdict = aggregate(
            results,
            review_reasons=state.review_reasons,
            target_drift=state.target_drift,
            target_drift_mode=drift_mode,
            extra_faults=state.extra_faults | release_faults,
            inconclusive_reasons=inconclusive_reasons,
        )

        # Policy remediation boundary: a valid proposed policy can supersede an
        # inactive record only when the run has no unwaived finding and no
        # unaccepted coverage gap.  The proposal never suppresses here.
        if state.proposed is not None and state.proposed.superseded_entries:
            open_findings = any(
                f.disposition.value == "OPEN"
                for r in results
                if r.tier == Tier.BLOCKING
                for f in r.findings
            )
            open_gaps = any(
                not g.accepted
                for r in results
                if r.tier == Tier.BLOCKING
                for g in r.coverage_gaps
            )
            if not open_findings and not open_gaps:
                if state.proposed.review_reasons:
                    state.review_reasons.update(state.proposed.review_reasons)
                else:
                    state.review_reasons.discard("waiver_review")
                    state.review_reasons.discard("coverage_acceptance_review")
                verdict = aggregate(
                    results,
                    review_reasons=state.review_reasons,
                    target_drift=state.target_drift,
                    target_drift_mode=drift_mode,
                    extra_faults=state.extra_faults | release_faults,
                    inconclusive_reasons=inconclusive_reasons,
                )

        review_cleared = bool(
            verdict.status == Verdict.REVIEW
            and state.codeowners.proven
            and request.review_mode == "codeowners"
            and set(verdict.reason_codes) <= {"policy_change_review", "gate_integrity_review"}
        )
        all_findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for result in results:
            for finding in result.findings:
                key = finding.fingerprint or f"{finding.defect_id}:{dict(finding.subject)}"
                if key not in seen:
                    seen.add(key)
                    all_findings.append(finding.to_dict())
        diagnostics = list(waiver_diagnostics) + list(acceptance_diagnostics)
        if git.parse_warnings:
            diagnostics.append(
                {
                    "code": "diff_parse_warning",
                    "count": len(git.parse_warnings),
                    "kinds": sorted({w.get("kind", "unknown") for w in git.parse_warnings}),
                }
            )
        if not is_release_validated:
            if request.candidate_build:
                diagnostics.append(
                    {
                        "code": "candidate_build_unvalidated",
                        "detail": (
                            val_diag
                            or "release-validation artifacts are absent; running in candidate-build mode"
                        ),
                    }
                )
            else:
                diagnostics.append(
                    {
                        "code": "check_not_validated",
                        "detail": (
                            val_diag
                            or "release-validation artifacts are absent; this internal build cannot emit a normal gate verdict"
                        ),
                    }
                )
        if state.extra_faults:
            diagnostics.append(
                {
                    "code": "invalid_policy",
                    "detail": (
                        state.invalid_policy_detail
                        or "the proposed policy is invalid; authoritative policy remains in force"
                    ),
                }
            )
        payload = _build_gate_payload(
            request=request,
            context=context,
            results=results,
            verdict=verdict,
            findings=all_findings,
            waivers=applied_waivers,
            accepted_gaps=accepted_gaps,
            diagnostics=diagnostics,
            review_reasons=tuple(sorted(state.review_reasons)),
            policy=policy,
            entries=state.entries,
            target_base=state.target_base,
            merge_base=state.merge_base,
            head=state.head,
            object_format=state.object_format,
            integrity_paths=state.integrity_paths,
            codeowners=state.codeowners,
            proposed=state.proposed,
            target_drift=state.target_drift,
            review_cleared=review_cleared,
            extra_faults=tuple(sorted(state.extra_faults)),
            is_release_validated=is_release_validated,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        return build_bundle(
            payload,
            generated_at=request.generated_at,
            duration_ms=duration_ms,
            cache={
                "mode": effective_cache_mode,
                "authoritative": effective_cache_mode != "local",
                "reason": cache_reason,
                "stats": fact_provider.cache_stats(),
                "sampled_recomputations": fact_provider.cache_stats()["sampled_recomputations"],
            },
            environment={"python": platform.python_version(), "platform": platform.system()},
        )
    except CacheIntegrityMismatch as exc:
        return _fatal_from_state(
            state,
            code="cache_integrity_mismatch",
            detail=f"sampled cache entry disagreed with Git-derived recomputation: {exc.entry_key}",
        )
    except ValueError as exc:
        return _fatal_from_state(
            state,
            code="cache_key_invalid",
            detail=f"cache key validation failed: {type(exc).__name__}",
        )
    except PolicyError as exc:
        reporting_policy = state.policy
        if reporting_policy is None and exc.source:
            reporting_policy = Policy(
                raw={},
                blob_hash=exc.blob_hash,
                source=exc.source,
                effective_hash=exc.blob_hash or "",
            )
        return _fatal_from_state(
            state,
            code=exc.code,
            detail=exc.detail,
            policy=reporting_policy,
            review_reasons=(
                state.review_reasons | {"policy_change_review", "gate_integrity_review"}
                if policy_changed(state.entries)
                else state.review_reasons
            ),
        )
    except GitError as exc:
        return _fatal_from_state(state, code=exc.code, detail=exc.detail)


__all__ = ["GateRequest", "run_gate"]
