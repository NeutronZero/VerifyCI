"""Gate orchestration: Git truth, policy binding, checks, and evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from hashlib import sha256
import os
import platform
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from verifyci.checks import contract, deletion, grounding, security, semantic
from verifyci.checks.base import CheckContext, error_result
from verifyci.contracts.manifest import (
    CHECK_ORDER,
    CHECK_SPECS,
    RELEASE_VALIDATED,
    manifest_hash,
    release_summary,
    validate_manifest,
)
from verifyci.contracts.model import (
    CheckResult,
    Coverage,
    CoverageGap,
    DiffEntry,
    EvidenceBundle,
    Outcome,
    Policy,
    Tier,
    Verdict,
)
from verifyci.contracts.names import normalize_repo_path
from verifyci.contracts.reason_codes import is_fault_code
from verifyci.evidence.bundle import build_bundle, toolchain_fingerprint
from verifyci.evidence.canonical import canonical_json_bytes
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
from verifyci.index.cache import CACHE_SCHEMA_VERSION, CacheStore
from verifyci.index.provider import CacheIntegrityMismatch, FactProvider
from verifyci.scm.git import GitError, GitRepo
from verifyci.scope.entities import ChangedScope, analyze_source, build_changed_scope


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
    generated_at: str | None = None
    cache_mode: str = "none"
    allow_local_cache: bool = False
    cache_dir: str | None = None
    cache_key: bytes | None = None
    cache_key_id: str = "k1"
    cache_read_only: bool = False
    jobs: int = 1
    release_validated: bool = False


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


def _context(
    *,
    git: GitRepo,
    policy: Policy,
    entries: Sequence[DiffEntry],
    scope: ChangedScope,
    as_of_date: str,
    object_format: str,
    target_base: str,
    merge_base: str,
    head: str,
    toolchain: str,
    source_roots: Sequence[str],
    rename_limit_exceeded: bool,
    integrity_paths: Sequence[str],
    target_drift: bool,
) -> CheckContext:
    return CheckContext(
        git=git,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date=as_of_date,
        object_format=object_format,
        target_base_commit=target_base,
        merge_base_commit=merge_base,
        head_commit=head,
        toolchain_fingerprint=toolchain,
        source_roots=tuple(source_roots),
        rename_limit_exceeded=rename_limit_exceeded,
        gate_integrity_paths=tuple(integrity_paths),
        target_drift=target_drift,
        release_validated=False,
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
                "id": "semantic_shadow_only",
                "detail": "semantic analysis is advisory in v3.1.10 and emits no solver-backed finding",
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
    context = _context(
        git=git or GitRepo(request.repo),
        policy=effective_policy,
        entries=entries,
        scope=_scope_empty(),
        as_of_date=as_of_date or request.as_of_date or _today(),
        object_format=object_format,
        target_base=target_base,
        merge_base=merge_base,
        head=head,
        toolchain=toolchain,
        source_roots=(),
        rename_limit_exceeded=False,
        integrity_paths=integrity_paths,
        target_drift=target_drift,
    )
    results = [
        error_result(context=context, check_id=check_id, detail=detail, reason_code=code, diagnostic_code=code)
        for check_id in CHECK_ORDER
    ]
    verdict = aggregate(
        results,
        review_reasons=review_reasons,
        extra_faults=(code,) if is_fault_code(code) else (),
    )
    payload = _payload(
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


def _payload(
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
    return _payload_build(
        request=request,
        context=context,
        results=results,
        verdict=verdict,
        findings=findings,
        waivers=waivers,
        accepted_gaps=accepted_gaps,
        diagnostics=diagnostics,
        review_reasons=review_reasons,
        policy_payload=policy_payload,
        inputs=inputs,
        scope=scope,
        excluded=excluded,
        integrity_paths=integrity_paths,
        codeowners=codeowners,
        entries=entries,
        proposed=proposed,
        review_cleared=review_cleared,
        extra_faults=extra_faults,
    )


def _payload_build(
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
    policy_payload: Mapping[str, Any],
    inputs: Mapping[str, Any],
    scope: Mapping[str, Any],
    excluded: Sequence[Mapping[str, Any]],
    integrity_paths: Sequence[str],
    codeowners: CodeownersCoverage,
    entries: Sequence[DiffEntry],
    proposed: ProposedReview | None,
    review_cleared: bool,
    extra_faults: Sequence[str],
) -> dict[str, Any]:
    assumptions = _assumptions(codeowners=codeowners, policy=context.policy)
    return _build_payload(
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
        assumptions=assumptions,
        excluded_scope=excluded,
        verdict=verdict,
        toolchain=context.toolchain_fingerprint,
        policy=policy_payload,
        gate_integrity={
            "changed_paths": list(integrity_paths),
            "policy_changed": POLICY_PATH in {p for e in entries for p in e.changed_paths},
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
            "release_validated": request.release_validated or RELEASE_VALIDATED,
            "manifest_hash": manifest_hash(),
            "check_specs": [CHECK_SPECS[c].to_dict() for c in CHECK_ORDER],
            "builtin_policy_hashes": {"builtin_bootstrap_v1": BUILTIN_BOOTSTRAP_HASH},
            "release_summary": release_summary(),
        },
    )


# A small indirection keeps _payload readable while avoiding duplicate payload
# construction in the fatal path.
def _build_payload(**kwargs: Any) -> dict[str, Any]:
    from verifyci.evidence.bundle import build_payload

    return build_payload(**kwargs)


_CODE_SUFFIXES = {
    "py", "pyi", "ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts",
    "go", "rs", "java", "kt", "kts", "c", "cc", "cpp", "cxx", "h", "hpp",
    "cs", "rb", "php", "swift", "scala", "lua", "ex", "exs", "erl", "hrl",
}


def _augment_scope_with_repository(
    scope: ChangedScope,
    *,
    git: GitRepo,
    base_rev: str,
    head_rev: str,
    source_roots: Sequence[str],
    fact_provider: FactProvider | None = None,
    toolchain_fingerprint: str = "",
    object_format: str = "",
) -> ChangedScope:
    """Add repository-local facts for reference and caller discovery.

    The changed-scope map is intentionally small.  Deletion and contract
    checks also need live references and callers in unchanged files, so the
    gate materializes facts for repository code files at both endpoints.
    """
    base_facts = dict(scope.base_facts)
    head_facts = dict(scope.head_facts)
    base_blobs: dict[str, str] = {}
    for mode, obj_type, object_id, path in git.list_tree(base_rev):
        if mode == "160000" or mode == "120000" or obj_type != "blob":
            continue
        suffix = path.rsplit(".", 1)[-1].lower()
        if suffix not in _CODE_SUFFIXES:
            continue
        base_blobs[path] = object_id
        if path in base_facts:
            continue
        raw = git.read_blob(object_id)
        if b"\0" in raw:
            continue
        base_facts[path] = analyze_source(
            path,
            raw.decode("utf-8", "replace"),
            source_roots,
            fact_provider=fact_provider,
            toolchain_fingerprint=toolchain_fingerprint,
            blob_hash=f"{object_format}:{object_id}" if object_format else object_id,
        )
    for mode, obj_type, object_id, path in git.list_tree(head_rev):
        if mode == "160000" or mode == "120000" or obj_type != "blob":
            continue
        suffix = path.rsplit(".", 1)[-1].lower()
        if suffix not in _CODE_SUFFIXES or path in head_facts:
            continue
        if base_blobs.get(path) == object_id and path in base_facts:
            head_facts[path] = base_facts[path]
            continue
        raw = git.read_blob(object_id)
        if b"\0" in raw:
            continue
        head_facts[path] = analyze_source(
            path,
            raw.decode("utf-8", "replace"),
            source_roots,
            fact_provider=fact_provider,
            toolchain_fingerprint=toolchain_fingerprint,
            blob_hash=f"{object_format}:{object_id}" if object_format else object_id,
        )
    base_entities = frozenset(
        entity.qname for facts in base_facts.values() for entity in facts.entities
    )
    head_entities = frozenset(
        entity.qname for facts in head_facts.values() for entity in facts.entities
    )
    return ChangedScope(
        base_facts=base_facts,
        head_facts=head_facts,
        changed_entities=scope.changed_entities,
        base_entities=base_entities,
        head_entities=head_entities,
        unmapped_hunks=scope.unmapped_hunks,
        rename_limit_exceeded=scope.rename_limit_exceeded,
        mapped_hunks=scope.mapped_hunks,
        mapped_entities=scope.mapped_entities,
        renames=scope.renames,
    )


def _run_checks(context: CheckContext, deadline: float | None = None) -> list[CheckResult]:
    results: list[CheckResult] = []
    for check_id in CHECK_ORDER:
        if deadline is not None and time.monotonic() > deadline:
            spec = CHECK_SPECS[check_id]
            results.append(
                CheckResult(
                    check_id=check_id,
                    check_version=spec.check_version,
                    tier=spec.tier,
                    maturity=spec.maturity,
                    outcome=Outcome.INCONCLUSIVE,
                    coverage=Coverage.PARTIAL,
                    evaluated_scope={},
                    scope_enumeration={"complete": False},
                    candidate_discovery={"complete": False},
                    applicability_evidence={},
                    method=spec.method,
                    method_version=spec.method_version,
                    reason_codes=("budget_exhausted",),
                    coverage_gaps=(
                        CoverageGap(
                            reason_code="budget_exhausted",
                            subject={"check_id": check_id},
                        ),
                    ),
                    diagnostics=({"code": "budget_exhausted", "detail": "cold/warm deadline elapsed"},),
                    toolchain_fingerprint=context.toolchain_fingerprint,
                )
            )
            continue
        runner = _CHECK_RUNNERS[check_id]
        try:
            result = runner(context)
        except Exception as exc:  # fail closed; preserve the traceback as a diagnostic
            result = error_result(
                context=context,
                check_id=check_id,
                detail=f"{type(exc).__name__}: {exc}",
                reason_code="internal_fault",
                diagnostic_code="internal_fault",
            )
        results.append(result)
    return results


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
    git = GitRepo(request.repo)
    toolchain = ""
    object_format = ""
    target_base = merge_base = head = ""
    entries: list[DiffEntry] = []
    integrity_paths: tuple[str, ...] = ()
    policy: Policy | None = None
    proposed: ProposedReview | None = None
    review_reasons: set[str] = set()
    extra_faults: set[str] = set()
    invalid_policy_detail = ""
    codeowners = CodeownersCoverage(proven=False, reasons=("not_evaluated",))
    target_drift = False
    try:
        git_version_result = git.run(["version"])
        git_version = git_version_result.stdout.decode("utf-8", "replace").strip() if git_version_result.returncode == 0 else ""
        object_format = git.object_format()
        toolchain = toolchain_fingerprint(git_version=git_version, object_format=object_format)
        target_base = git.resolve_commit(request.base)
        head = git.resolve_commit(request.head)
        merge_base = git.merge_base(target_base, head, request.merge_base)
        target_drift = merge_base != target_base
        entries, rename_limit_exceeded = git.diff_entries(merge_base, head)
        integrity_paths, _policy_changed = gate_integrity(entries)
        if integrity_paths:
            review_reasons.add("gate_integrity_review")
        if _policy_changed:
            review_reasons.add("policy_change_review")
        codeowners = load_codeowners(git, target_base)[2]

        authoritative = load_policy_at(git, target_base)
        head_policy = git.read_path_at(head, POLICY_PATH)
        if authoritative is None:
            if head_policy is None:
                raise PolicyError("invalid_policy", "target base has no .verifyci/policy.toml and the PR does not add one")
            try:
                proposed = review_proposed_policy(
                    builtin_bootstrap_policy(),
                    head_policy,
                    as_of_date=as_of,
                )
                policy = builtin_bootstrap_policy()
                review_reasons.update(proposed.review_reasons)
                review_reasons.add("policy_change_review")
            except PolicyError:
                raise
        else:
            policy = authoritative
            if _policy_changed:
                if head_policy is None:
                    review_reasons.add("policy_change_review")
                else:
                    try:
                        proposed = review_proposed_policy(
                            authoritative,
                            head_policy,
                            as_of_date=as_of,
                        )
                        review_reasons.update(proposed.review_reasons)
                    except PolicyError as exc:
                        extra_faults.add("invalid_policy")
                        review_reasons.update({"policy_change_review", "gate_integrity_review"})
                        proposed = None
                        invalid_policy_detail = exc.detail
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
            try:
                cache_dir.relative_to(git.repo.resolve(strict=False))
            except ValueError:
                pass
            else:
                raise GitError("invalid_cache_location", "cache directory must be outside the working tree")
        remote_result = git.run(["config", "--get", "remote.origin.url"])
        remote_identity = remote_result.stdout.decode("utf-8", "replace").strip()
        repository_identity = os.environ.get("GITHUB_REPOSITORY") or remote_identity or str(common_dir.resolve(strict=False))
        namespace = sha256(
            canonical_json_bytes(
                {
                    "repository": repository_identity,
                    "key_id": request.cache_key_id,
                    "toolchain_fingerprint": toolchain,
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
            entries,
            source_roots=source_roots,
            rename_limit_exceeded=rename_limit_exceeded,
            fact_provider=fact_provider,
            toolchain_fingerprint=toolchain,
            object_format=object_format,
        )
        scope = _augment_scope_with_repository(
            scope,
            git=git,
            base_rev=target_base,
            head_rev=head,
            source_roots=source_roots,
            fact_provider=fact_provider,
            toolchain_fingerprint=toolchain,
            object_format=object_format,
        )
        context = _context(
            git=git,
            policy=policy,
            entries=entries,
            scope=scope,
            as_of_date=as_of,
            object_format=object_format,
            target_base=target_base,
            merge_base=merge_base,
            head=head,
            toolchain=toolchain,
            source_roots=source_roots,
            rename_limit_exceeded=rename_limit_exceeded,
            integrity_paths=integrity_paths,
            target_drift=target_drift,
        )
        cold = policy.gate.get("cold_deadline_seconds")
        deadline = started + float(cold) if isinstance(cold, (int, float)) and cold > 0 else None
        results = _run_checks(context, deadline)

        results, applied_waivers, waiver_reviews, waiver_diagnostics = apply_waivers(
            results, policy, as_of_date=as_of
        )
        review_reasons.update(waiver_reviews)
        results, accepted_gaps, acceptance_reviews, acceptance_diagnostics = apply_acceptances(
            results, policy, as_of_date=as_of
        )
        review_reasons.update(acceptance_reviews)

        is_release_validated = request.release_validated or RELEASE_VALIDATED
        verdict = aggregate(
            results,
            review_reasons=review_reasons,
            target_drift=target_drift,
            target_drift_mode=str(policy.gate.get("target_drift", "record")),
            extra_faults=(
                extra_faults
                | ({"check_not_validated"} if not is_release_validated else set())
            ),
        )

        # Policy remediation boundary: a valid proposed policy can supersede an
        # inactive record only when the run has no unwaived finding and no
        # unaccepted coverage gap.  The proposal never suppresses here.
        if proposed is not None and proposed.superseded_entries:
            open_findings = [
                f
                for r in results
                if r.tier == Tier.BLOCKING
                for f in r.findings
                if f.disposition.value == "OPEN"
            ]
            open_gaps = [
                g
                for r in results
                if r.tier == Tier.BLOCKING
                for g in r.coverage_gaps
                if not g.accepted
            ]
            if not open_findings and not open_gaps:
                # If the proposed policy still contains stale records, keep
                # their review reasons.  Otherwise the renewal/removal wins.
                if proposed.review_reasons:
                    review_reasons.update(proposed.review_reasons)
                else:
                    review_reasons.discard("waiver_review")
                    review_reasons.discard("coverage_acceptance_review")
                verdict = aggregate(
                    results,
                    review_reasons=review_reasons,
                    target_drift=target_drift,
                    target_drift_mode=str(policy.gate.get("target_drift", "record")),
                    extra_faults=(
                        extra_faults
                        | ({"check_not_validated"} if not is_release_validated else set())
                    ),
                )

        review_cleared = bool(
            verdict.status == Verdict.REVIEW
            and codeowners.proven
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
        if not is_release_validated:
            diagnostics.append(
                {
                    "code": "check_not_validated",
                    "detail": "release-validation artifacts are absent; this internal build cannot emit a normal gate verdict",
                }
            )
        if extra_faults:
            diagnostics.append(
                {
                    "code": "invalid_policy",
                    "detail": (
                        invalid_policy_detail
                        or "the proposed policy is invalid; authoritative policy remains in force"
                    ),
                }
            )
        payload = _payload(
            request=request,
            context=context,
            results=results,
            verdict=verdict,
            findings=all_findings,
            waivers=applied_waivers,
            accepted_gaps=accepted_gaps,
            diagnostics=diagnostics,
            review_reasons=tuple(sorted(review_reasons)),
            policy=policy,
            entries=entries,
            target_base=target_base,
            merge_base=merge_base,
            head=head,
            object_format=object_format,
            integrity_paths=integrity_paths,
            codeowners=codeowners,
            proposed=proposed,
            target_drift=target_drift,
            review_cleared=review_cleared,
            extra_faults=tuple(sorted(extra_faults)),
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
        return _fatal_bundle(
            request=request,
            git=git,
            code="cache_integrity_mismatch",
            detail=f"sampled cache entry disagreed with Git-derived recomputation: {exc.entry_key}",
            toolchain=toolchain,
            object_format=object_format,
            as_of_date=as_of,
            review_reasons=review_reasons,
            policy=policy,
            entries=entries,
            target_base=target_base,
            merge_base=merge_base,
            head=head,
            started=started,
            integrity_paths=integrity_paths,
            target_drift=target_drift,
        )
    except PolicyError as exc:
        return _fatal_bundle(
            request=request,
            git=git,
            code=exc.code,
            detail=exc.detail,
            toolchain=toolchain,
            object_format=object_format,
            as_of_date=as_of,
            review_reasons=(
                review_reasons | {"policy_change_review", "gate_integrity_review"}
                if policy_changed(entries)
                else review_reasons
            ),
            policy=policy,
            entries=entries,
            target_base=target_base,
            merge_base=merge_base,
            head=head,
            started=started,
            integrity_paths=integrity_paths,
            target_drift=target_drift,
        )
    except GitError as exc:
        return _fatal_bundle(
            request=request,
            git=git,
            code=exc.code,
            detail=exc.detail,
            toolchain=toolchain,
            object_format=object_format,
            as_of_date=as_of,
            review_reasons=review_reasons,
            policy=policy,
            entries=entries,
            target_base=target_base,
            merge_base=merge_base,
            head=head,
            started=started,
            integrity_paths=integrity_paths,
            target_drift=target_drift,
        )


__all__ = ["GateRequest", "run_gate"]
