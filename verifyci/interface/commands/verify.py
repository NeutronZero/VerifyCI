import hashlib
from typing import Any

from verifyci.contracts.canonical import effective_policy_bundle_hash, report_hash
from verifyci.contracts.verification_ir import (
    CheckSummary,
    EvidenceManifestEntry,
    VerificationEnvelope,
    VerificationPolicy,
)
from verifyci.interface.commands import InfraError, open_for_read, resolve_db, resolve_repository
from verifyci.interface.commands.graph_loader import load_graph
from verifyci.interface.limits import ExecutionBudget, TIMEOUT_PROFILE_CLI
from verifyci.verification.blast_radius import blast_radius_check
from verifyci.verification.config import (
    is_policy_file,
    load_trusted_base_invariants,
    load_trusted_base_waivers,
)
from verifyci.verification.diffmap import parse_diff_files, seed_entities_for_diff
from verifyci.verification.intent_align import evaluate_invariants
from verifyci.verification.policy import PolicyEvaluator
from verifyci.verification.removal import removal_provenance_check
from verifyci.verification.return_swap import return_statement_check
from verifyci.verification.call_swap import call_target_check
from verifyci.verification.call_semantics import call_semantics_check
from verifyci.verification.semi_formal_reason import SemiFormalReasoner
from verifyci.verification.verification_ir import build_semi_check, build_verification_report


def run_verify(diff: str, revision_id: str = "", task_id: str = "cli_verify",
               db_path: str | None = None, return_artifacts: bool = False,
               signing_key: Any | None = None, signing_key_id: str | None = None,
               policy: VerificationPolicy | None = None,
               budget: ExecutionBudget | None = None) -> dict:
    from verifyci.interface.ingress import IngressValidationError, validate_diff_ingress
    try:
        diff = validate_diff_ingress(diff)
    except IngressValidationError as exc:
        res = {
            "report_id": "",
            "status": "INFRA_ERROR",
            "rationale": f"ingress_refusal:{exc.code}",
            "revision_id": revision_id,
            "files": [],
            "changed_entities": [],
            "error": exc.code,
        }
        if return_artifacts:
            res["certificate"] = None
            res["report"] = None
            res["decision"] = None
            res["policy"] = None
            res["envelope"] = None
        return res

    budget = budget or ExecutionBudget.create(timeout_seconds=TIMEOUT_PROFILE_CLI)
    try:
        budget.check_deadline()
    except Exception:
        res = {
            "report_id": "",
            "status": "INFRA_ERROR",
            "rationale": "verification_budget_deadline_exceeded",
            "revision_id": revision_id,
            "files": [],
            "changed_entities": [],
            "error": "timeout",
            "envelope": None,
        }
        if return_artifacts:
            res["certificate"] = None
            res["report"] = None
            res["decision"] = None
            res["policy"] = None
        return res

    from verifyci.graph.traverse import TraversalBudgetExceededError
    from verifyci.interface.limits import BudgetExceededError

    try:
        db = resolve_db(db_path)

        # Storage availability is its own axis, checked without ever
        # suppressing a diff-intrinsic verdict: a forbidden pattern or secret
        # the diff TEXT reveals (forbid_call, secrets_scan) needs no graph and
        # must still FAIL even when the DB is missing, locked, or corrupt —
        # fail-closed outranks a tidy exit code. The store being broken is
        # only reported as INFRA_ERROR when the gate otherwise could not
        # conclude (INCONCLUSIVE), so infrastructure never masquerades as
        # that verdict — a valid-but-empty DB still earns INCONCLUSIVE (it is
        # readable; it simply grounds nothing).
        infra_error: str | None = None
        try:
            probe = open_for_read(db)
            try:
                if revision_id and not probe.execute(
                        "SELECT 1 FROM revisions WHERE revision_id = ?",
                        (revision_id,)).fetchone():
                    infra_error = "revision_not_found"
            finally:
                probe.close()
        except InfraError as e:
            infra_error = e.kind
        if infra_error and infra_error in ("db_not_found", "db_locked", "db_unreadable"):
            graph, node_map, entities, resolved_revision = None, {}, [], ""
            invariants = load_trusted_base_invariants(None, diff=diff)
            waivers = []
        else:
            try:
                budget.check_deadline()
                graph, node_map, entities, resolved_revision = load_graph(
                    db, revision_id or "", return_revision=True)
            except InfraError as e:
                # The probe passed but the load itself failed (locked/corrupt
                # mid-read, WAL-mode on a sealed mount): same infrastructure
                # axis, recorded the same way. A concrete FAIL the diff text
                # already earned (forbidden call, secret) still stands below —
                # fail-closed outranks a tidy exit code.
                infra_error = infra_error or e.kind
                graph, node_map, entities, resolved_revision = None, {}, [], ""
            try:
                invariants = load_trusted_base_invariants(db, diff=diff)
                waivers = load_trusted_base_waivers(db, diff=diff)
            except ValueError:
                files = parse_diff_files(diff)
                res = {
                    "report_id": "",
                    "status": "FAIL",
                    "rationale": "invalid_invariants_config",
                    "revision_id": resolved_revision,
                    "files": files,
                    "changed_entities": [],
                    "envelope": None,
                }
                if return_artifacts:
                    res["certificate"] = None
                    res["report"] = None
                    res["decision"] = None
                    res["policy"] = None
                return res

        budget.check_deadline()
        reasoner = SemiFormalReasoner(signing_key=signing_key, signing_key_id=signing_key_id)
        cert = reasoner.verify(diff=diff, graph=graph, node_map=node_map or None,
                               entities=entities or None, waivers=waivers)
        files = parse_diff_files(diff)
        checks = [build_semi_check(cert, files, entities, diff=diff)]
        mapping = seed_entities_for_diff(files, entities, diff)
        changed = sorted({eid for eids in mapping.values() for eid in eids})

        from verifyci.verification.partition import FilePartition, classify_path
        test_entities = None
        if entities is not None and graph is not None:
            test_entities = {
                e.revision_entity_id for e in entities
                if classify_path(e.file_path) == FilePartition.TEST_SUITE
            }

        blast, blast_check = blast_radius_check(
            graph=graph, changed_entities=changed, test_entities=test_entities,
            node_map=node_map or None, budget=budget)
        checks.append(blast_check)
        checks.append(removal_provenance_check(diff, entities or []))
        checks.append(return_statement_check(diff))
        checks.append(call_target_check(diff))
        checks.append(call_semantics_check(diff))
        from verifyci.verification.guard_inversion import guard_condition_check
        from verifyci.verification.import_resolution import import_resolution_check
        checks.append(guard_condition_check(diff))
        checks.append(import_resolution_check(diff))
        inv_evidence = list(cert.evidence)
        if not inv_evidence and cert.premises and all(classify_path(f) in (FilePartition.CONFIGURATION, FilePartition.TEST_SUITE) for f in files):
            inv_evidence = [p.statement for p in cert.premises]
        inv_checks, _metrics = evaluate_invariants(
            diff, invariants, graph, evidence=inv_evidence)
        checks.extend(inv_checks)

        report = build_verification_report(task_id=task_id, policy_id="default", checks=checks, blast_radius=blast)
        effective_policy = policy if policy is not None else VerificationPolicy(
            policy_id="default", on_failure="block", on_inconclusive="human_review",
            on_human_review="block", require_deterministic_checker=True,
        )
        decision = PolicyEvaluator().evaluate(report, effective_policy)
        policy_modified = any(is_policy_file(f) for f in files)

        contract_flag: str | None = None
        if infra_error:
            if decision.status == "FAIL":
                verdict = "FAIL"
                rationale = decision.rationale
                final_status = "FAIL"
                contract_flag = "security_violation_preempts_infra_error"
            else:
                verdict = "INFRA_ERROR"
                rationale = f"storage_unavailable:{infra_error}"
                final_status = "INFRA_ERROR"
        elif policy_modified:
            if decision.status == "FAIL":
                verdict = "FAIL"
                rationale = decision.rationale
                final_status = "FAIL"
            else:
                verdict = "HUMAN_REVIEW"
                rationale = "unverified_policy_change: gate configuration modified in diff"
                final_status = "HUMAN_REVIEW"
        else:
            verdict = decision.status
            rationale = decision.rationale
            final_status = decision.status

        repo_id = resolve_repository(db) or "verifyci"
        manifest_entries = []
        if cert:
            manifest_entries.append(
                EvidenceManifestEntry(
                    role="certificate",
                    identity=cert.certificate_id,
                    content_hash=cert.content_hash(),
                )
            )
        check_summaries = tuple(
            CheckSummary(
                check_id=c.check_id,
                passed=bool(c.passed),
                blocking=bool(c.blocking),
                established=bool(c.established),
                score=float(c.score),
                evidence_count=len(c.evidence),
            )
            for c in report.checks
        )
        diff_hash = hashlib.sha256(diff.encode("utf-8")).hexdigest()
        eff_policy_hash = effective_policy_bundle_hash(
            policy=effective_policy,
            invariants=invariants,
            waivers=waivers,
        )
        envelope = VerificationEnvelope(
            envelope_version="1.0",
            report_id=report.report_id,
            report_hash=report_hash(report),
            verdict=verdict,
            rationale=rationale,
            repository_id=repo_id,
            revision_id=resolved_revision,
            source_commit_id=resolved_revision,
            diff_hash=diff_hash,
            effective_policy_bundle_hash=eff_policy_hash,
            evidence_manifest=tuple(manifest_entries),
            check_summaries=check_summaries,
            created_at=decision.timestamp,
            verifier_build_id="verifyci-0.1.0",
        )
        from verifyci.env import get_env
        resolved_signing_key = signing_key or get_env("SIGNING_KEY")
        resolved_key_id = signing_key_id or get_env("SIGNING_KEY_ID")
        if resolved_signing_key:
            try:
                envelope = envelope.sign(resolved_signing_key, key_id=resolved_key_id)
            except Exception:
                pass

        res = {
            "report_id": report.report_id,
            "status": final_status,
            "rationale": rationale,
            "revision_id": resolved_revision,
            "files": files,
            "changed_entities": changed,
            "envelope": envelope,
        }
        if infra_error:
            if contract_flag:
                res["infra_error"] = infra_error
                res["contract"] = contract_flag
            else:
                res["error"] = infra_error

        if return_artifacts:
            res["certificate"] = cert
            res["report"] = report
            res["decision"] = decision
            res["policy"] = effective_policy

        return res

    except (BudgetExceededError, TraversalBudgetExceededError) as exc:
        res = {
            "report_id": "",
            "status": "INFRA_ERROR",
            "rationale": f"verification_budget_deadline_exceeded:{exc}",
            "revision_id": resolved_revision if "resolved_revision" in locals() else revision_id,
            "files": files if "files" in locals() else parse_diff_files(diff),
            "changed_entities": [],
            "error": "timeout",
            "envelope": None,
        }
        if return_artifacts:
            res["certificate"] = None
            res["report"] = None
            res["decision"] = None
            res["policy"] = None
        return res

