from verifyci.contracts.verification_ir import VerificationPolicy
from verifyci.interface.commands import InfraError, open_for_read, resolve_db
from verifyci.interface.commands.graph_loader import load_graph
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
               db_path: str | None = None) -> dict:
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
            return {
                "report_id": "",
                "status": "FAIL",
                "rationale": "invalid_invariants_config",
                "revision_id": resolved_revision,
                "files": files,
                "changed_entities": [],
            }
    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(diff=diff, graph=graph, node_map=node_map or None,
                           entities=entities or None, waivers=waivers)
    files = parse_diff_files(diff)
    checks = [build_semi_check(cert, files, entities, diff=diff)]
    mapping = seed_entities_for_diff(files, entities, diff)
    changed = sorted({eid for eids in mapping.values() for eid in eids})
    blast, blast_check = blast_radius_check(
        graph=graph, changed_entities=changed, test_entities=set(), node_map=node_map or None)
    checks.append(blast_check)
    checks.append(removal_provenance_check(diff, entities or []))
    checks.append(return_statement_check(diff))
    checks.append(call_target_check(diff))
    checks.append(call_semantics_check(diff))
    inv_checks, _metrics = evaluate_invariants(
        diff, invariants, graph, evidence=list(cert.evidence))
    checks.extend(inv_checks)
    report = build_verification_report(task_id=task_id, policy_id="default", checks=checks, blast_radius=blast)
    policy = VerificationPolicy(
        policy_id="default", on_failure="block", on_inconclusive="human_review",
        on_human_review="block", require_deterministic_checker=True,
    )
    decision = PolicyEvaluator().evaluate(report, policy)
    policy_modified = any(is_policy_file(f) for f in files)
    if infra_error:
        if decision.status == "FAIL":
            # Explicit contract: diff-intrinsic security/contract violation preempts
            # infrastructure error to guarantee fail-closed security gating (exit 1),
            # while explicitly recording that an infrastructure failure co-occurred.
            return {"report_id": report.report_id, "status": "FAIL",
                    "rationale": decision.rationale,
                    "infra_error": infra_error,
                    "contract": "security_violation_preempts_infra_error",
                    "revision_id": resolved_revision,
                    "files": files, "changed_entities": changed}
        # Required verification substrate failure dominates over PASS,
        # INCONCLUSIVE, and HUMAN_REVIEW — missing/broken storage must NEVER return PASS.
        return {"report_id": report.report_id, "status": "INFRA_ERROR",
                "error": infra_error,
                "rationale": f"storage_unavailable:{infra_error}",
                "revision_id": resolved_revision,
                "files": files, "changed_entities": changed}

    if policy_modified:
        if decision.status == "FAIL":
            # Invariant violation under trusted base configuration preempts; fails closed.
            return {"report_id": report.report_id, "status": "FAIL",
                    "rationale": decision.rationale, "revision_id": resolved_revision,
                    "files": files, "changed_entities": changed}
        # Base-Ref Policy Integrity: gate configuration was modified in the diff;
        # policy changes cannot be silently accepted and require explicit human review.
        return {"report_id": report.report_id, "status": "HUMAN_REVIEW",
                "rationale": "unverified_policy_change: gate configuration modified in diff",
                "revision_id": resolved_revision,
                "files": files, "changed_entities": changed}

    return {"report_id": report.report_id, "status": decision.status,
            "rationale": decision.rationale, "revision_id": resolved_revision,
            "files": files, "changed_entities": changed}
