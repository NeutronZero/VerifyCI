from verifyci.contracts.verification_ir import VerificationPolicy
from verifyci.interface.commands import InfraError, open_for_read, resolve_db
from verifyci.interface.commands.graph_loader import load_graph
from verifyci.verification.blast_radius import blast_radius_check
from verifyci.verification.config import load_repo_invariants
from verifyci.verification.diffmap import parse_diff_files, seed_entities_for_diff
from verifyci.verification.intent_align import evaluate_invariants
from verifyci.verification.policy import PolicyEvaluator
from verifyci.verification.removal import removal_provenance_check
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
    graph, node_map, entities, resolved_revision = load_graph(
        db, revision_id or "", return_revision=True)
    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(diff=diff, graph=graph, node_map=node_map or None,
                           entities=entities or None)
    files = parse_diff_files(diff)
    checks = [build_semi_check(cert, files, entities, diff=diff)]
    mapping = seed_entities_for_diff(files, entities, diff)
    changed = sorted({eid for eids in mapping.values() for eid in eids})
    blast, blast_check = blast_radius_check(
        graph=graph, changed_entities=changed, test_entities=set(), node_map=node_map or None)
    checks.append(blast_check)
    checks.append(removal_provenance_check(diff, entities or []))
    inv_checks, _metrics = evaluate_invariants(
        diff, load_repo_invariants(db), graph, evidence=list(cert.evidence))
    checks.extend(inv_checks)
    report = build_verification_report(task_id=task_id, policy_id="default", checks=checks, blast_radius=blast)
    policy = VerificationPolicy(
        policy_id="default", on_failure="block", on_inconclusive="human_review",
        on_human_review="block", require_deterministic_checker=True,
    )
    decision = PolicyEvaluator().evaluate(report, policy)
    if infra_error and decision.status == "INCONCLUSIVE":
        # The gate could not conclude AND could not read its store:
        # report the real cause instead of letting a broken database
        # hide behind "nothing grounded". FAIL/HUMAN_REVIEW/PASS are
        # left alone — they are real verdicts the diff text earned.
        return {"report_id": report.report_id, "status": "INFRA_ERROR",
                "error": infra_error,
                "rationale": f"storage_unavailable:{infra_error}",
                "revision_id": resolved_revision,
                "files": files, "changed_entities": changed}
    return {"report_id": report.report_id, "status": decision.status,
            "rationale": decision.rationale, "revision_id": resolved_revision,
            "files": files, "changed_entities": changed}
