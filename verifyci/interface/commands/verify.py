from verifyci.contracts.verification_ir import VerificationPolicy
from verifyci.interface.commands import resolve_db
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
    graph, node_map, entities, resolved_revision = load_graph(
        db, revision_id or "", return_revision=True)
    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(diff=diff, graph=graph, node_map=node_map or None,
                           entities=entities or None)
    files = parse_diff_files(diff)
    checks = [build_semi_check(cert, files, entities)]
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
    return {"report_id": report.report_id, "status": decision.status,
            "rationale": decision.rationale, "revision_id": resolved_revision,
            "files": files, "changed_entities": changed}
