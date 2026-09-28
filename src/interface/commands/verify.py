from src.contracts.verification_ir import CheckResult, VerificationPolicy
from src.interface.commands import resolve_db
from src.interface.commands.graph_loader import load_graph
from src.verification.blast_radius import blast_radius_check
from src.verification.diffmap import map_files_to_entity_ids, parse_diff_files
from src.verification.intent_align import evaluate_invariants
from src.verification.policy import PolicyEvaluator
from src.verification.semi_formal_reason import SemiFormalReasoner
from src.verification.verification_ir import build_verification_report


def run_verify(diff: str, revision_id: str = "", task_id: str = "cli_verify",
               db_path: str | None = None) -> dict:
    db = resolve_db(db_path)
    graph, node_map, entities = load_graph(db, revision_id or "")
    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(diff=diff, graph=graph, node_map=node_map or None,
                           entities=entities or None)
    checks = [CheckResult(
        check_id="semi_formal", passed=cert.certificate_verified, score=cert.confidence,
        evidence=[e.file_path for e in cert.evidence],
        explanation=cert.conclusion.reasoning, certificate=cert,
    )]
    files = parse_diff_files(diff)
    mapping = map_files_to_entity_ids(files, entities)
    changed = sorted({eid for eids in mapping.values() for eid in eids})
    blast, blast_check = blast_radius_check(
        graph=graph, changed_entities=changed, test_entities=set(), node_map=node_map or None)
    checks.append(blast_check)
    inv_checks, _metrics = evaluate_invariants(
        diff, _default_invariants(), graph, evidence=list(cert.evidence))
    checks.extend(inv_checks)
    report = build_verification_report(task_id=task_id, policy_id="default", checks=checks, blast_radius=blast)
    policy = VerificationPolicy(
        policy_id="default", on_failure="block", on_inconclusive="human_review",
        on_human_review="block", require_deterministic_checker=True,
    )
    decision = PolicyEvaluator().evaluate(report, policy)
    return {"report_id": report.report_id, "status": decision.status,
            "rationale": decision.rationale, "revision_id": revision_id,
            "files": files, "changed_entities": changed}


def _default_invariants():
    from src.contracts.verification_ir import Invariant
    return [
        Invariant(invariant_id="secrets_scan", rule="no hardcoded secrets",
                  compiled_query="secrets_scan", blocking=True),
        Invariant(invariant_id="provenance_check", rule="claims traceable to files",
                  compiled_query="provenance_check", blocking=False),
    ]
