from typing import Any

from verifyci.contracts.task_ir import NodeResult


class VerificationBlocker(Exception):
    def __init__(self, report, decision):
        self.report = report
        self.decision = decision
        super().__init__(f"verification_failed:{decision.status}")


class HumanReviewRequired(Exception):
    def __init__(self, report, decision):
        self.report = report
        self.decision = decision
        super().__init__(f"human_review_required:{decision.status}")


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _payload_entities(graph: Any) -> list:
    nodes_fn = getattr(graph, "nodes", None)
    if graph is None or not callable(nodes_fn):
        return []
    try:
        return [d for d in nodes_fn()
                if hasattr(d, "file_path") and hasattr(d, "revision_entity_id")]
    except Exception:  # noqa: BLE001, S110
        return []


class Executor:
    async def execute_node(self, node: Any, context: Any) -> NodeResult:
        from verifyci.observability.tracing import start_agent_span

        step_id = _get(node, "step_id", "unknown") or "unknown"
        conversation_id = _get(context, "conversation_id", "") or ""
        with start_agent_span(f"node.{step_id}", conversation_id, "node.execute"):
            result = NodeResult(step_id=step_id, status="COMPLETED", output=None)
            pre_hook = _get(node, "pre_commit_hook_id", None)
            if not pre_hook:
                return result

            from verifyci.verification.verification_ir import (
                build_semi_check, build_verification_report,
            )
            from verifyci.verification.policy import PolicyEvaluator
            from verifyci.verification.semi_formal_reason import SemiFormalReasoner
            from verifyci.verification.intent_align import evaluate_invariants
            from verifyci.verification.blast_radius import blast_radius_check
            from verifyci.verification.defaults import default_invariants
            from verifyci.verification.diffmap import parse_diff_files, seed_entities_for_diff
            from verifyci.verification.removal import removal_provenance_check
            from verifyci.contracts.verification_ir import (
                VerificationPolicy,
            )

            graph = _get(context, "graph", None)
            node_config = _get(node, "config", {}) or {}
            diff = (
                _get(result, "diff", None)
                or (node_config.get("diff") if isinstance(node_config, dict) else _get(node_config, "diff", None))
                or _get(context, "diff", "")
                or ""
            )
            task_id = _get(context, "task_id", "") or "unknown"
            tests = set(_get(context, "test_entities", []) or [])
            invariants = list(_get(context, "invariants", []) or []) or default_invariants()
            node_map = _get(context, "node_map", None)
            graph_entities = list(_get(context, "entities", []) or []) or _payload_entities(graph)

            changed = list(_get(context, "changed_entities", []) or [])
            if not changed and diff:
                files = parse_diff_files(diff)
                mapping = seed_entities_for_diff(files, graph_entities, diff)
                changed = sorted({eid for eids in mapping.values() for eid in eids})

            reasoner = SemiFormalReasoner()
            cert = reasoner.verify(diff=diff, graph=graph, node_map=node_map,
                                   entities=graph_entities or None)

            checks = [build_semi_check(
                cert, parse_diff_files(diff), graph_entities)]

            blast, blast_check = blast_radius_check(
                graph=graph, changed_entities=changed, test_entities=tests,
                dependency_graph=_get(context, "dependency_graph", None),
                vuln_cache=_get(context, "vuln_cache", None),
                node_map=node_map,
            )
            checks.append(blast_check)
            checks.append(removal_provenance_check(diff, graph_entities))

            if invariants:
                inv_checks, _metrics = evaluate_invariants(
                    diff, invariants, graph, evidence=list(cert.evidence), node_map=node_map)
                checks.extend(inv_checks)

            report = build_verification_report(
                task_id=str(task_id), policy_id="default",
                checks=checks, blast_radius=blast,
            )
            evaluator = PolicyEvaluator()
            policy = VerificationPolicy(
                policy_id="default",
                on_failure="block",
                on_inconclusive="human_review",
                on_human_review="block",
                require_deterministic_checker=True,
            )
            decision = evaluator.evaluate(report, policy)

            if decision.status == "FAIL":
                raise VerificationBlocker(report, decision)
            if decision.status in ("HUMAN_REVIEW", "INCONCLUSIVE"):
                raise HumanReviewRequired(report, decision)

            import dataclasses
            return dataclasses.replace(result, decision=decision)
