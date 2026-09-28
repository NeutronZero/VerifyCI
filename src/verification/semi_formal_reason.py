"""Semi-formal reasoning: premise -> trace -> conclusion -> certificate.

Grounding rule: only files named in the diff (``+++`` side) seed
verification. Premises are per changed file; traces are call-flow paths
from entities declared in those files; evidence cites those entities.
A diff naming no files, or only files absent from the graph, yields
``inconclusive`` — never ``pass``. ``certificate_verified`` additionally
requires every deterministic check to have *passed*.
"""
import time
import uuid
from dataclasses import dataclass
from typing import Any

from src.contracts.verification_ir import (
    Certificate, Premise, FileEvidence, ExecutionTrace, Conclusion,
)
from src.graph.traverse import CALL_FLOW_TYPES, derive_node_map, traverse
from src.verification.diffmap import map_files_to_entity_ids, parse_diff_files


@dataclass
class DeterministicCheck:
    checker_id: str
    passed: bool
    detail: str = ""
    is_deterministic: bool = True


class SemiFormalReasoner:
    def __init__(self, model_name: str = "llama3.1", max_hops: int = 2):
        self.model_name = model_name
        self.max_hops = max_hops

    def verify(self, diff: Any, graph: Any, node_map: dict | None = None,
               entities: list | None = None) -> Certificate:
        files = parse_diff_files(diff if isinstance(diff, str) else str(diff or ""))
        premises = [
            Premise(premise_id=str(uuid.uuid4()), statement=f"file_changed:{f}", source=f)
            for f in files
        ]
        node_data = self._graph_nodes(graph)
        if entities is None:
            entities = [d for d in node_data if hasattr(d, "file_path") and hasattr(d, "revision_entity_id")]
        mapping = map_files_to_entity_ids(files, entities)
        seeds = sorted({eid for eids in mapping.values() for eid in eids})
        if node_map is None:
            node_map = derive_node_map(graph)
        paths = self._trace_from_seeds(graph, seeds, node_map)
        evidence = self._collect_evidence(seeds, entities)
        det_checks = self._run_deterministic_checks(files, mapping, paths, evidence)
        conclusion = self._derive_conclusion(paths, evidence, det_checks)
        verified = (
            bool(det_checks)
            and all(c.passed for c in det_checks)
            and bool(paths)
            and bool(evidence)
            and conclusion.result == "pass"
        )
        return Certificate(
            certificate_id=str(uuid.uuid4()),
            premises=premises,
            evidence=evidence,
            execution_traces=paths,
            conclusion=conclusion,
            confidence=self._compute_confidence(det_checks),
            generated_by=self.model_name,
            checked_by=[c.checker_id for c in det_checks],
            verification_method="semi_formal_reasoning",
            certificate_verified=verified,
            timestamp=time.time(),
        )

    def _graph_nodes(self, graph: Any) -> list[Any]:
        if graph is None:
            return []
        nodes_fn = getattr(graph, "nodes", None)
        if not callable(nodes_fn):
            return []
        try:
            data = list(nodes_fn())
        except Exception:  # noqa: BLE001, S110
            return []
        return [d for d in data if d is not None]

    def _trace_from_seeds(self, graph: Any, seeds: list[str], node_map: dict) -> list[ExecutionTrace]:
        if graph is None or not node_map:
            return []
        reverse = {v: k for k, v in node_map.items()}
        paths = []
        for eid in seeds[:20]:
            idx = node_map.get(eid)
            if idx is None:
                continue
            paths.append(ExecutionTrace(trace_id=str(uuid.uuid4()), path=[eid], conditions=[]))
            for direction in ("incoming", "outgoing"):
                for nidx in sorted(traverse(graph, idx, direction, self.max_hops, node_map, CALL_FLOW_TYPES)):
                    paths.append(ExecutionTrace(
                        trace_id=str(uuid.uuid4()),
                        path=[eid, reverse.get(nidx, str(nidx))],
                        conditions=[],
                    ))
        return paths

    def _collect_evidence(self, seeds: list[str], entities: list) -> list[FileEvidence]:
        by_id = {getattr(e, "revision_entity_id", None): e for e in entities}
        evidence = []
        for eid in seeds:
            entity = by_id.get(eid)
            if entity is None:
                continue
            file_path = getattr(entity, "file_path", None)
            source_hash = getattr(entity, "source_hash", None)
            if not file_path or not source_hash:
                continue
            line_start = getattr(entity, "line_start", 1) or 1
            line_end = getattr(entity, "line_end", line_start) or line_start
            meta = getattr(entity, "metadata", None) or {}
            snippet = meta.get("snippet") or str(getattr(entity, "name", ""))
            evidence.append(FileEvidence(
                file_path=str(file_path), line_start=int(line_start),
                line_end=int(line_end),
                snippet=snippet[:500],
                source_hash=str(source_hash),
            ))
        return evidence

    def _run_deterministic_checks(self, files: list[str], mapping: dict,
                                  paths: list[ExecutionTrace],
                                  evidence: list[FileEvidence]) -> list[DeterministicCheck]:
        from src.ingestion.language import is_ingestible
        grounded = [f for f, eids in mapping.items() if eids]
        # Only ingestible-but-absent files veto: docs/config outside the
        # graph are legitimately ungroundable, not verification failures.
        ungrounded = [f for f in files
                      if f not in grounded and is_ingestible(f)]
        return [
            DeterministicCheck(
                checker_id="diff_parsed",
                passed=bool(files),
                detail=f"files={len(files)}",
            ),
            DeterministicCheck(
                checker_id="seeds_grounded",
                passed=bool(files) and not ungrounded,
                detail=f"grounded={len(grounded)} ungrounded={ungrounded}",
            ),
            DeterministicCheck(
                checker_id="trace_supported",
                passed=bool(paths) and all(bool(p.path) for p in paths),
                detail=f"paths={len(paths)}",
            ),
            DeterministicCheck(
                checker_id="evidence_coverage",
                passed=bool(evidence) and bool(files),
                detail=f"evidence={len(evidence)}",
            ),
        ]

    def _derive_conclusion(self, paths: list[ExecutionTrace],
                           evidence: list[FileEvidence],
                           det_checks: list[DeterministicCheck]) -> Conclusion:
        if det_checks and all(c.passed for c in det_checks) and paths and evidence:
            return Conclusion(result="pass", reasoning="deterministic_checks_passed")
        missing = [c.checker_id for c in det_checks if not c.passed] if det_checks else ["no_checks"]
        return Conclusion(result="inconclusive", reasoning=f"insufficient_evidence:{','.join(missing)}")

    def _compute_confidence(self, det_checks: list[DeterministicCheck]) -> float:
        if not det_checks:
            return 0.0
        passed = sum(1 for c in det_checks if c.passed)
        return round(passed / len(det_checks), 3)
