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

from verifyci.contracts.verification_ir import (
    Certificate, Premise, FileEvidence, ExecutionTrace, Conclusion,
)
from verifyci.graph.traverse import CALL_FLOW_TYPES, derive_node_map, traverse
from verifyci.verification.diffmap import map_files_to_entity_ids, parse_diff_files, find_deletion_hunks


def _is_code_entity(entity: Any) -> bool:
    """Anything but a MODULE row. Payloads without type info (test fakes)
    count as code so unit tests exercise the grounding logic, not the guard."""
    t = getattr(entity, "type", None)
    if t is None:
        return True
    from verifyci.contracts.entity import EntityType
    if isinstance(t, EntityType):
        return t != EntityType.MODULE
    return str(t) != "MODULE"


@dataclass
class DeterministicCheck:
    checker_id: str
    passed: bool
    detail: str = ""
    is_deterministic: bool = True


class SemiFormalReasoner:
    # Default names the deterministic producer, not an LLM: every
    # production path stamped generated_by="llama3.1" on certificates
    # no model ever touched. Callers passing a real model name (an
    # LLM-assisted premise drafter, when one exists) keep working.
    def __init__(self, model_name: str = "semi_formal_reasoner", max_hops: int = 2):
        self.model_name = model_name
        self.max_hops = max_hops

    def verify(self, diff: Any, graph: Any, node_map: dict | None = None,
               entities: list | None = None) -> Certificate:
        diff_str = diff if isinstance(diff, str) else str(diff or "")
        files = parse_diff_files(diff_str)
        deletion_hunks = find_deletion_hunks(diff_str)
        premises = [
            Premise(premise_id=str(uuid.uuid4()), statement=f"file_changed:{f}", source=f)
            for f in files
        ]
        node_data = self._graph_nodes(graph)
        if entities is None:
            entities = [d for d in node_data if hasattr(d, "file_path") and hasattr(d, "revision_entity_id")]
        mapping = map_files_to_entity_ids(files, entities)
        by_id = {getattr(e, "revision_entity_id", None): e for e in entities}
        seeds = sorted({eid for eids in mapping.values() for eid in eids})
        # MODULE entities prove a file exists, not that any code in it is
        # known. A diff grounding only to MODULE rows (e.g. an enum-only
        # change, enums being unmapped) must not verify.
        code_seeds = sorted(eid for eid in seeds if _is_code_entity(by_id.get(eid)))
        module_only = sorted(
            f for f, eids in mapping.items()
            if eids and all(not _is_code_entity(by_id.get(eid)) for eid in eids)
        )
        seeds = code_seeds
        if node_map is None:
            from verifyci.graph.traverse import NodeMapError
            try:
                node_map = derive_node_map(graph)
            except NodeMapError:
                # Unreadable graph: no traces, so trace_supported fails
                # and the verdict is INCONCLUSIVE — never a crash, never
                # a pass on missing structure.
                node_map = {}
        paths = self._trace_from_seeds(graph, seeds, node_map)
        evidence = self._collect_evidence(seeds, entities)
        from verifyci.contracts.evidence import EvidencePack, SourceChunk
        from verifyci.verification.evidence_verifier import verify_evidence_coverage
        _chunks = [SourceChunk(chunk_id=e.file_path, file_path=e.file_path, line_start=e.line_start, line_end=e.line_end, content=e.snippet, source_hash=e.source_hash) for e in evidence]
        _pack = EvidencePack(query='', entities=list(entities or []), relationships=[], source_chunks=_chunks, provenance=[], scores={}, retrieval_methods=[], retrieval_timestamp=0.0, graph_revision='')
        _covered = verify_evidence_coverage(_pack)
        det_checks = self._run_deterministic_checks(
            files, mapping, paths, evidence, module_only, deletion_hunks)
        conclusion = self._derive_conclusion(paths, evidence, det_checks)
        verified = (
            bool(det_checks)
            and all(c.passed for c in det_checks)
            and bool(paths)
            and bool(evidence)
            and conclusion.result == "pass"
            and _covered
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
                                   evidence: list[FileEvidence],
                                   module_only: list[str] | None = None,
                                   deletion_hunks: list[tuple[int, str]] | None = None
                                   ) -> list[DeterministicCheck]:
        grounded = [f for f, eids in mapping.items() if eids]
        # Every named file must ground. A clean .py hunk used to launder
        # arbitrary unverified content (Dockerfile, CI workflows, .env)
        # in the same diff into a PASS; ungroundable content is now
        # inability (INCONCLUSIVE), never a free pass.
        ungrounded = [f for f in files if f not in grounded]
        module_only = module_only or []
        deletion_hunks = deletion_hunks or []
        seeds_ok = bool(files) and not ungrounded and not module_only
        detail = f"grounded={len(grounded)} ungrounded={ungrounded}"
        if module_only:
            detail += f" module_only={module_only}"
        if deletion_hunks:
            detail += f" deletion_hunks={len(deletion_hunks)}"
        return [
            DeterministicCheck(
                checker_id="diff_parsed",
                passed=bool(files),
                detail=f"files={len(files)}",
            ),
            DeterministicCheck(
                checker_id="seeds_grounded",
                passed=seeds_ok,
                detail=detail,
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
            DeterministicCheck(
                checker_id="no_deletion_hunks",
                passed=not deletion_hunks,
                detail=f"deletion_hunks={len(deletion_hunks)}",
            ),
        ]

    def _derive_conclusion(self, paths: list[ExecutionTrace],
                           evidence: list[FileEvidence],
                           det_checks: list[DeterministicCheck]) -> Conclusion:
        if det_checks and all(c.passed for c in det_checks) and paths and evidence:
            return Conclusion(result="pass", reasoning="deterministic_checks_passed")
        missing = [c.checker_id for c in det_checks if not c.passed] if det_checks else ["no_checks"]
        reasoning = f"insufficient_evidence:{','.join(missing)}"
        sg = next((c.detail for c in det_checks
                   if c.checker_id == "seeds_grounded" and not c.passed), "")
        if sg:
            reasoning += f" ({sg})"
        dh = next((c for c in det_checks
                   if c.checker_id == "no_deletion_hunks" and not c.passed), None)
        if dh:
            reasoning = "diff_contains_deletion_hunks; content-level removal verification is V1.1"
        return Conclusion(result="inconclusive", reasoning=reasoning)

    def _compute_confidence(self, det_checks: list[DeterministicCheck]) -> float:
        if not det_checks:
            return 0.0
        passed = sum(1 for c in det_checks if c.passed)
        return round(passed / len(det_checks), 3)
