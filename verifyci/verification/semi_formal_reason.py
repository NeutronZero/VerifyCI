"""Semi-formal reasoning: premise -> trace -> conclusion -> certificate.

Grounding rule: diff paths are partitioned according to FilePartition:
- CODE_CORE: requires CPG grounding from entities declared in changed files.
  A diff naming no files, or naming CODE_CORE files absent from the graph,
  yields inconclusive — never pass.
- DOCUMENTATION: inert fast path yields pass without requiring CPG grounding
  or execution witnesses, provided no code files were changed.
- CONFIGURATION: validated via syntax and schema parsers (TOML, YAML, JSON, INI).
  Pure configuration changes with valid syntax pass without CPG grounding;
  indeterminate multi-hunk JSON diffs yield inconclusive; invalid syntax fails.
- TEST_SUITE: evaluated under test-suite policy with execution witness extraction.

certificate_verified additionally requires every deterministic check to have passed.
"""
import time
import uuid
from dataclasses import dataclass
from typing import Any

from verifyci.contracts.verification_ir import (
    Certificate, Premise, FileEvidence, ExecutionTrace, Conclusion,
)
from verifyci.graph.traverse import CALL_FLOW_TYPES, derive_node_map, traverse
from verifyci.verification.diffmap import map_files_to_entity_ids, parse_diff_files


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


def _find_code_deletion_hunks(diff_str: str, code_files: set[str]) -> list[tuple[int, str]]:
    from verifyci.verification.diffmap import normalize_path, parse_unified_diff
    norm_code = {normalize_path(f) for f in code_files}
    hunks: list[tuple[int, str]] = []
    for f in parse_unified_diff(diff_str):
        if normalize_path(f.path) not in norm_code and f.path not in code_files:
            continue
        for h in f.hunks:
            if h.approximate:
                removed = [b.lstrip()[1:] if b.lstrip()[:1] in "-+" else b.lstrip()
                           for b in h.lines if b.lstrip().startswith("-")]
                if removed:
                    hunks.append((h.old_start, "\n".join(removed)))
                continue
            minus = [b[1:] for b in h.lines if b.startswith("-")]
            plus = sum(1 for b in h.lines if b.startswith("+"))
            if minus and len(minus) > plus:
                hunks.append((h.old_start, "\n".join(minus)))
        if f.stray_removed:
            hunks.append((0, "\n".join(f.stray_removed)))
    return hunks


def _validate_configuration_diff(diff_str: str, config_files: list[str]) -> tuple[str, str]:
    from verifyci.verification.diffmap import normalize_path, parse_unified_diff
    norm_config = {normalize_path(f) for f in config_files}
    parsed = parse_unified_diff(diff_str)
    for f in parsed:
        if normalize_path(f.path) not in norm_config and f.path not in config_files:
            continue
        new_lines: list[str] = []
        for h in f.hunks:
            for line in h.lines:
                if line.startswith(("+", " ")):
                    new_lines.append(line[1:])
        content = "\n".join(new_lines)
        if not content.strip():
            continue
        p_lower = f.path.lower()
        if p_lower.endswith(".toml"):
            import tomllib
            try:
                tomllib.loads(content)
            except Exception as e:
                if f.hunks and f.hunks[0].new_start > 1:
                    return "inconclusive", f"{f.path}: toml_fragment ({e})"
                return "fail", f"{f.path}: {e}"
        elif p_lower.endswith((".yaml", ".yml")):
            import yaml
            try:
                yaml.safe_load(content)
            except Exception as e:
                if f.hunks and f.hunks[0].new_start > 1:
                    return "inconclusive", f"{f.path}: yaml_fragment ({e})"
                return "fail", f"{f.path}: {e}"
        elif p_lower.endswith(".json"):
            import json
            try:
                json.loads(content)
            except Exception:
                try:
                    json.loads("{" + content + "}")
                except Exception:
                    try:
                        json.loads("[" + content + "]")
                    except Exception as e:
                        if len(f.hunks) > 1:
                            return "inconclusive", f"{f.path}: multi_hunk_json_configuration ({e})"
                        return "fail", f"{f.path}: {e}"
        elif p_lower.endswith((".ini", ".cfg")):
            import configparser
            import re
            try:
                cp = configparser.ConfigParser()
                cp.read_string(content)
            except Exception as e:
                if (isinstance(e, configparser.MissingSectionHeaderError)
                        and not re.search(r"(?m)^\s*\[", content)):
                    # A hunk far from any [section] header carries only
                    # `key = value` lines: not a standalone INI document,
                    # so validity is indeterminate. Decline (inconclusive),
                    # don't reject a valid change for lacking context the
                    # diff never contained.
                    return "inconclusive", f"{f.path}: headerless_ini_fragment ({e})"
                return "fail", f"{f.path}: {e}"
    return "pass", ""


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
               entities: list | None = None,
               waivers: list | None = None) -> Certificate:
        from verifyci.verification.partition import classify_path, FilePartition
        from verifyci.verification.witness import extract_execution_witnesses

        diff_str = diff if isinstance(diff, str) else str(diff or "")
        files = parse_diff_files(diff_str)
        if not files:
            det_checks = [
                DeterministicCheck(checker_id="diff_parsed", passed=False, detail="files=0"),
                DeterministicCheck(checker_id="seeds_grounded", passed=False, detail="grounded=0 ungrounded=[]"),
                DeterministicCheck(checker_id="trace_supported", passed=False, detail="paths=0"),
                DeterministicCheck(checker_id="evidence_coverage", passed=False, detail="evidence=0"),
                DeterministicCheck(checker_id="deletion_verification", passed=True, detail="deletion_hunks=0"),
            ]
            conclusion = Conclusion(result="inconclusive", reasoning="insufficient_evidence:diff_parsed,seeds_grounded,trace_supported,evidence_coverage (grounded=0 ungrounded=[])")
            return Certificate(
                certificate_id=str(uuid.uuid4()),
                premises=[],
                evidence=[],
                execution_traces=[],
                conclusion=conclusion,
                confidence=0.2,
                generated_by=self.model_name,
                checked_by=[c.checker_id for c in det_checks],
                verification_method="semi_formal_reasoning",
                certificate_verified=False,
                timestamp=time.time(),
                witnesses=(),
                waivers=(),
            )

        code_files = [f for f in files if classify_path(f) == FilePartition.CODE_CORE]
        test_files = [f for f in files if classify_path(f) == FilePartition.TEST_SUITE]
        doc_files = [f for f in files if classify_path(f) == FilePartition.DOCUMENTATION]
        config_files = [f for f in files if classify_path(f) == FilePartition.CONFIGURATION]
        waivers_list = list(waivers or [])

        if not code_files:
            premises = [
                Premise(premise_id=str(uuid.uuid4()), statement=f"file_changed:{f}", source=f)
                for f in files
            ]
            if doc_files and not test_files and not config_files:
                det_checks = [
                    DeterministicCheck(checker_id="documentation_policy", passed=True, detail=f"doc_files={len(doc_files)}"),
                ]
                conclusion = Conclusion(result="pass", reasoning="documentation_inert_change")
                return Certificate(
                    certificate_id=str(uuid.uuid4()),
                    premises=premises,
                    evidence=[],
                    execution_traces=[],
                    conclusion=conclusion,
                    confidence=1.0,
                    generated_by=self.model_name,
                    checked_by=[c.checker_id for c in det_checks],
                    verification_method="fast_path_documentation",
                    certificate_verified=True,
                    timestamp=time.time(),
                    witnesses=(),
                    waivers=tuple(waivers_list),
                )

            if config_files and not test_files and not doc_files:
                cfg_status, err = _validate_configuration_diff(diff_str, config_files)
                if cfg_status == "inconclusive":
                    det_checks = [
                        DeterministicCheck(
                            checker_id="diff_parsed",
                            passed=True,
                            detail=f"files={len(files)}",
                        ),
                        DeterministicCheck(
                            checker_id="configuration_schema_validation",
                            passed=False,
                            detail=err or "multi_hunk_json_configuration",
                        ),
                    ]
                    conclusion = Conclusion(
                        result="inconclusive",
                        reasoning=f"insufficient_evidence:configuration_schema_validation ({err})",
                    )
                    return Certificate(
                        certificate_id=str(uuid.uuid4()),
                        premises=premises,
                        evidence=[],
                        execution_traces=[],
                        conclusion=conclusion,
                        confidence=0.5,
                        generated_by=self.model_name,
                        checked_by=[c.checker_id for c in det_checks],
                        verification_method="configuration_schema_validation",
                        certificate_verified=False,
                        timestamp=time.time(),
                        witnesses=(),
                        waivers=tuple(waivers_list),
                    )
                is_valid = (cfg_status == "pass")
                det_checks = [
                    DeterministicCheck(
                        checker_id="configuration_schema_validation",
                        passed=is_valid,
                        detail=err or "syntax_valid",
                    ),
                ]
                conclusion = (
                    Conclusion(result="pass", reasoning="configuration_schema_valid")
                    if is_valid
                    else Conclusion(result="fail", reasoning=f"configuration_schema_invalid: {err}")
                )
                return Certificate(
                    certificate_id=str(uuid.uuid4()),
                    premises=premises,
                    evidence=[],
                    execution_traces=[],
                    conclusion=conclusion,
                    confidence=1.0 if is_valid else 0.0,
                    generated_by=self.model_name,
                    checked_by=[c.checker_id for c in det_checks],
                    verification_method="configuration_schema_validation",
                    certificate_verified=is_valid,
                    timestamp=time.time(),
                    witnesses=(),
                    waivers=tuple(waivers_list),
                )

            if test_files:
                cfg_status = "pass"
                config_err = ""
                if config_files:
                    cfg_status, config_err = _validate_configuration_diff(diff_str, config_files)
                witnesses = extract_execution_witnesses(
                    diff=diff_str,
                    code_files=[],
                    test_files=test_files,
                    entities=entities,
                )
                if cfg_status == "inconclusive":
                    det_checks = [
                        DeterministicCheck(checker_id="diff_parsed", passed=True, detail=f"files={len(files)}"),
                        DeterministicCheck(checker_id="seeds_grounded", passed=True, detail="no_code_core_files"),
                        DeterministicCheck(checker_id="test_suite_policy", passed=False, detail=config_err),
                    ]
                    conclusion = Conclusion(result="inconclusive", reasoning=f"insufficient_evidence:test_suite_policy ({config_err})")
                    return Certificate(
                        certificate_id=str(uuid.uuid4()),
                        premises=premises,
                        evidence=[],
                        execution_traces=[],
                        conclusion=conclusion,
                        confidence=0.5,
                        generated_by=self.model_name,
                        checked_by=[c.checker_id for c in det_checks],
                        verification_method="test_suite_policy",
                        certificate_verified=False,
                        timestamp=time.time(),
                        witnesses=tuple(witnesses),
                        waivers=tuple(waivers_list),
                    )
                config_ok = (cfg_status == "pass")
                det_checks = [
                    DeterministicCheck(checker_id="diff_parsed", passed=True, detail=f"files={len(files)}"),
                    DeterministicCheck(checker_id="seeds_grounded", passed=True, detail="no_code_core_files"),
                    DeterministicCheck(checker_id="test_suite_policy", passed=config_ok, detail=config_err or f"test_files={len(test_files)}"),
                ]
                conclusion = (
                    Conclusion(result="pass", reasoning="test_suite_only_change")
                    if config_ok
                    else Conclusion(result="fail", reasoning=f"configuration_schema_invalid: {config_err}")
                )
                return Certificate(
                    certificate_id=str(uuid.uuid4()),
                    premises=premises,
                    evidence=[],
                    execution_traces=[],
                    conclusion=conclusion,
                    confidence=1.0 if config_ok else 0.0,
                    generated_by=self.model_name,
                    checked_by=[c.checker_id for c in det_checks],
                    verification_method="test_suite_policy",
                    certificate_verified=config_ok,
                    timestamp=time.time(),
                    witnesses=tuple(witnesses),
                    waivers=tuple(waivers_list),
                )

            cfg_status = "pass"
            config_err = ""
            if config_files:
                cfg_status, config_err = _validate_configuration_diff(diff_str, config_files)
            if cfg_status == "inconclusive":
                det_checks = [
                    DeterministicCheck(checker_id="diff_parsed", passed=True, detail=f"files={len(files)}"),
                    DeterministicCheck(checker_id="non_code_policy", passed=False, detail=config_err),
                ]
                conclusion = Conclusion(result="inconclusive", reasoning=f"insufficient_evidence:non_code_policy ({config_err})")
                return Certificate(
                    certificate_id=str(uuid.uuid4()),
                    premises=premises,
                    evidence=[],
                    execution_traces=[],
                    conclusion=conclusion,
                    confidence=0.5,
                    generated_by=self.model_name,
                    checked_by=[c.checker_id for c in det_checks],
                    verification_method="non_code_policy",
                    certificate_verified=False,
                    timestamp=time.time(),
                    witnesses=(),
                    waivers=tuple(waivers_list),
                )
            config_ok = (cfg_status == "pass")
            det_checks = [
                DeterministicCheck(checker_id="diff_parsed", passed=True, detail=f"files={len(files)}"),
                DeterministicCheck(checker_id="non_code_policy", passed=config_ok, detail=config_err or "non_code_files"),
            ]
            conclusion = (
                Conclusion(result="pass", reasoning="non_code_change")
                if config_ok
                else Conclusion(result="fail", reasoning=f"configuration_schema_invalid: {config_err}")
            )
            return Certificate(
                certificate_id=str(uuid.uuid4()),
                premises=premises,
                evidence=[],
                execution_traces=[],
                conclusion=conclusion,
                confidence=1.0 if config_ok else 0.0,
                generated_by=self.model_name,
                checked_by=[c.checker_id for c in det_checks],
                verification_method="non_code_policy",
                certificate_verified=config_ok,
                timestamp=time.time(),
                witnesses=(),
                waivers=tuple(waivers_list),
            )

        code_deletion_hunks = _find_code_deletion_hunks(diff_str, set(code_files))
        config_valid = True
        config_err = ""
        if config_files:
            cfg_status, config_err = _validate_configuration_diff(diff_str, config_files)
            if cfg_status != "pass":
                config_valid = False

        witnesses = extract_execution_witnesses(
            diff=diff_str,
            code_files=code_files,
            test_files=test_files,
            entities=entities,
        )

        from verifyci.verification.deletion import evaluate_deletions
        del_ok, del_status, del_reason, _ = evaluate_deletions(
            diff=diff_str,
            code_files=code_files,
            entities=entities,
            graph=graph,
            node_map=node_map,
            witnesses=witnesses,
            waivers=waivers_list,
        )

        premises = [
            Premise(premise_id=str(uuid.uuid4()), statement=f"file_changed:{f}", source=f)
            for f in files
        ]
        node_data = self._graph_nodes(graph)
        if entities is None:
            entities = [d for d in node_data if hasattr(d, "file_path") and hasattr(d, "revision_entity_id")]
        mapping = map_files_to_entity_ids(code_files, entities)
        by_id = {getattr(e, "revision_entity_id", None): e for e in entities}
        seeds = sorted({eid for eids in mapping.values() for eid in eids})
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
                node_map = {}
        paths = self._trace_from_seeds(graph, seeds, node_map)
        evidence = self._collect_evidence(seeds, entities)
        from verifyci.contracts.evidence import EvidencePack, SourceChunk
        from verifyci.verification.evidence_verifier import verify_evidence_coverage
        _chunks = [SourceChunk(chunk_id=e.file_path, file_path=e.file_path, line_start=e.line_start, line_end=e.line_end, content=e.snippet, source_hash=e.source_hash) for e in evidence]
        _pack = EvidencePack(query='', entities=list(entities or []), relationships=[], source_chunks=_chunks, provenance=[], scores={}, retrieval_methods=[], retrieval_timestamp=0.0, graph_revision='')
        _covered = verify_evidence_coverage(_pack)
        det_checks = self._run_deterministic_checks(
            files=files,
            mapping=mapping,
            paths=paths,
            evidence=evidence,
            module_only=module_only,
            deletion_hunks=code_deletion_hunks,
            code_files=code_files,
            config_valid=config_valid,
            config_err=config_err,
            deletion_passed=del_ok,
            deletion_status=del_status,
            deletion_detail=del_reason,
        )
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
            witnesses=tuple(witnesses),
            waivers=tuple(waivers_list),
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
                                   deletion_hunks: list[tuple[int, str]] | None = None,
                                   code_files: list[str] | None = None,
                                   config_valid: bool = True,
                                   config_err: str = "",
                                   deletion_passed: bool | None = None,
                                   deletion_status: str = "",
                                   deletion_detail: str = "",
                                   ) -> list[DeterministicCheck]:
        if code_files is None:
            from verifyci.verification.partition import classify_path, FilePartition
            code_files = [f for f in files if classify_path(f) == FilePartition.CODE_CORE]
        grounded = [f for f, eids in mapping.items() if eids]
        ungrounded = [f for f in code_files if f not in grounded]
        module_only = module_only or []
        deletion_hunks = deletion_hunks or []
        seeds_ok = bool(code_files) and not ungrounded and not module_only
        detail = f"grounded={len(grounded)} ungrounded={ungrounded}"
        if module_only:
            detail += f" module_only={module_only}"
        if deletion_hunks:
            detail += f" deletion_hunks={len(deletion_hunks)}"
        checks = [
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
                passed=bool(evidence) and bool(code_files),
                detail=f"evidence={len(evidence)}",
            ),
        ]
        if deletion_passed is not None:
            checks.append(DeterministicCheck(
                checker_id="deletion_verification",
                passed=deletion_passed,
                detail=deletion_detail or ("deletion_verified" if deletion_passed else "deletion_unverified"),
            ))
        else:
            checks.append(DeterministicCheck(
                checker_id="deletion_verification",
                passed=not deletion_hunks,
                detail=f"deletion_hunks={len(deletion_hunks)}",
            ))
        if not config_valid or config_err:
            checks.append(DeterministicCheck(
                checker_id="configuration_schema_validation",
                passed=config_valid,
                detail=config_err or "syntax_valid",
            ))
        return checks

    def _derive_conclusion(self, paths: list[ExecutionTrace],
                           evidence: list[FileEvidence],
                           det_checks: list[DeterministicCheck]) -> Conclusion:
        if det_checks and all(c.passed for c in det_checks) and paths and evidence:
            return Conclusion(result="pass", reasoning="deterministic_checks_passed")
        for c in det_checks:
            if not c.passed and c.checker_id == "configuration_schema_validation":
                if "multi_hunk_json_configuration" in getattr(c, "detail", ""):
                    continue
                if "headerless_ini_fragment" in getattr(c, "detail", ""):
                    continue
                return Conclusion(result="fail", reasoning=f"configuration_schema_invalid: {c.detail}")
            if not c.passed and c.checker_id == "deletion_verification":
                if "class_3" in getattr(c, "detail", "") or "without_waiver" in getattr(c, "detail", ""):
                    return Conclusion(result="fail", reasoning=f"class_3_guard_removal_without_waiver: {c.detail}")
                if "fabricated" in getattr(c, "detail", ""):
                    return Conclusion(result="fail", reasoning=f"fabricated_deletion_provenance: {c.detail}")
        missing = [c.checker_id for c in det_checks if not c.passed] if det_checks else ["no_checks"]
        reasoning = f"insufficient_evidence:{','.join(missing)}"
        sg = next((c.detail for c in det_checks
                   if c.checker_id == "seeds_grounded" and not c.passed), "")
        if sg:
            reasoning += f" ({sg})"
        cfg = next((c.detail for c in det_checks
                    if c.checker_id == "configuration_schema_validation" and not c.passed), "")
        if cfg:
            reasoning += f" ({cfg})"
        dv = next((c for c in det_checks
                   if c.checker_id in ("deletion_verification", "no_deletion_hunks") and not c.passed), None)
        if dv:
            reasoning += f" (deletion_verification:{dv.detail})"
        return Conclusion(result="inconclusive", reasoning=reasoning)

    def _compute_confidence(self, det_checks: list[DeterministicCheck]) -> float:
        if not det_checks:
            return 0.0
        passed = sum(1 for c in det_checks if c.passed)
        return round(passed / len(det_checks), 3)
