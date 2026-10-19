from __future__ import annotations

import difflib
from typing import Any

from verifyci_v2.contracts.ai_protocol import GenerativeSynthesizerProtocol
from verifyci_v2.contracts.attestation import CandidateFix, VerificationFinding
from verifyci_v2.contracts.redaction import redact_secrets
from verifyci_v2.ingestion.compile_context import CompiledFilePair, compile_file_pair
from verifyci_v2.neural.adapters import DeterministicSynthesizerAdapter
from verifyci_v2.pipeline import DiffFileEntry, VerificationPipeline
from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver, _evaluate_concrete_divergence, _z3_mod


class CEGISAutoRepairEngine:
    """Counterexample-guided patch candidate generator with full gate re-verification.

    A verified repair is metadata attached to the original finding. It never changes
    the verdict for the unpatched request.
    """

    def __init__(
        self,
        synthesizer: GenerativeSynthesizerProtocol | None = None,
        prover: Z3SymbolicProver | None = None,
        max_rounds: int = 3,
    ) -> None:
        self.synthesizer = synthesizer or DeterministicSynthesizerAdapter()
        self.prover = prover or Z3SymbolicProver()
        self.max_rounds = max_rounds

    def repair_finding(
        self,
        *,
        file_path: str | None = None,
        base_source: str | None = None,
        head_source: str | None = None,
        finding: VerificationFinding,
        target_qualified_name: str,
        compiled_file: CompiledFilePair | None = None,
        pipeline: VerificationPipeline | None = None,
    ) -> VerificationFinding:
        if finding.verdict != "FAIL" or finding.witness is None or _z3_mod is None:
            return finding
        if compiled_file is None:
            if file_path is None or base_source is None or head_source is None:
                return finding
            compiled_file = compile_file_pair(
                DiffFileEntry.from_sources(file_path, base_source, head_source),
                repo_id=pipeline.repo_id if pipeline else "default-repo",
            )
        file_path = compiled_file.file_path
        base_source = compiled_file.base_source if base_source is None else base_source
        head_source = compiled_file.head_source if head_source is None else head_source
        if compiled_file.reconstruction_failed or compiled_file.syntax_error is not None:
            return finding
        func_base = compiled_file.base_ussa.get(target_qualified_name)
        base_fn_node = (
            compiled_file.base_ast.functions_by_qname.get(target_qualified_name)
            if compiled_file.base_ast is not None else None
        )
        if func_base is None or base_fn_node is None:
            return finding

        # Candidate source is generated from a fresh/redacted source buffer. Each
        # candidate revision is compiled once and its artifacts are reused by proof
        # and full-pipeline verification.
        candidate_src = redact_secrets(head_source).redacted_text
        for attempt in range(1, max(1, self.max_rounds) + 1):
            proposed_src = self.synthesizer.synthesize_patch(
                file_path=file_path,
                original_source=candidate_src,
                rule_id=finding.rule_id,
                counterexample_assignments=dict(finding.witness.input_assignments),
                attempt=attempt,
            )
            candidate_repo_id = pipeline.repo_id if pipeline is not None else "default-repo"
            candidate_entry = DiffFileEntry.from_sources(file_path, base_source, proposed_src)
            candidate_compiled = compile_file_pair(
                candidate_entry,
                stored_source=None,
                repo_id=candidate_repo_id,
            )
            if candidate_compiled.syntax_error is not None or candidate_compiled.reconstruction_failed:
                candidate_src = proposed_src
                continue
            func_cand = candidate_compiled.head_ussa.get(target_qualified_name)
            cand_fn_node = (
                candidate_compiled.head_ast.functions_by_qname.get(target_qualified_name)
                if candidate_compiled.head_ast is not None else None
            )
            if func_cand is None or cand_fn_node is None:
                candidate_src = proposed_src
                continue

            candidate_pipeline = self._candidate_pipeline(
                pipeline, file_path, base_source, candidate_compiled=candidate_compiled
            )
            proof = self.prover.prove_equivalence(
                func_base=func_base,
                func_cand=func_cand,
                base_fn_node=base_fn_node,
                cand_fn_node=cand_fn_node,
            )
            if getattr(proof, "outcome", None) != "PROVEN_EQUIVALENT_UNSAT":
                candidate_src = proposed_src
                continue

            witness_diverges = _evaluate_concrete_divergence(
                base_src=base_source,
                head_src=proposed_src,
                fn_name=target_qualified_name.split(".")[-1],
                params=func_base.parameters,
                witness_inputs=finding.witness.input_assignments,
            )
            if witness_diverges is not False:
                candidate_src = proposed_src
                continue

            # Re-run every mandatory gate under the active request's policy. The
            # candidate is evaluated against the exact original base contents.
            candidate_result = candidate_pipeline.verify_files(
                [candidate_entry], compiled_overrides={file_path: candidate_compiled}
            )
            if candidate_result.status != "PASS":
                candidate_src = proposed_src
                continue

            diff_lines = list(difflib.unified_diff(
                head_source.splitlines(keepends=True),
                proposed_src.splitlines(keepends=True),
                fromfile=f"a/{file_path}", tofile=f"b/{file_path}",
            ))
            verified_fix = CandidateFix(
                file_path=file_path,
                start_line=func_cand.start_line,
                end_line=func_cand.end_line,
                replacement_text=proposed_src,
                unified_diff="".join(diff_lines),
                z3_verified_unsat=True,
            )
            return VerificationFinding(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                severity=finding.severity,
                verdict="FAIL",  # Original, unpatched input remains failing.
                file_path=finding.file_path,
                start_line=finding.start_line,
                end_line=finding.end_line,
                message=finding.message,
                witness=finding.witness,
                fixes=(*finding.fixes, verified_fix),
            )
        return finding

    @staticmethod
    def _candidate_pipeline(
        active: VerificationPipeline | None,
        file_path: str,
        base_source: str,
        *,
        candidate_compiled: CompiledFilePair | None = None,
    ) -> VerificationPipeline:
        if active is None:
            return VerificationPipeline(base_sources={file_path: base_source})

        base_sources = dict(active.base_sources)
        # An immutable stored baseline wins over a caller-supplied mismatch.
        base_sources.setdefault(file_path, base_source)
        isolated_salsa = None
        active_salsa = active.salsa_engine
        if active_salsa is not None and candidate_compiled is not None:
            from verifyci_v2.ingestion.salsa_cutoff import SalsaIncrementalEngine

            isolated_salsa = SalsaIncrementalEngine(repo_id=active_salsa.repo_id, store=None)
            sources = dict(active_salsa._source_by_file)
            trees = dict(active_salsa._tree_by_file)
            file_qnames = {path: set(names) for path, names in active_salsa._file_to_qnames.items()}
            functions = {
                qname: fn for qname, fn in active_salsa._ussa_by_qname.items()
                if fn.file_path != file_path
            }
            # Replace this file's active revision with the candidate compilation.
            sources[file_path] = candidate_compiled.head_source
            if candidate_compiled.head_ast is not None:
                trees[file_path] = candidate_compiled.head_ast.tree
            else:
                trees.pop(file_path, None)
            file_qnames[file_path] = set(candidate_compiled.head_ussa)
            functions.update(candidate_compiled.head_ussa)
            isolated_salsa._source_by_file = sources
            isolated_salsa._tree_by_file = trees
            isolated_salsa._file_to_qnames = file_qnames
            isolated_salsa._ussa_by_qname = functions
            isolated_salsa._verification_fingerprints = {
                name: fp for name, fp in active_salsa._verification_fingerprints.items()
                if name in functions
            }
            for path, source in sorted(sources.items()):
                file_functions = [fn for fn in functions.values() if fn.file_path == path]
                language = file_functions[0].language if file_functions else (
                    "python" if path.endswith((".py", ".pyi")) else "unknown"
                )
                tree = trees.get(path)
                isolated_salsa.stitcher.upsert_file(
                    path, source, language=language, preparsed_tree=tree
                )
                isolated_salsa.bridge_resolver.scan_file(
                    path, source, language=language, preparsed_tree=tree
                )
            isolated_salsa.bridge_resolver.resolve_bridges(isolated_salsa.stitcher)

        return VerificationPipeline(
            repo_id=active.repo_id,
            smt_timeout_ms=active.smt_timeout_ms,
            base_sources=base_sources,
            salsa_engine=isolated_salsa,
            # Never share the durable store for speculative candidate runs.
            cpg_store=None,
            intent_text=active.intent_text,
            contracts=tuple(active.contracts),
            wasm_sandbox=active.wasm_sandbox,
            policy_digest=active.policy_digest,
        )

