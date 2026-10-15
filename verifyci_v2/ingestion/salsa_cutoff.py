from __future__ import annotations

from dataclasses import dataclass

from verifyci_v2.contracts.ssa_ir import CutoffEvaluation, FunctionUSSA
from verifyci_v2.ingestion.polyglot_bridge import PolyglotBridgeResolver
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.ingestion.stack_graphs import StackGraphStitcher


@dataclass(frozen=True, slots=True)
class IncrementalIngestionPlan:
    file_path: str
    evaluations: tuple[CutoffEvaluation, ...]
    functions_to_verify_locally: tuple[str, ...]
    transitive_callers_to_reverify: tuple[str, ...]
    skipped_transitive_callers: tuple[str, ...]
    type_and_taint_callers_to_reverify: tuple[str, ...] = ()
    semantic_value_callers_to_reverify: tuple[str, ...] = ()


class SalsaIncrementalEngine:
    """
    Implements the VerifyCI v2 Salsa-style demand-driven incremental query engine.
    Tracks H_body(f) and H_interface(f) per function to cut off downstream blast-radius
    invalidation when a private body edit preserves the function's external contract.
    """

    def __init__(self, repo_id: str = "default-repo") -> None:
        self.repo_id = repo_id
        self.stitcher = StackGraphStitcher()
        self.bridge_resolver = PolyglotBridgeResolver()
        self._ussa_by_qname: dict[str, FunctionUSSA] = {}
        self._file_to_qnames: dict[str, set[str]] = {}

    def get_function_ussa(self, qualified_name: str) -> FunctionUSSA | None:
        return self._ussa_by_qname.get(qualified_name)

    def all_functions(self) -> tuple[FunctionUSSA, ...]:
        return tuple(
            self._ussa_by_qname[k] for k in sorted(self._ussa_by_qname.keys())
        )

    def evaluate_function_mutation(self, new_func: FunctionUSSA) -> CutoffEvaluation:
        """Evaluates the 3-Case Salsa Early-Cutoff state machine for a single function."""
        prev = self._ussa_by_qname.get(new_func.qualified_name)
        if prev is None:
            return CutoffEvaluation(
                qualified_name=new_func.qualified_name,
                file_path=new_func.file_path,
                status="NEW_FUNCTION",
                previous_h_body=None,
                current_h_body=new_func.h_body,
                previous_h_interface=None,
                current_h_interface=new_func.h_interface,
                requires_local_verification=True,
                propagate_to_callers=True,
            )

        # Case 1: H_body(f) == H_body(f') AND H_interface(f) == H_interface(f') -> Whitespace/comment-only edit (O(1) cache hit)
        if prev.h_body == new_func.h_body and prev.h_interface == new_func.h_interface:
            return CutoffEvaluation(
                qualified_name=new_func.qualified_name,
                file_path=new_func.file_path,
                status="CACHE_HIT_BODY_IDENTICAL",
                previous_h_body=prev.h_body,
                current_h_body=new_func.h_body,
                previous_h_interface=prev.h_interface,
                current_h_interface=new_func.h_interface,
                requires_local_verification=False,
                propagate_to_callers=False,
            )

        # Case 2: H_body(f) != H_body(f') AND H_interface(f) == H_interface(f') -> Early Cutoff!
        if prev.h_interface == new_func.h_interface:
            return CutoffEvaluation(
                qualified_name=new_func.qualified_name,
                file_path=new_func.file_path,
                status="CUTOFF_INTERFACE_INVARIANT",
                previous_h_body=prev.h_body,
                current_h_body=new_func.h_body,
                previous_h_interface=prev.h_interface,
                current_h_interface=new_func.h_interface,
                requires_local_verification=True,
                propagate_to_callers=False,
            )

        # Case 3: H_interface(f) != H_interface(f') -> Propagate invalidation to Callers+(f)
        return CutoffEvaluation(
            qualified_name=new_func.qualified_name,
            file_path=new_func.file_path,
            status="PROPAGATE_INTERFACE_CHANGED",
            previous_h_body=prev.h_body,
            current_h_body=new_func.h_body,
            previous_h_interface=prev.h_interface,
            current_h_interface=new_func.h_interface,
            requires_local_verification=True,
            propagate_to_callers=True,
        )

    def ingest_file(
        self,
        file_path: str,
        source: str,
        *,
        language: str = "python",
    ) -> IncrementalIngestionPlan:
        """
        Incrementally updates StackGraphs, lowers functions to U-SSA, links polyglot bridges,
        and computes the exact set of functions requiring local vs. transitive re-verification.
        """
        lowered_funcs = lower_file_to_ussa(
            file_path,
            source,
            language=language,
            repo_id=self.repo_id,
        )

        new_qnames = {fn.qualified_name for fn in lowered_funcs}
        old_qnames = self._file_to_qnames.get(file_path, set())
        removed_qnames = sorted(old_qnames - new_qnames)

        # Pre-compute transitive callers of removed functions before re-indexing
        pre_removed_callers = self.stitcher.transitive_blast_radius(removed_qnames) if removed_qnames else ()

        self.stitcher.upsert_file(file_path, source, language=language)
        self.bridge_resolver.scan_file(file_path, source, language=language)
        self.bridge_resolver.resolve_bridges(self.stitcher)

        evaluations: list[CutoffEvaluation] = []
        local_verify: list[str] = []
        interface_changed_seeds: list[str] = []
        cutoff_saved_seeds: list[str] = []

        # Any deleted function in the file triggers caller propagation
        for removed_qname in removed_qnames:
            interface_changed_seeds.append(removed_qname)
            self._ussa_by_qname.pop(removed_qname, None)

        for fn in lowered_funcs:
            eval_res = self.evaluate_function_mutation(fn)
            evaluations.append(eval_res)
            self._ussa_by_qname[fn.qualified_name] = fn

            if eval_res.requires_local_verification:
                local_verify.append(fn.qualified_name)
            if eval_res.propagate_to_callers:
                interface_changed_seeds.append(fn.qualified_name)
            elif eval_res.status == "CUTOFF_INTERFACE_INVARIANT":
                cutoff_saved_seeds.append(fn.qualified_name)

        self._file_to_qnames[file_path] = new_qnames

        type_and_taint_callers = tuple(sorted(set(self.stitcher.transitive_blast_radius(interface_changed_seeds)) | set(pre_removed_callers)))
        semantic_seeds = sorted(set(interface_changed_seeds) | set(cutoff_saved_seeds))
        semantic_value_callers = tuple(sorted(set(self.stitcher.transitive_blast_radius(semantic_seeds)) | set(pre_removed_callers)))

        potentially_affected_by_cutoff = set(
            self.stitcher.transitive_blast_radius(cutoff_saved_seeds)
        )
        skipped_callers = tuple(
            sorted(potentially_affected_by_cutoff - set(type_and_taint_callers) - set(local_verify))
        )

        return IncrementalIngestionPlan(
            file_path=file_path,
            evaluations=tuple(evaluations),
            functions_to_verify_locally=tuple(sorted(local_verify)),
            transitive_callers_to_reverify=type_and_taint_callers,
            skipped_transitive_callers=skipped_callers,
            type_and_taint_callers_to_reverify=type_and_taint_callers,
            semantic_value_callers_to_reverify=semantic_value_callers,
        )


SalsaCutoffEngine = SalsaIncrementalEngine
SalsaCutoffPlan = IncrementalIngestionPlan