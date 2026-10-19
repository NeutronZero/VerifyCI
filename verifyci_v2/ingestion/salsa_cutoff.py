from __future__ import annotations

import ast
from typing import Any, Mapping

import msgspec

from verifyci_v2.contracts.canonical import canonical_jcs_str, content_digest_hex
from verifyci_v2.contracts.ssa_ir import CutoffEvaluation, FunctionUSSA
from verifyci_v2.ingestion.polyglot_bridge import PolyglotBridgeResolver
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa, lower_module_to_ussa
from verifyci_v2.ingestion.stack_graphs import StackGraphStitcher


ENGINE_ANALYSIS_VERSION = "vc2.3.1-phase3-5"


class IncrementalIngestionPlan(msgspec.Struct, frozen=True, kw_only=True):
    file_path: str
    evaluations: tuple[CutoffEvaluation, ...]
    functions_to_verify_locally: tuple[str, ...]
    transitive_callers_to_reverify: tuple[str, ...]
    skipped_transitive_callers: tuple[str, ...]
    type_and_taint_callers_to_reverify: tuple[str, ...] = ()
    semantic_value_callers_to_reverify: tuple[str, ...] = ()
    removed_qualified_names: tuple[str, ...] = ()
    removed_callers: tuple[tuple[str, tuple[str, ...]], ...] = ()
    removed_transitive_callers: tuple[tuple[str, tuple[str, ...]], ...] = ()
    fingerprint_changed_callers: tuple[str, ...] = ()


class SalsaIncrementalEngine:
    """Salsa-style incremental engine using compiled U-SSA and dependency fingerprints.

    A fingerprint is only used to identify reusable prior work. Callers must still
    establish that the cached verification result and its mandatory-gate receipts
    exist before skipping a gate.
    """

    def __init__(self, repo_id: str = "default-repo", *, store: Any | None = None) -> None:
        self.repo_id = repo_id
        self.store = store
        self.stitcher = StackGraphStitcher()
        self.bridge_resolver = PolyglotBridgeResolver()
        self._ussa_by_qname: dict[str, FunctionUSSA] = {}
        self._file_to_qnames: dict[str, set[str]] = {}
        self._source_by_file: dict[str, str] = {}
        self._tree_by_file: dict[str, ast.Module] = {}
        self._verification_fingerprints: dict[str, str] = {}
        if self.store is not None and hasattr(self.store, "load_verification_fingerprints"):
            try:
                self._verification_fingerprints.update(self.store.load_verification_fingerprints())
            except Exception:
                # Persistent cache corruption must cause misses, never optimistic reuse.
                self._verification_fingerprints.clear()

    def get_function_ussa(self, qualified_name: str) -> FunctionUSSA | None:
        return self._ussa_by_qname.get(qualified_name)

    def all_functions(self) -> tuple[FunctionUSSA, ...]:
        return tuple(self._ussa_by_qname[k] for k in sorted(self._ussa_by_qname))

    def _resolve_callee(self, symbol: str, functions: Mapping[str, FunctionUSSA]) -> FunctionUSSA | None:
        exact = functions.get(symbol)
        if exact is not None:
            return exact
        candidates = [fn for qn, fn in functions.items() if qn.endswith("." + symbol) or qn.split(".")[-1] == symbol]
        return candidates[0] if len(candidates) == 1 else None

    def _verification_fingerprint(
        self,
        fn: FunctionUSSA,
        *,
        functions: Mapping[str, FunctionUSSA],
        policy_digest: str,
        dependency_fingerprint: str = "",
    ) -> str:
        deps = []
        for callee_name in sorted(set(fn.call_targets)):
            callee = self._resolve_callee(callee_name, functions)
            deps.append({
                "callee": callee.qualified_name if callee else callee_name,
                "callee_h_interface": callee.h_interface if callee else "unresolved",
                # Include the full transitive reachable behavioral surface. A
                # direct-only hash lets caller A reuse its proof when A calls B,
                # B calls C, and only C changes with an unchanged B body.
                "callee_behavioral_digest": self._behavioral_digest(
                    callee.qualified_name if callee else callee_name,
                    functions=functions,
                ),
                "callee_taint_summary": msgspec.to_builtins(callee.taint_summary) if callee else None,
            })
        payload = {
            "engine_version": ENGINE_ANALYSIS_VERSION,
            "qualified_name": fn.qualified_name,
            "h_interface": fn.h_interface,
            "h_body": fn.h_body,
            "taint_summary": msgspec.to_builtins(fn.taint_summary),
            "callee_dependencies": deps,
            "policy_digest": policy_digest,
            "dependency_fingerprint": dependency_fingerprint,
        }
        return content_digest_hex(canonical_jcs_str(payload), domain="verifyci.v2.verification_fingerprint")

    def _behavioral_digest(
        self,
        qualified_name: str,
        *,
        functions: Mapping[str, FunctionUSSA],
    ) -> str:
        """Hash a function and its full reachable call dependency closure.

        Iterative closure construction handles recursion/cycles without recursion
        depth hazards. Including each reachable function's local body, interface,
        and taint summary makes a transitive callee change invalidate callers even
        when intermediate caller bodies and summaries remain unchanged.
        """
        pending = [qualified_name]
        visited: dict[str, FunctionUSSA] = {}
        unresolved_edges: set[tuple[str, str]] = set()
        while pending:
            requested = pending.pop()
            callee = self._resolve_callee(requested, functions)
            if callee is None:
                unresolved_edges.add(("<root>" if requested == qualified_name else "<dependency>", requested))
                continue
            if callee.qualified_name in visited:
                continue
            visited[callee.qualified_name] = callee
            for target in callee.call_targets:
                resolved = self._resolve_callee(target, functions)
                if resolved is None:
                    unresolved_edges.add((callee.qualified_name, target))
                else:
                    pending.append(resolved.qualified_name)
        payload = {
            "root": qualified_name,
            "reachable": [
                {
                    "qualified_name": name,
                    "h_interface": fn.h_interface,
                    "h_body": fn.h_body,
                    "taint_summary": msgspec.to_builtins(fn.taint_summary),
                }
                for name, fn in sorted(visited.items())
            ],
            "unresolved_edges": [list(item) for item in sorted(unresolved_edges)],
        }
        return content_digest_hex(
            canonical_jcs_str(payload), domain="verifyci.v2.behavioral_dependency_closure"
        )

    def _ingest_artifacts(
        self,
        *,
        file_path: str,
        source: str,
        lowered_funcs: tuple[FunctionUSSA, ...],
        tree: ast.Module | None,
        language: str,
        policy_digest: str,
        dependency_fingerprint: str,
    ) -> IncrementalIngestionPlan:
        new_qnames = {fn.qualified_name for fn in lowered_funcs}
        old_qnames = self._file_to_qnames.get(file_path, set())
        removed_qnames = tuple(sorted(old_qnames - new_qnames))
        pre_removed_callers = self.stitcher.transitive_blast_radius(removed_qnames) if removed_qnames else ()
        removed_callers = tuple(
            (qname, tuple(self.stitcher.direct_callers(qname))) for qname in removed_qnames
        )
        removed_transitive_callers = tuple(
            (qname, tuple(self.stitcher.transitive_blast_radius([qname])))
            for qname in removed_qnames
        )

        # Update graph indices from the already parsed artifact whenever available.
        self.stitcher.upsert_file(file_path, source, language=language, preparsed_tree=tree)
        self.bridge_resolver.scan_file(file_path, source, language=language, preparsed_tree=tree)
        self.bridge_resolver.resolve_bridges(self.stitcher)

        previous_functions = dict(self._ussa_by_qname)
        for qname in old_qnames:
            previous_functions.pop(qname, None)
        prospective = dict(previous_functions)
        prospective.update({fn.qualified_name: fn for fn in lowered_funcs})

        evaluations: list[CutoffEvaluation] = []
        local_verify: set[str] = set()
        interface_changed_seeds: set[str] = set(removed_qnames)
        type_taint_changed_seeds: set[str] = set(removed_qnames)
        cutoff_saved_seeds: set[str] = set()
        fingerprint_changed: set[str] = set()
        new_fps: dict[str, str] = {}

        for fn in lowered_funcs:
            old = self._ussa_by_qname.get(fn.qualified_name)
            fp = self._verification_fingerprint(
                fn, functions=prospective, policy_digest=policy_digest,
                dependency_fingerprint=dependency_fingerprint,
            )
            new_fps[fn.qualified_name] = fp
            prev_fp = self._verification_fingerprints.get(fn.qualified_name)
            if old is None:
                ev = CutoffEvaluation(
                    qualified_name=fn.qualified_name, file_path=file_path, status="NEW_FUNCTION",
                    previous_h_body=None, current_h_body=fn.h_body,
                    previous_h_interface=None, current_h_interface=fn.h_interface,
                    requires_local_verification=True, propagate_to_callers=True,
                )
            elif old.h_body == fn.h_body and old.h_interface == fn.h_interface:
                if prev_fp is not None and prev_fp != fp:
                    # Same local text but a callee/policy/analyzer dependency changed.
                    ev = CutoffEvaluation(
                        qualified_name=fn.qualified_name, file_path=file_path,
                        status="DEPENDENCY_FINGERPRINT_CHANGED",
                        previous_h_body=old.h_body, current_h_body=fn.h_body,
                        previous_h_interface=old.h_interface, current_h_interface=fn.h_interface,
                        requires_local_verification=True, propagate_to_callers=True,
                    )
                    fingerprint_changed.add(fn.qualified_name)
                else:
                    ev = CutoffEvaluation(
                        qualified_name=fn.qualified_name, file_path=file_path,
                        status="CACHE_HIT_BODY_IDENTICAL",
                        previous_h_body=old.h_body, current_h_body=fn.h_body,
                        previous_h_interface=old.h_interface, current_h_interface=fn.h_interface,
                        requires_local_verification=False, propagate_to_callers=False,
                    )
            elif old.h_interface == fn.h_interface:
                ev = CutoffEvaluation(
                    qualified_name=fn.qualified_name, file_path=file_path, status="CUTOFF_INTERFACE_INVARIANT",
                    previous_h_body=old.h_body, current_h_body=fn.h_body,
                    previous_h_interface=old.h_interface, current_h_interface=fn.h_interface,
                    requires_local_verification=True, propagate_to_callers=False,
                )
                cutoff_saved_seeds.add(fn.qualified_name)
            else:
                ev = CutoffEvaluation(
                    qualified_name=fn.qualified_name, file_path=file_path, status="PROPAGATE_INTERFACE_CHANGED",
                    previous_h_body=old.h_body, current_h_body=fn.h_body,
                    previous_h_interface=old.h_interface, current_h_interface=fn.h_interface,
                    requires_local_verification=True, propagate_to_callers=True,
                )
                interface_changed_seeds.add(fn.qualified_name)
            evaluations.append(ev)
            if old is not None and (
                old.h_interface != fn.h_interface
                or msgspec.to_builtins(old.taint_summary) != msgspec.to_builtins(fn.taint_summary)
            ):
                type_taint_changed_seeds.add(fn.qualified_name)
            if ev.requires_local_verification:
                local_verify.add(fn.qualified_name)
            if ev.propagate_to_callers:
                interface_changed_seeds.add(fn.qualified_name)

        # Commit current state only after fingerprints and invalidation seeds are computed.
        for qname in removed_qnames:
            self._ussa_by_qname.pop(qname, None)
            self._verification_fingerprints.pop(qname, None)
        self._ussa_by_qname.update({fn.qualified_name: fn for fn in lowered_funcs})
        # Do not advance the verified-result cache here. Ingestion records current
        # source/IR state, but only VerificationPipeline may certify fingerprints
        # after every required gate for the request has passed.
        self._file_to_qnames[file_path] = new_qnames
        self._source_by_file[file_path] = source
        if tree is not None:
            self._tree_by_file[file_path] = tree

        # A body's semantic change always invalidates semantic callers unless an
        # independently verified equivalence class is supplied in dependency_fingerprint.
        semantic_seeds = set(interface_changed_seeds) | set(cutoff_saved_seeds) | set(fingerprint_changed)
        type_callers = set(self.stitcher.transitive_blast_radius(interface_changed_seeds | type_taint_changed_seeds)) | set(pre_removed_callers)
        semantic_callers = set(self.stitcher.transitive_blast_radius(semantic_seeds)) | set(pre_removed_callers)
        skipped = set(self.stitcher.transitive_blast_radius(cutoff_saved_seeds)) - type_callers - local_verify

        if self.store is not None and hasattr(self.store, "record_verification_fingerprints"):
            self.store.record_verification_fingerprints(
                dict(self._verification_fingerprints), replace_all=True
            )

        return IncrementalIngestionPlan(
            file_path=file_path,
            evaluations=tuple(evaluations),
            functions_to_verify_locally=tuple(sorted(local_verify)),
            transitive_callers_to_reverify=tuple(sorted(type_callers)),
            skipped_transitive_callers=tuple(sorted(skipped)),
            type_and_taint_callers_to_reverify=tuple(sorted(type_callers)),
            semantic_value_callers_to_reverify=tuple(sorted(semantic_callers)),
            removed_qualified_names=removed_qnames,
            removed_callers=removed_callers,
            removed_transitive_callers=removed_transitive_callers,
            fingerprint_changed_callers=tuple(sorted(fingerprint_changed)),
        )

    def ingest_compiled_file(
        self,
        compiled: Any,
        *,
        policy_digest: str = "",
        dependency_fingerprint: str = "",
    ) -> IncrementalIngestionPlan:
        if compiled.reconstruction_failed or compiled.syntax_error is not None or compiled.head_ast is None:
            raise ValueError("Salsa ingestion requires a successfully reconstructed, compiled head revision")
        funcs = tuple(compiled.head_ussa.values())
        return self._ingest_artifacts(
            file_path=compiled.file_path,
            source=compiled.head_source,
            lowered_funcs=funcs,
            tree=compiled.head_ast.tree,
            language="python",
            policy_digest=policy_digest,
            dependency_fingerprint=dependency_fingerprint,
        )

    def ingest_file(
        self,
        file_path: str,
        source: str,
        *,
        language: str = "python",
        policy_digest: str = "",
        dependency_fingerprint: str = "",
    ) -> IncrementalIngestionPlan:
        """Compatibility ingest API; parses/lowers once for this standalone revision."""
        if language == "python":
            tree = ast.parse(source, filename=file_path) if source else ast.Module(body=[], type_ignores=[])
            lowered = lower_module_to_ussa(file_path, tree, source, language=language, repo_id=self.repo_id)
        else:
            tree = None
            lowered = lower_file_to_ussa(file_path, source, language=language, repo_id=self.repo_id)
        return self._ingest_artifacts(
            file_path=file_path, source=source, lowered_funcs=tuple(lowered), tree=tree,
            language=language, policy_digest=policy_digest,
            dependency_fingerprint=dependency_fingerprint,
        )

    def mark_compiled_files_verified(
        self,
        compiled_files: tuple[Any, ...],
        *,
        policy_digest: str = "",
        dependency_fingerprint: str = "",
    ) -> None:
        """Persist reusable fingerprints only after the pipeline has returned PASS."""
        functions = dict(self._ussa_by_qname)
        verified_names: set[str] = set()
        for compiled in compiled_files:
            if compiled is None or compiled.reconstruction_failed or compiled.syntax_error is not None:
                continue
            for fn in compiled.head_ussa.values():
                # Ensure this compiled artifact is still the current in-memory
                # revision; stale pipeline artifacts cannot certify newer state.
                current = functions.get(fn.qualified_name)
                if current is None or current.h_body != fn.h_body or current.h_interface != fn.h_interface:
                    continue
                fp = self._verification_fingerprint(
                    fn, functions=functions, policy_digest=policy_digest,
                    dependency_fingerprint=dependency_fingerprint,
                )
                self._verification_fingerprints[fn.qualified_name] = fp
                verified_names.add(fn.qualified_name)
        if verified_names and self.store is not None and hasattr(self.store, "record_verification_fingerprints"):
            self.store.record_verification_fingerprints(
                dict(self._verification_fingerprints), replace_all=True
            )

    def verification_fingerprint(self, qualified_name: str) -> str | None:
        return self._verification_fingerprints.get(qualified_name)

    def get_source(self, file_path: str) -> str | None:
        return self._source_by_file.get(file_path)


SalsaCutoffEngine = SalsaIncrementalEngine
SalsaCutoffPlan = IncrementalIngestionPlan
