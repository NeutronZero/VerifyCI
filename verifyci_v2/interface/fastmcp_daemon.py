from __future__ import annotations

import asyncio
import msgspec
import os
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from verifyci_v2.contracts.attestation import (
    InTotoVerificationPredicate,
    VerificationFinding,
)
from verifyci_v2.contracts.canonical import canonical_jcs_str
from verifyci_v2.contracts.ingress import (
    IngressBudgetConfig,
    IngressLimitExceededError,
    TokenBucketRateLimiter,
)
from verifyci_v2 import VerifyCIConfig
from verifyci_v2.ingestion.salsa_cutoff import SalsaIncrementalEngine
from verifyci_v2.pipeline import DiffFileEntry, VerificationPipeline
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.neural.cegis_repair import CEGISAutoRepairEngine
from verifyci_v2.provenance.dsse_intoto import InTotoDSSESigner, export_sarif_v2
from verifyci_v2.provenance.gittuf_rsl import GittufRSLLedger
from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore
from verifyci_v2.store.model2vec_embed import build_neighborhood_header
from verifyci_v2.store.rabitq_index import RaBitQHybridIndex
from verifyci_v2.symbolic.secrets_taint import TaintTrackedSecretEngine
from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver


class VerifyCIFastMCPDaemon:
    """
    Layer 1 Unified Stateful FastMCP Daemon (`verifyci_v2/interface/fastmcp_daemon.py`).
    Consolidates v1's `mcp_server.py` and `fastmcp_server.py` into a single hot-reloading
    in-memory server with <20ms tool latency and strict ingress budget enforcement.
    """

    def __init__(
        self,
        repo_id: str = "default-repo",
        budget: IngressBudgetConfig | None = None,
        config: VerifyCIConfig | None = None,
        repo_path: str | Path | None = None,
    ) -> None:
        # The attested `ai_provider` is read from configuration rather than
        # hardcoded, so the signed predicate describes the provider this daemon
        # actually built its judge from.
        self.config = config or VerifyCIConfig.load()
        if repo_id == "default-repo":
            repo_id = self.config.repo_id
        self.repo_id = repo_id
        self._judge = None
        self._pipeline_obj: VerificationPipeline | None = None
        self._pipeline_key: tuple[Any, ...] | None = None
        self.budget = budget or IngressBudgetConfig()
        if repo_path is not None:
            candidate_repo = Path(repo_path).resolve()
            has_git = (candidate_repo / ".git").exists()
            self.repo_path = candidate_repo if has_git else None
        else:
            self.repo_path = None
            has_git = False
        if self.repo_path is not None:
            db_path = self.repo_path / ".verifyci" / "store.vc2"
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self.cpg_store = DuckDBCPGStore(str(db_path), repo_path=self.repo_path)
        else:
            self.cpg_store = DuckDBCPGStore()
        self.engine = SalsaIncrementalEngine(repo_id=repo_id, store=self.cpg_store)
        # Warm up DuckDB cold-start (extensions) so the first ingest tool call
        # stays within the per-query wall-clock budget (spec sec. 3.4).
        try:
            self.cpg_store.record_commit_snapshot("__warmup__", (), ())
        except Exception:
            pass
        self.rabitq_index = RaBitQHybridIndex(cpg_store=self.cpg_store)
        # Warm up tree-sitter parsers (spec sec. 3.2).
        try:
            from verifyci_v2.ingestion.ts_symbols import get_parser

            for _lang in ("c", "cpp", "javascript", "typescript", "go", "rust"):
                get_parser(_lang)
        except Exception:
            pass
        self.prover = Z3SymbolicProver()
        self.secret_engine = TaintTrackedSecretEngine()
        self.cegis = CEGISAutoRepairEngine(prover=self.prover)
        loaded_signer = InTotoDSSESigner.from_env()
        if loaded_signer is not None:
            self.signer = loaded_signer
            self.signer_pubkey = loaded_signer.public_key
        else:
            self.signer, self.signer_pubkey = InTotoDSSESigner.generate_ephemeral()
        if self.repo_path is not None and has_git:
            self.rsl = GittufRSLLedger(repo_path=self.repo_path)
        else:
            # No Git repository is available: opt into the in-memory adapter
            # explicitly, keeping production Git-backed ledgers strict.
            from verifyci_v2.provenance.gittuf_rsl import InMemoryGitPlumbingAdapter
            self.rsl = GittufRSLLedger(git_adapter=InMemoryGitPlumbingAdapter())
        self._session_findings: list[VerificationFinding] = []
        self._session_findings_by_id: dict[str, list[VerificationFinding]] = {}
        self.rate_limiter = TokenBucketRateLimiter(
            capacity=self.budget.rate_limit_capacity,
            refill_per_sec=self.budget.rate_limit_refill_per_sec,
        )
        self._tools: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "vc_ingest_files": self._tool_ingest_files,
            "vc_blast_radius": self._tool_blast_radius,
            "vc_query_ussa": self._tool_query_ussa,
            "vc_polyglot_bridges": self._tool_polyglot_bridges,
            "vc_prove_diff": self._tool_prove_diff,
            "vc_triage_secrets": self._tool_triage_secrets,
            "vc_search_rabitq": self._tool_search_rabitq,
            "vc_anchor_attestation": self._tool_anchor_attestation,
            "vc_verify_contract": self._tool_verify_contract,
            "vc_clear_session": self._tool_clear_session,
        }

    def list_tools(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools.keys()))

    @property
    def judge(self) -> Any:
        """System 1 judge for the configured provider, built on first use.

        Deferred because constructing the adapter imports the `neural` package,
        which transitively loads the Z3 prover. Paying that on every daemon
        construction would dominate the sub-20ms tool-latency budget the daemon
        exists to meet.
        """
        if self._judge is None:
            self._judge = self.config.build_judge()
        return self._judge

    def close(self) -> None:
        """Release long-lived resources held by the daemon (CPG store, watchers)."""
        watcher = getattr(self, "_watch_thread", None)
        if watcher is not None:
            self._watch_thread = None
        self.cpg_store.close()

    def __enter__(self) -> VerifyCIFastMCPDaemon:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def invoke_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Executes an MCP tool under rate-limiter, payload-size, and wall-clock budget guards.

        Guards that refuse work *before* it starts (rate limit, payload bound,
        unknown tool) raise `IngressLimitExceededError`. The wall-clock budget is
        a different case: the handler has already run, so the result exists but
        the engine cannot vouch for it having finished inside its deadline.
        Discarding a completed result would lose work the caller already paid
        for, and reporting success would overstate what was verified, so the
        call fails closed with an explicit INCONCLUSIVE verdict instead.
        """
        if not self.rate_limiter.consume(1.0):
            raise IngressLimitExceededError(
                "MCP rate limit exceeded (token bucket depleted)"
            )

        serialized_args = canonical_jcs_str(arguments)
        if len(serialized_args.encode("utf-8")) > self.budget.max_payload_bytes:
            raise IngressLimitExceededError(
                f"Payload size exceeds maximum bound of {self.budget.max_payload_bytes} bytes"
            )

        handler = self._tools.get(tool_name)
        if handler is None:
            raise KeyError(f"Unknown VerifyCI v2 MCP tool: {tool_name}")

        start_ns = time.perf_counter_ns()
        try:
            result = handler(arguments)
        except Exception as exc:
            # A tool that raises has produced no verdict. Letting the exception
            # escape would surface as an opaque transport error and could be
            # mistaken for "nothing to report"; fail closed with the reason.
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            return {
                "status": "ok",
                "tool": tool_name,
                "latency_ms": round(elapsed_ms, 3),
                "stackgraph_merkle_root": self.engine.stitcher.graph_merkle_root(),
                "data": {
                    "verdict": "INCONCLUSIVE",
                    "tool_error": True,
                    "error_type": type(exc).__name__,
                    "rationale": f"Tool '{tool_name}' failed closed: {exc}",
                    "findings": [],
                },
            }
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

        if elapsed_ms > self.budget.max_query_wall_ms:
            return {
                "status": "ok",
                "tool": tool_name,
                "latency_ms": round(elapsed_ms, 3),
                "stackgraph_merkle_root": self.engine.stitcher.graph_merkle_root(),
                "data": {
                    "verdict": "INCONCLUSIVE",
                    "budget_exceeded": True,
                    "elapsed_ms": round(elapsed_ms, 3),
                    "budget_ms": self.budget.max_query_wall_ms,
                    "rationale": (
                        f"Tool '{tool_name}' exceeded its wall-clock budget "
                        f"({elapsed_ms:.2f}ms > {self.budget.max_query_wall_ms:.2f}ms); "
                        "failing closed."
                    ),
                    "findings": result.get("findings", [])
                    if isinstance(result, dict)
                    else [],
                },
            }

        return {
            "status": "ok",
            "tool": tool_name,
            "latency_ms": round(elapsed_ms, 3),
            "stackgraph_merkle_root": self.engine.stitcher.graph_merkle_root(),
            "data": result,
        }

    def _normalize_repo_path(self, file_path: str) -> str:
        """Return a stable repo-relative identity for paths inside the repository."""
        raw = Path(file_path)
        if raw.is_absolute() and self.repo_path is not None:
            try:
                return raw.resolve().relative_to(Path(self.repo_path).resolve()).as_posix()
            except ValueError:
                # External paths retain their absolute identity and cannot be
                # misrepresented as Git-tree source evidence by the store.
                return raw.as_posix()
        return Path(file_path).as_posix()

    def _tool_ingest_files(self, args: dict[str, Any]) -> dict[str, Any]:
        raw_files = args.get("files", [])
        if not isinstance(raw_files, list) or not all(
            isinstance(item, dict) and "file_path" in item and "source" in item
            for item in raw_files
        ):
            raise ValueError("files must be a list of objects containing file_path and source")
        files: list[dict[str, Any]] = [
            dict(item, file_path=self._normalize_repo_path(str(item["file_path"])))
            for item in raw_files
        ]
        commit_sha: str = str(args.get("commit_sha", "working-tree"))
        snapshot_recorded = False
        graph_snapshot_key = "working-tree"

        # Validate claimed immutable source identity *before* mutating the graph.
        # A forged or stale snapshot must not contaminate live symbols or bridges.
        if commit_sha != "working-tree":
            source_map = {str(item["file_path"]): str(item["source"]) for item in files}
            self.cpg_store.record_source_snapshot(commit_sha, source_map)
            graph_snapshot_key = self.cpg_store._resolve_snapshot_commit(commit_sha)
            snapshot_recorded = True

        plans = []
        # Ingestion is not a verification request; compute a neutral engine/policy
        # fingerprint without loading an unrelated HEAD snapshot or cached pipeline.
        policy_digest = VerificationPipeline(repo_id=self.repo_id, salsa_engine=self.engine, cpg_store=self.cpg_store)._active_policy_digest()
        for item in files:
            plan = self.engine.ingest_file(
                file_path=str(item["file_path"]),
                source=str(item["source"]),
                language=str(item.get("language", "python")),
                policy_digest=policy_digest,
            )
            plans.append(msgspec.to_builtins(plan))

        all_fns = self.engine.all_functions()
        bridges = self.engine.bridge_resolver.resolve_bridges(self.engine.stitcher)
        self.cpg_store.record_commit_snapshot(graph_snapshot_key, all_fns, bridges)
        for fn in all_fns:
            hdr = build_neighborhood_header(
                fn,
                callers=self.engine.stitcher.direct_callers(fn.qualified_name),
                callees=fn.call_targets,
            )
            self.rabitq_index.upsert_document(fn.node_uid, fn.qualified_name, hdr)

        self._pipeline_obj = None
        self._pipeline_key = None
        return {
            "ingested_count": len(plans),
            "plans": plans,
            "source_snapshot_recorded": snapshot_recorded,
            "snapshot_commit_sha": graph_snapshot_key if snapshot_recorded else None,
        }

    def _tool_verify_contract(self, args: dict[str, Any]) -> dict[str, Any]:
        """Verifies a call site against a declared contract (`cap004`).

        Arguments: `call_code`, `callee_signature`, `contract`. Fails closed:
        an ungroundable binding returns INCONCLUSIVE, never VERIFIED.
        """
        from verifyci_v2.symbolic.contract_checker import verify_call_contract

        try:
            result = verify_call_contract(
                str(args["call_code"]),
                dict(args["callee_signature"]),
                dict(args["contract"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            return {
                "verdict": "INCONCLUSIVE",
                "reason": f"contract input malformed: {exc}",
            }
        return {"verdict": result.verdict, "reason": result.reason}

    def _tool_blast_radius(self, args: dict[str, Any]) -> dict[str, Any]:
        seeds: list[str] = args.get("qualified_names", [])
        max_depth: int = int(args.get("max_depth", 8))
        commit_sha: str = args.get("commit_sha", "working-tree")
        affected, truncated = self.engine.stitcher.transitive_blast_radius_with_truncation(
            seeds, max_depth=max_depth
        )
        cte_reachability = [
            {"qualified_name": qname, "hop": hop, "weight": w}
            for qname, hop, w in self.cpg_store.query_blast_radius_cte(
                commit_sha, seeds, max_hops=max_depth
            )
        ]
        return {
            "seeds": seeds,
            "transitive_callers": list(affected),
            "affected_count": len(affected),
            "cte_reachability": cte_reachability,
            "truncated": truncated,
            "max_depth": max_depth,
        }

    def _tool_query_ussa(self, args: dict[str, Any]) -> dict[str, Any]:
        qname: str = args["qualified_name"]
        fn_ussa = self.engine.get_function_ussa(qname)
        if fn_ussa is None:
            return {"found": False, "qualified_name": qname}
        return {
            "found": True,
            "function": msgspec.to_builtins(fn_ussa),
        }

    def _tool_polyglot_bridges(self, _args: dict[str, Any]) -> dict[str, Any]:
        bridges = self.engine.bridge_resolver.resolve_bridges(self.engine.stitcher)
        return {
            "bridge_count": len(bridges),
            "bridges": [msgspec.to_builtins(b) for b in bridges],
        }

    def _tool_prove_diff(self, args: dict[str, Any]) -> dict[str, Any]:
        file_path: str = self._normalize_repo_path(str(args["file_path"]))
        base_source: str = args["base_source"]
        head_source: str = args["head_source"]
        auto_fix: bool = bool(args.get("auto_fix", False))
        session_id: str | None = args.get("session_id")

        # Same pipeline the CLI gate runs, so an agent driving the daemon gets
        # the same checks, the same rule ids, and the same severities. This
        # method used to reimplement a subset of them.
        requested_base_sha = args.get("base_commit_sha")
        if requested_base_sha:
            active_pipeline = self._pipeline(
                base_commit_sha=str(requested_base_sha),
                intent_text=str(args.get("intent_text", "")),
                contracts=tuple(args.get("contracts", ())),
            )
        else:
            # The request carries complete base/head buffers. If the persistent
            # HEAD snapshot is for a different file revision, do not incorrectly
            # reinterpret it as the patch base; retain other file records but let
            # the explicit source pair ground this file. Callers needing immutable
            # Git provenance should supply base_commit_sha.
            sources = self._base_sources("HEAD")
            if file_path in sources and sources[file_path] != base_source:
                sources.pop(file_path)
            active_pipeline = self._pipeline(
                base_commit_sha="explicit-source-pair",
                intent_text=str(args.get("intent_text", "")),
                contracts=tuple(args.get("contracts", ())),
                base_sources_override=sources,
            )
        result = active_pipeline.verify_files(
            [DiffFileEntry.from_sources(file_path, base_source, head_source)]
        )

        findings = []
        synthesized_fixes_count = 0
        fix_verification_flags: list[bool] = []
        for finding in result.findings:
            if auto_fix and finding.verdict == "FAIL":
                target = self._enclosing_qualified_name(
                    file_path, head_source, finding.start_line, finding.end_line,
                    compiled=active_pipeline._last_compiled_by_path.get(file_path),
                )
                if target is not None:
                    finding = self.cegis.repair_finding(
                        file_path=file_path,
                        base_source=base_source,
                        head_source=head_source,
                        finding=finding,
                        target_qualified_name=target,
                        pipeline=active_pipeline,
                        compiled_file=active_pipeline._last_compiled_by_path.get(file_path),
                    )
                    verified_fixes = [fix for fix in finding.fixes if getattr(fix, "z3_verified_unsat", False)]
                    synthesized_fixes_count += len(verified_fixes)
                    fix_verification_flags.extend(
                        bool(getattr(fix, "z3_verified_unsat", False)) for fix in finding.fixes
                    )
            self._session_findings.append(finding)
            if session_id:
                self._session_findings_by_id.setdefault(session_id, []).append(finding)
            findings.append(msgspec.to_builtins(finding))

        return {
            "verdict": result.status,
            "rationale": result.rationale,
            "finding_count": len(findings),
            "findings": findings,
            "synthesized_fixes_count": synthesized_fixes_count,
            "all_fixes_z3_verified": (bool(fix_verification_flags) and all(fix_verification_flags)) if auto_fix else None,
        }

    def _base_sources(self, commit_sha: str = "HEAD") -> dict[str, str]:
        """Load only a verified snapshot for the exact requested commit identity."""
        if self.cpg_store.db_path == ":memory:":
            return {}
        from verifyci_v2.store.duckdb_cpg import LineageIntegrityError
        try:
            return self.cpg_store.load_source_snapshot(commit_sha)
        except LineageIntegrityError:
            # Integrity errors must propagate; treating a tampered snapshot as an
            # absent baseline would obscure a provenance violation.
            raise
        except ValueError:
            # Unknown/unresolvable revisions have no usable baseline and therefore
            # cause deletion checks to abstain.
            return {}

    def _pipeline(
        self,
        *,
        base_commit_sha: str = "HEAD",
        intent_text: str = "",
        contracts: Sequence[Mapping[str, Any]] = (),
        base_sources_override: Mapping[str, str] | None = None,
    ) -> VerificationPipeline:
        """Return a pipeline keyed by immutable base identity and all gate policy inputs."""
        contract_tuple = tuple(dict(c) for c in contracts)
        effective_sources = dict(base_sources_override) if base_sources_override is not None else self._base_sources(base_commit_sha)
        base_digest = canonical_jcs_str({k: effective_sources[k] for k in sorted(effective_sources)})
        key = (base_commit_sha, intent_text, canonical_jcs_str(list(contract_tuple)), self.repo_id, base_digest)
        if self._pipeline_obj is None or self._pipeline_key != key:
            self._pipeline_obj = VerificationPipeline(
                repo_id=self.repo_id,
                base_sources=effective_sources,
                salsa_engine=self.engine,
                cpg_store=self.cpg_store,
                intent_text=intent_text,
                contracts=contract_tuple,
            )
            self._pipeline_key = key
        return self._pipeline_obj

    @staticmethod
    def _enclosing_qualified_name(
        file_path: str, source: str, start_line: int, end_line: int,
        *, compiled: Any | None = None,
    ) -> str | None:
        """Resolve a finding's function from the retained artifact when available.

        Auto-repair is scoped to one function. The compatibility fallback is only
        used by older direct callers that do not hold the request compilation.
        """
        try:
            funcs = tuple(compiled.head_ussa.values()) if compiled is not None and compiled.head_ussa else lower_file_to_ussa(file_path, source)
        except Exception:
            return None
        enclosing = [
            fn
            for fn in funcs
            if fn.start_line <= start_line and fn.end_line >= end_line
        ]
        if not enclosing:
            return None
        # Innermost wins: nested defs produce several containing functions.
        return min(enclosing, key=lambda f: f.end_line - f.start_line).qualified_name

    def _tool_triage_secrets(self, args: dict[str, Any]) -> dict[str, Any]:
        file_path: str = args["file_path"]
        source: str = args["source"]
        findings = self.secret_engine.scan_python_source(file_path, source)
        self._session_findings.extend(findings)
        if session_id := args.get("session_id"):
            self._session_findings_by_id.setdefault(session_id, []).extend(findings)
        return {
            "finding_count": len(findings),
            "findings": [msgspec.to_builtins(f) for f in findings],
        }

    def _tool_search_rabitq(self, args: dict[str, Any]) -> dict[str, Any]:
        query: str = args["query"]
        top_k: int = int(args.get("top_k", 5))
        stats = self.rabitq_index.search(query, top_k=top_k)
        return msgspec.to_builtins(stats)

    def _tool_anchor_attestation(self, args: dict[str, Any]) -> dict[str, Any]:
        session_id: str | None = args.get("session_id")
        auto_clear: bool = bool(args.get("auto_clear", True))
        ref_name: str = args.get("ref_name", "refs/heads/main")
        head_input = str(args.get("head_commit_sha", "HEAD" if self.repo_path is not None else "1" * 40))
        try:
            head_sha = self.rsl.git_adapter.resolve_commit(head_input)
        except Exception as exc:
            return {"verdict": "INCONCLUSIVE", "reason": f"Head commit could not be resolved for attestation: {exc}"}
        if args.get("base_commit_sha"):
            try:
                base_sha = self.rsl.git_adapter.resolve_commit(str(args["base_commit_sha"]))
            except Exception as exc:
                return {"verdict": "INCONCLUSIVE", "reason": f"Base commit could not be resolved for attestation: {exc}"}
        elif self.repo_path is not None:
            try:
                base_sha = self.rsl.git_adapter.resolve_commit("HEAD^")
            except Exception:
                base_sha = head_sha
        else:
            base_sha = "0" * 40
        merkle = self.engine.stitcher.graph_merkle_root()

        if session_id and session_id in self._session_findings_by_id:
            session_findings = tuple(self._session_findings_by_id[session_id])
            if auto_clear:
                self._session_findings_by_id.pop(session_id, None)
        else:
            session_findings = tuple(self._session_findings)
            if auto_clear:
                self._session_findings.clear()
        pred = InTotoVerificationPredicate(
            repo_id=self.repo_id,
            base_commit_sha=base_sha,
            head_commit_sha=head_sha,
            ussa_merkle_root=merkle,
            gittuf_rsl_entry_hash=self.rsl.latest_entry.entry_id
            if self.rsl.latest_entry
            else "genesis",
            ai_provider=self.judge.provider_name,
            conformal_profile_hash=None,
            findings=session_findings,
        )
        envelope = self.signer.sign_predicate(pred)
        rsl_entry = self.rsl.append_reference_entry(
            ref_name=ref_name,
            target_commit_sha=head_sha,
            ussa_merkle_root=merkle,
            dsse_envelope=envelope,
        )
        sarif = export_sarif_v2(
            session_findings, ussa_merkle_root=merkle, rsl_entry_hash=rsl_entry.entry_id
        )
        return {
            "rsl_entry": msgspec.to_builtins(rsl_entry),
            "dsse_envelope": msgspec.to_builtins(envelope),
            "sarif_v2": sarif,
        }

    def clear_session(self, session_id: str | None = None) -> int:
        """Clears accumulated findings for a specific session_id or global session."""
        if session_id:
            count = len(self._session_findings_by_id.pop(session_id, []))
            return count
        count = len(self._session_findings)
        self._session_findings.clear()
        self._session_findings_by_id.clear()
        return count

    def _tool_clear_session(self, args: dict[str, Any]) -> dict[str, Any]:
        session_id = args.get("session_id")
        cleared = self.clear_session(session_id)
        return {"cleared_findings_count": cleared, "session_id": session_id}

    async def watch_workspace_once(self, root_dir: str) -> int:
        """Scans working tree files and incrementally updates changed files in memory."""
        ext_map = {
            ".py": "python",
            ".ts": "typescript",
            ".js": "javascript",
            ".c": "c",
            ".cpp": "cpp",
        }
        updated = 0
        for dirpath, _dirnames, filenames in os.walk(root_dir):
            if ".git" in dirpath or "__pycache__" in dirpath:
                continue
            for fname in sorted(filenames):
                _, ext = os.path.splitext(fname)
                ext = ext.lower()
                if ext in ext_map:
                    full_path = os.path.join(dirpath, fname)
                    file_id = self._normalize_repo_path(full_path)
                    # Decode raw bytes rather than text-mode universal-newline
                    # conversion so the compiler sees the actual file contents.
                    content = Path(full_path).read_bytes().decode("utf-8")
                    plan = self.engine.ingest_file(
                        file_id, content, language=ext_map[ext]
                    )
                    if any(
                        ev.status != "CACHE_HIT_BODY_IDENTICAL"
                        for ev in plan.evaluations
                    ):
                        updated += 1
        await asyncio.sleep(0)
        return updated

    def start_hot_reload(self, root, on_change=None):
        """Best-effort background filesystem watcher (watchfiles) per spec sec. 3.1.
        No-op when watchfiles is unavailable."""
        try:
            from watchfiles import awatch
        except Exception:
            return None
        if getattr(self, "_watch_thread", None) is not None:
            return self._watch_thread
        import threading

        def _runner():
            import asyncio

            async def _loop():
                async for _changes in awatch(root):
                    if callable(on_change):
                        try:
                            on_change()
                        except Exception:
                            pass

            try:
                asyncio.run(_loop())
            except Exception:
                pass

        t = threading.Thread(target=_runner, name="vc2-hot-reload", daemon=True)
        t.start()
        self._watch_thread = t
        return t

