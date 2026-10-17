from __future__ import annotations

import asyncio
import msgspec
import os
import time
from typing import Any, Callable

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
        self.budget = budget or IngressBudgetConfig()
        self.engine = SalsaIncrementalEngine(repo_id=repo_id)
        self.cpg_store = DuckDBCPGStore()
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
        self.rsl = GittufRSLLedger()
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

    def _tool_ingest_files(self, args: dict[str, Any]) -> dict[str, Any]:
        files: list[dict[str, str]] = args.get("files", [])
        commit_sha: str = args.get("commit_sha", "working-tree")
        plans = []
        for item in files:
            plan = self.engine.ingest_file(
                file_path=item["file_path"],
                source=item["source"],
                language=item.get("language", "python"),
            )
            plans.append(msgspec.to_builtins(plan))

        all_fns = self.engine.all_functions()
        bridges = self.engine.bridge_resolver.resolve_bridges(self.engine.stitcher)
        self.cpg_store.record_commit_snapshot(commit_sha, all_fns, bridges)
        for fn in all_fns:
            hdr = build_neighborhood_header(
                fn,
                callers=self.engine.stitcher.direct_callers(fn.qualified_name),
                callees=fn.call_targets,
            )
            self.rabitq_index.upsert_document(fn.node_uid, fn.qualified_name, hdr)

        return {"ingested_count": len(plans), "plans": plans}

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
        file_path: str = args["file_path"]
        base_source: str = args["base_source"]
        head_source: str = args["head_source"]
        auto_fix: bool = bool(args.get("auto_fix", False))
        session_id: str | None = args.get("session_id")

        # Same pipeline the CLI gate runs, so an agent driving the daemon gets
        # the same checks, the same rule ids, and the same severities. This
        # method used to reimplement a subset of them.
        result = self._pipeline().verify_files(
            [DiffFileEntry.from_sources(file_path, base_source, head_source)]
        )

        findings = []
        for finding in result.findings:
            if auto_fix and finding.verdict == "FAIL":
                target = self._enclosing_qualified_name(
                    file_path, head_source, finding.start_line, finding.end_line
                )
                if target is not None:
                    finding = self.cegis.repair_finding(
                        file_path=file_path,
                        base_source=base_source,
                        head_source=head_source,
                        finding=finding,
                        target_qualified_name=target,
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
        }

    def _base_sources(self) -> dict[str, str]:
        """Stored base revision, when the daemon has a file-backed store."""
        if self.cpg_store.db_path == ":memory:":
            return {}
        try:
            return self.cpg_store.load_source_snapshot("HEAD")
        except Exception:
            return {}

    def _pipeline(self) -> VerificationPipeline:
        """Long-lived pipeline, so the prover and taint engine are built once."""
        if self._pipeline_obj is None:
            self._pipeline_obj = VerificationPipeline(
                repo_id=self.repo_id,
                base_sources=self._base_sources(),
            )
        return self._pipeline_obj

    @staticmethod
    def _enclosing_qualified_name(
        file_path: str, source: str, start_line: int, end_line: int
    ) -> str | None:
        """Qualified name of the function whose line span contains a finding.

        Auto-repair is scoped to one function. A finding that cannot be placed
        inside one is left unrepaired rather than repaired against a guess.
        """
        try:
            funcs = lower_file_to_ussa(file_path, source)
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
        base_sha: str = args.get("base_commit_sha", "0" * 40)
        head_sha: str = args.get("head_commit_sha", "1" * 40)
        ref_name: str = args.get("ref_name", "refs/heads/main")
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
                if ext in ext_map:
                    full_path = os.path.join(dirpath, fname)
                    rel_path = os.path.relpath(full_path, root_dir).replace("\\", "/")
                    with open(full_path, "r", encoding="utf-8") as fh:
                        content = fh.read()
                    plan = self.engine.ingest_file(
                        rel_path, content, language=ext_map[ext]
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

