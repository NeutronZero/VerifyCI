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
from verifyci_v2.contracts.canonical import blake3_hex, canonical_jcs_str
from verifyci_v2.ingestion.salsa_cutoff import SalsaIncrementalEngine
from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.neural.cegis_repair import CEGISAutoRepairEngine
from verifyci_v2.provenance.dsse_intoto import InTotoDSSESigner, export_sarif_v2
from verifyci_v2.provenance.gittuf_rsl import GittufRSLLedger
from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore
from verifyci_v2.store.model2vec_embed import build_neighborhood_header
from verifyci_v2.store.rabitq_index import RaBitQHybridIndex
from verifyci_v2.symbolic.secrets_taint import TaintTrackedSecretEngine
from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver


class IngressLimitExceededError(RuntimeError):
    """Raised when a tool call exceeds rate limits, payload bounds, or CPU wall-clock budgets."""


class IngressBudgetConfig(msgspec.Struct, frozen=True):
    max_payload_bytes: int = 2 * 1024 * 1024  # 2 MiB max payload
    rate_limit_capacity: float = 50.0  # Burst capacity (requests)
    rate_limit_refill_per_sec: float = 25.0  # Token refill rate
    max_query_wall_ms: float = 500.0  # Per-query wall-clock budget


class TokenBucketRateLimiter:
    """Deterministic token-bucket rate limiter protecting the stateful MCP daemon."""

    def __init__(
        self,
        capacity: float = 50.0,
        refill_per_sec: float = 25.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self._clock = clock
        self._tokens = capacity
        self._last_timestamp = clock()

    def consume(self, tokens: float = 1.0) -> bool:
        now = self._clock()
        elapsed = max(0.0, now - self._last_timestamp)
        self._last_timestamp = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_sec)
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False


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
    ) -> None:
        self.repo_id = repo_id
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
        self.signer, self.signer_pubkey = InTotoDSSESigner.generate_ephemeral()
        self.rsl = GittufRSLLedger()
        self._session_findings: list[VerificationFinding] = []
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
        }

    def list_tools(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools.keys()))

    def invoke_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Executes an MCP tool under rate-limiter, payload-size, and wall-clock budget guards."""
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
        result = handler(arguments)
        elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

        if elapsed_ms > self.budget.max_query_wall_ms:
            raise IngressLimitExceededError(
                f"Tool '{tool_name}' exceeded wall-clock budget ({elapsed_ms:.2f}ms > {self.budget.max_query_wall_ms:.2f}ms)"
            )

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
        affected = self.engine.stitcher.transitive_blast_radius(
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

        base_fns = {
            f.qualified_name: f
            for f in lower_file_to_ussa(file_path, base_source, repo_id=self.repo_id)
        }
        head_fns = {
            f.qualified_name: f
            for f in lower_file_to_ussa(file_path, head_source, repo_id=self.repo_id)
        }

        findings = []
        for qname, fn_head in head_fns.items():
            fn_base = base_fns.get(qname)
            if fn_base is not None:
                res = self.prover.prove_function_diff(
                    file_path=file_path,
                    base_source=base_source,
                    head_source=head_source,
                    func_base=fn_base,
                    func_head=fn_head,
                )
                if not res and fn_base.h_body != fn_head.h_body:
                    is_eq, smt_st = self.prover.prove_equivalence(
                        base_source=base_source,
                        cand_source=head_source,
                        func_base=fn_base,
                        func_cand=fn_head,
                    )
                    if not is_eq and smt_st == "SAT":
                        div_finding = VerificationFinding(
                            finding_id=blake3_hex(
                                f"DIVERGE:{file_path}:{qname}",
                                domain="verifyci.v2.finding",
                            )[:16],
                            rule_id="VC2-Z3-SEMANTIC-DIVERGENCE",
                            severity="HIGH",
                            verdict="FAIL",
                            file_path=file_path,
                            start_line=fn_head.start_line,
                            end_line=fn_head.end_line,
                            message=f"Z3 proven semantic divergence between base and head for '{qname}'.",
                        )
                        res = (div_finding,)
                for f in res:
                    if auto_fix and f.verdict == "FAIL":
                        f = self.cegis.repair_finding(
                            file_path=file_path,
                            base_source=base_source,
                            head_source=head_source,
                            finding=f,
                            target_qualified_name=qname,
                        )
                    self._session_findings.append(f)
                    findings.append(msgspec.to_builtins(f))

        return {"finding_count": len(findings), "findings": findings}

    def _tool_triage_secrets(self, args: dict[str, Any]) -> dict[str, Any]:
        file_path: str = args["file_path"]
        source: str = args["source"]
        findings = self.secret_engine.scan_python_source(file_path, source)
        self._session_findings.extend(findings)
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
        base_sha: str = args.get("base_commit_sha", "0" * 40)
        head_sha: str = args.get("head_commit_sha", "1" * 40)
        ref_name: str = args.get("ref_name", "refs/heads/main")
        merkle = self.engine.stitcher.graph_merkle_root()

        session_findings = tuple(self._session_findings)
        pred = InTotoVerificationPredicate(
            repo_id=self.repo_id,
            base_commit_sha=base_sha,
            head_commit_sha=head_sha,
            ussa_merkle_root=merkle,
            gittuf_rsl_entry_hash=self.rsl.latest_entry.entry_id
            if self.rsl.latest_entry
            else "genesis",
            ai_provider="deterministic",
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

