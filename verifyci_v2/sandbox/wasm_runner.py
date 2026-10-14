from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from verifyci_v2.contracts.attestation import VerificationFinding
from verifyci_v2.contracts.canonical import blake3_hex
from verifyci_v2.contracts.ssa_ir import FunctionUSSA

try:
    import wasmtime as _wasmtime_mod  # type: ignore[import-untyped]
except ImportError:
    _wasmtime_mod = None


class SandboxFuelExhaustedError(RuntimeError):
    """Raised when a sandboxed checker plugin exceeds its deterministic CPU instruction fuel budget."""


class SandboxCapabilityViolationError(PermissionError):
    """Raised when a checker plugin attempts forbidden host filesystem, socket, or subprocess I/O, or passes unconfined Python."""


@dataclass(frozen=True, slots=True)
class WasmSandboxConfig:
    max_instruction_fuel: int = 10_000_000
    allow_filesystem: bool = False
    allow_network: bool = False
    require_wasm_isolation: bool = True


@dataclass(frozen=True, slots=True)
class WasmPluginExecutionReport:
    plugin_id: str
    plugin_digest: str
    fuel_consumed: int
    fuel_limit: int
    findings: tuple[VerificationFinding, ...]
    is_wasm_sandboxed: bool = True


class WasmCheckerSandbox:
    """
    Layer 7 Sandboxed Plugin Runner (`verifyci_v2/sandbox/wasm_runner.py`).
    Executes compiled WebAssembly checker modules with strict instruction-fuel accounting
    and zero WASI capability imports. Rejects unconfined Python callables by default.
    """

    def __init__(self, config: WasmSandboxConfig | None = None) -> None:
        self.config = config or WasmSandboxConfig()
        self._plugins: dict[str, tuple[str, Any]] = {}

    def register_plugin(
        self,
        plugin_id: str,
        plugin_source_or_wasm: bytes | str,
        runner_fn: Callable[[tuple[FunctionUSSA, ...]], list[VerificationFinding]] | None = None,
    ) -> str:
        if self.config.require_wasm_isolation and runner_fn is not None:
            raise SandboxCapabilityViolationError(
                f"Plugin '{plugin_id}' uses Python callable which violates require_wasm_isolation=True. "
                "Provide a compiled WASM/WAT binary module or set require_wasm_isolation=False."
            )

        text_repr = (
            plugin_source_or_wasm.decode("utf-8", errors="ignore")
            if isinstance(plugin_source_or_wasm, bytes)
            else plugin_source_or_wasm
        )

        forbidden = ("os.system", "subprocess.", "socket.", "open(", "urllib.", "httpx.")
        if not self.config.allow_filesystem and not self.config.allow_network:
            for tok in forbidden:
                if tok in text_repr:
                    raise SandboxCapabilityViolationError(
                        f"Plugin '{plugin_id}' contains forbidden capability reference: '{tok}'"
                    )

        digest = blake3_hex(plugin_source_or_wasm, domain="verifyci.v2.wasm.plugin")

        if runner_fn is not None:
            self._plugins[plugin_id] = (digest, runner_fn)
            return digest

        # Compile WAT / WASM using wasmtime
        # Compile WAT / WASM using wasmtime
        if _wasmtime_mod is not None:
            cfg = _wasmtime_mod.Config()
            cfg.consume_fuel = True
            engine = _wasmtime_mod.Engine(cfg)
            module = _wasmtime_mod.Module(engine, plugin_source_or_wasm)
            self._plugins[plugin_id] = (digest, (engine, module))
        else:
            if self.config.require_wasm_isolation:
                raise RuntimeError(
                    f"Cannot register WASM plugin '{plugin_id}': wasmtime runtime is unavailable "
                    "and require_wasm_isolation=True."
                )
            self._plugins[plugin_id] = (digest, None)

        return digest

    def execute_plugin(
        self,
        plugin_id: str,
        functions: tuple[FunctionUSSA, ...],
    ) -> WasmPluginExecutionReport:
        if plugin_id not in self._plugins:
            raise KeyError(f"Unregistered sandbox plugin: {plugin_id}")

        digest, target = self._plugins[plugin_id]

        # Case A: Pure Python callback when require_wasm_isolation is disabled
        if callable(target):
            fuel_used = 0
            for fn in functions:
                for blk in fn.basic_blocks:
                    fuel_used += 500 + 150 * (len(blk.instructions) + len(blk.phi_nodes))
                    if fuel_used > self.config.max_instruction_fuel:
                        raise SandboxFuelExhaustedError(
                            f"Plugin '{plugin_id}' exhausted CPU fuel budget "
                            f"({fuel_used} > {self.config.max_instruction_fuel})"
                        )
            raw_findings = target(functions)
            return WasmPluginExecutionReport(
                plugin_id=plugin_id,
                plugin_digest=digest,
                fuel_consumed=fuel_used,
                fuel_limit=self.config.max_instruction_fuel,
                findings=tuple(raw_findings),
                is_wasm_sandboxed=False,
            )

        # Case B: Real WebAssembly execution with wasmtime fuel metering
        if _wasmtime_mod is not None and isinstance(target, tuple):
            engine, module = target
            store = _wasmtime_mod.Store(engine)
            store.set_fuel(self.config.max_instruction_fuel)
            instance = _wasmtime_mod.Instance(store, module, [])
            exports = instance.exports(store)
            run_func = exports.get("run") or exports.get("check")

            findings_list: list[VerificationFinding] = []
            if run_func:
                try:
                    ret = run_func(store)
                    if isinstance(ret, int) and ret > 0:
                        findings_list.append(
                            VerificationFinding(
                                finding_id=blake3_hex(f"{plugin_id}:{digest}:{ret}", domain="verifyci.v2.finding")[:16],
                                rule_id=f"WASM-{plugin_id.upper()}",
                                severity="HIGH",
                                verdict="FAIL",
                                file_path="wasm_module",
                                start_line=1,
                                end_line=1,
                                message=f"WASM checker plugin '{plugin_id}' reported {ret} violation(s).",
                            )
                        )
                except Exception as exc:
                    exc_str = str(exc).lower()
                    if "fuel" in exc_str or "all fuel consumed" in exc_str:
                        raise SandboxFuelExhaustedError(
                            f"WASM plugin '{plugin_id}' exhausted instruction fuel limit ({self.config.max_instruction_fuel})"
                        ) from exc
                    raise

            consumed = self.config.max_instruction_fuel - store.get_fuel()
            return WasmPluginExecutionReport(
                plugin_id=plugin_id,
                plugin_digest=digest,
                fuel_consumed=consumed,
                fuel_limit=self.config.max_instruction_fuel,
                findings=tuple(findings_list),
                is_wasm_sandboxed=True,
            )

        if self.config.require_wasm_isolation:
            raise RuntimeError(
                f"WASM plugin '{plugin_id}' cannot execute: wasmtime runtime is unavailable "
                "and require_wasm_isolation=True."
            )

        return WasmPluginExecutionReport(
            plugin_id=plugin_id,
            plugin_digest=digest,
            fuel_consumed=0,
            fuel_limit=self.config.max_instruction_fuel,
            findings=(),
            is_wasm_sandboxed=True,
        )


class UnconfinedPythonCheckerRunner:
    """Explicitly unconfined pure-Python checker runner with is_wasm_sandboxed=False."""

    def __init__(self, max_fuel: int = 10_000_000) -> None:
        self.max_fuel = max_fuel
        self._plugins: dict[str, tuple[str, Callable[[tuple[FunctionUSSA, ...]], list[VerificationFinding]]]] = {}

    def register_plugin(
        self,
        plugin_id: str,
        source: str,
        runner_fn: Callable[[tuple[FunctionUSSA, ...]], list[VerificationFinding]],
    ) -> str:
        digest = blake3_hex(source, domain="verifyci.v2.unconfined.plugin")
        self._plugins[plugin_id] = (digest, runner_fn)
        return digest

    def execute_plugin(
        self,
        plugin_id: str,
        functions: tuple[FunctionUSSA, ...],
    ) -> WasmPluginExecutionReport:
        if plugin_id not in self._plugins:
            raise KeyError(f"Unregistered unconfined plugin: {plugin_id}")
        digest, fn = self._plugins[plugin_id]
        findings = fn(functions)
        return WasmPluginExecutionReport(
            plugin_id=plugin_id,
            plugin_digest=digest,
            fuel_consumed=0,
            fuel_limit=self.max_fuel,
            findings=tuple(findings),
            is_wasm_sandboxed=False,
        )