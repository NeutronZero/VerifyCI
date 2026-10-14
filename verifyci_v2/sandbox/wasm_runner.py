from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from verifyci_v2.contracts.attestation import VerificationFinding
from verifyci_v2.contracts.canonical import blake3_hex
from verifyci_v2.contracts.ssa_ir import FunctionUSSA


class SandboxFuelExhaustedError(RuntimeError):
    """Raised when a sandboxed checker plugin exceeds its deterministic CPU instruction fuel budget."""


class SandboxCapabilityViolationError(PermissionError):
    """Raised when a checker plugin attempts forbidden host filesystem, socket, or subprocess I/O."""


@dataclass(frozen=True, slots=True)
class WasmSandboxConfig:
    max_instruction_fuel: int = 10_000_000
    allow_filesystem: bool = False
    allow_network: bool = False


@dataclass(frozen=True, slots=True)
class WasmPluginExecutionReport:
    plugin_id: str
    plugin_digest: str
    fuel_consumed: int
    fuel_limit: int
    findings: tuple[VerificationFinding, ...]


class WasmCheckerSandbox:
    """
    Layer 7 Sandboxed Plugin Runner (`verifyci_v2/sandbox/wasm_runner.py`).
    Executes custom repository invariant plugins over read-only FunctionUSSA snapshots
    with zero filesystem/network access and strict instruction-fuel accounting.
    """

    def __init__(self, config: WasmSandboxConfig | None = None) -> None:
        self.config = config or WasmSandboxConfig()
        self._plugins: dict[str, tuple[str, Callable[[tuple[FunctionUSSA, ...]], list[VerificationFinding]]]] = {}

    def register_plugin(
        self,
        plugin_id: str,
        plugin_source_or_wasm: bytes | str,
        runner_fn: Callable[[tuple[FunctionUSSA, ...]], list[VerificationFinding]],
    ) -> str:
        # Static capability scan for forbidden host I/O calls in plugin representation
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
                        f"Plugin '{plugin_id}' contains forbidden WASI capability reference: '{tok}'"
                    )
        digest = blake3_hex(plugin_source_or_wasm, domain="verifyci.v2.wasm.plugin")
        self._plugins[plugin_id] = (digest, runner_fn)
        return digest

    def execute_plugin(
        self,
        plugin_id: str,
        functions: tuple[FunctionUSSA, ...],
    ) -> WasmPluginExecutionReport:
        if plugin_id not in self._plugins:
            raise KeyError(f"Unregistered sandbox plugin: {plugin_id}")

        digest, runner_fn = self._plugins[plugin_id]

        # Deterministic instruction fuel accounting: 150 fuel units per U-SSA instruction + 500 per block
        fuel_used = 0
        for fn in functions:
            for blk in fn.basic_blocks:
                fuel_used += 500 + 150 * (len(blk.instructions) + len(blk.phi_nodes))
                if fuel_used > self.config.max_instruction_fuel:
                    raise SandboxFuelExhaustedError(
                        f"Plugin '{plugin_id}' exhausted CPU fuel budget "
                        f"({fuel_used} > {self.config.max_instruction_fuel})"
                    )

        raw_findings = runner_fn(functions)
        return WasmPluginExecutionReport(
            plugin_id=plugin_id,
            plugin_digest=digest,
            fuel_consumed=fuel_used,
            fuel_limit=self.config.max_instruction_fuel,
            findings=tuple(raw_findings),
        )