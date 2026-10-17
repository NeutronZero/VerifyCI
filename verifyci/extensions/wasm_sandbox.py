"""Fuel-metered and memory-constrained WebAssembly sandbox adapter using Wasmtime."""

from __future__ import annotations

import time
from typing import Any, Sequence

from verifyci.extensions.protocols import SandboxProtocol, SandboxResult


def _get_wasmtime() -> Any:
    try:
        import wasmtime  # type: ignore[import-untyped]
        return wasmtime
    except ImportError:
        return None


class WasmSandboxCapabilityError(Exception):
    """Raised when an unconfined host action or capability violation is attempted."""


class WasmFuelExhaustedError(Exception):
    """Raised when plugin execution exceeds allocated computational fuel."""


class WasmtimeSandboxAdapter(SandboxProtocol):
    """WebAssembly sandbox enforcing strict fuel limits and memory isolation."""

    def __init__(self) -> None:
        pass

    def execute_plugin(
        self,
        plugin_id: str,
        plugin_wasm: bytes | str,
        inputs: Sequence[Any] = (),
        fuel_limit: int = 1_000_000,
        memory_limit_bytes: int = 64 * 1024 * 1024,
    ) -> SandboxResult:
        wt = _get_wasmtime()
        t0 = time.perf_counter()

        if wt is None:
            return SandboxResult(
                output=None,
                fuel_consumed=0,
                memory_bytes=0,
                duration_ms=0.0,
                error="Wasmtime runtime is not installed",
            )

        config = wt.Config()
        config.consume_fuel = True

        engine = wt.Engine(config)
        store = wt.Store(engine)
        store.set_fuel(fuel_limit)
        store.set_limits(memory_size=memory_limit_bytes)

        try:
            if isinstance(plugin_wasm, str):
                # Text format (.wat)
                wasm_bytes = wt.wat2wasm(plugin_wasm)
            else:
                wasm_bytes = plugin_wasm

            module = wt.Module(engine, wasm_bytes)

            # Strict host isolation: reject modules that attempt to import unconfined host capabilities
            if module.imports:
                unauthorized = [f"{imp.module}::{imp.name}" for imp in module.imports]
                raise WasmSandboxCapabilityError(
                    f"Plugin '{plugin_id}' attempts unauthorized host imports: {unauthorized}"
                )

            instance = wt.Instance(store, module, [])

            run_fn = instance.exports(store).get("run")
            if run_fn is None:
                return SandboxResult(
                    output=None,
                    fuel_consumed=0,
                    memory_bytes=0,
                    duration_ms=(time.perf_counter() - t0) * 1000,
                    error="Module does not export 'run' function",
                )

            res = run_fn(store, *inputs)
            fuel_remaining = store.get_fuel()
            fuel_consumed = fuel_limit - fuel_remaining

            duration_ms = (time.perf_counter() - t0) * 1000
            return SandboxResult(
                output=res,
                fuel_consumed=fuel_consumed,
                memory_bytes=memory_limit_bytes,
                duration_ms=duration_ms,
            )

        except (wt.WasmtimeError, wt.Trap) as exc:
            err_str = str(exc)
            if "fuel" in err_str.lower() or "all fuel consumed" in err_str.lower():
                raise WasmFuelExhaustedError(f"Plugin '{plugin_id}' exhausted fuel limit ({fuel_limit})") from exc
            if "memory" in err_str.lower() and "limit" in err_str.lower():
                raise WasmSandboxCapabilityError(
                    f"Plugin '{plugin_id}' exceeded memory limit ({memory_limit_bytes} bytes): {exc}"
                ) from exc
            return SandboxResult(
                output=None,
                fuel_consumed=fuel_limit,
                memory_bytes=0,
                duration_ms=(time.perf_counter() - t0) * 1000,
                error=f"Wasmtime execution trap: {exc}",
            )
