"""Tests for fuel-metered and memory-isolated Wasmtime sandbox adapter."""

from __future__ import annotations

import pytest

from verifyci.extensions.wasm_sandbox import (
    WasmFuelExhaustedError,
    WasmtimeSandboxAdapter,
)


def test_wasm_sandbox_computes_function() -> None:
    # A simple WASM module adding two numbers
    wat = """
    (module
        (func (export "run") (param i32 i32) (result i32)
            local.get 0
            local.get 1
            i32.add)
    )
    """
    adapter = WasmtimeSandboxAdapter()
    res = adapter.execute_plugin("adder", wat, inputs=(10, 25), fuel_limit=10_000)

    assert res.error is None
    assert res.output == 35
    assert res.fuel_consumed > 0


def test_wasm_sandbox_fuel_exhaustion_on_infinite_loop() -> None:
    # An infinite loop in WAT
    wat_infinite = """
    (module
        (func (export "run")
            (loop br 0))
    )
    """
    adapter = WasmtimeSandboxAdapter()
    with pytest.raises(WasmFuelExhaustedError):
        adapter.execute_plugin("loop", wat_infinite, fuel_limit=1_000)
