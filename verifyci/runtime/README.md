# verifyci.runtime

## Overview
The `verifyci.runtime` package provides deterministic execution controls, resource budget enforcement, subprocess process isolation sandboxing, deterministic batch scheduling, and wall-clock-independent diagnostic logging for VerifyCI.

## Interface
- `[budget.py:WorkBudget]`: Dataclass specifying strict deterministic resource limits (entities, references, symbolic paths, taint depth, solver rlimit, file bytes, and AST complexity).
- `[diagnostics.py:format_diagnostic]`: Formats structured diagnostic events without relying on non-deterministic wall-clock timestamps.
- `[sandbox.py:SandboxError]`: Exception raised when sandboxed process execution encounters an unhandled error or timeout.
- `[sandbox.py:run_sandboxed]`: Executes a callable in an isolated child Python process using length-prefixed JSON over standard I/O pipes.
- `[scheduler.py:run_deterministic_batch]`: Executes a batch of tasks while guaranteeing deterministic reduction order regardless of worker completion order.

## Invariants
- `[budget.py:WorkBudget]`: Must enforce immutable limits to guarantee reproducible check execution across environments.
- `[scheduler.py:run_deterministic_batch]`: Output collection order must remain strictly deterministic and match the input task sequence.

## Side Effects
- `[sandbox.py:run_sandboxed]`: Spawns isolated child Python processes using `subprocess.Popen` and communicates over pipes.

## Verification
- Run: `pytest`
