# verifyci.frontend

## Overview
The `verifyci.frontend` package provides multi-language AST/CST parsing, normalization, and lowering into the Verified Function Intermediate Representation (VFIR). It defines language frontend protocols, implements concrete frontends for Python and TypeScript/JavaScript, and verifies frontend lowering fidelity.

## Interface
- `[fidelity.py:check_fidelity]`: Evaluates semantic and structural fidelity between source ASTs and lowered representations.
- `[protocol.py:LanguageFrontendProtocol]`: Formal protocol specifying requirements for language frontend parsers and IR lowerers.
- `[python_frontend.py:PythonFrontend]`: Python source code parser and VFIR lowering engine based on Python's built-in AST.
- `[ts_frontend.py:TypeScriptFrontend]`: TypeScript and JavaScript source code parser and VFIR lowering engine.
- `[vfir.py:EntityStatus]`: Enum tracking change status of code entities (`UNCHANGED`, `MODIFIED`, `ADDED`, `REMOVED`).
- `[vfir.py:Capability]`: Enum defining specific VFIR capabilities and supported language features.
- `[vfir.py:BasicBlock]`: Represents a basic block within a control-flow graph in VFIR.
- `[vfir.py:FunctionVFIR]`: Intermediate representation data structure for verified functions.

## Invariants
- `[protocol.py:LanguageFrontendProtocol]`: Language frontends must fail closed on syntax errors by returning explicit parse error diagnostics rather than failing silently.
- `[vfir.py:FunctionVFIR]`: Maintains consistent control-flow edges and variable mappings across lowered basic blocks.

## Side Effects
- `[ts_frontend.py:TypeScriptFrontend]`: May invoke external Node.js child processes when executing TypeScript CST parser tools.

## Verification
- Run: `pytest`
