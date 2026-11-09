# verifyci.analysis

## Overview
The `verifyci.analysis` package provides foundational static analysis models and intermediate representations for VerifyCI. It encompasses control-flow graph (CFG) representations, Static Single Assignment (SSA) form variable versioning, guard condition extraction and normalization, state mutation and side-effect modeling, interprocedural function summaries, and taint propagation analysis utilized across verification checks.

## Interface
- `[cfg.py:CFG]`: Control-flow graph representation and dominance frontier structure holding basic block sequences.
- `[effects.py:EffectModel]`: State mutation and side-effect modeling for function-level operations.
- `[guards.py:GuardAnalyzer]`: Guard condition analyzer extracting and normalizing path conditions.
- `[ssa.py:SSAForm]`: Static Single Assignment (SSA) form and def-use chain container tracking variable versions.
- `[summaries.py:FunctionSummary]`: Interprocedural function contract summaries for call-site verification and taint propagation.
- `[taint.py:TaintAnalyzer]`: Interprocedural taint flow analyzer tracking source-to-sink data flow.

## Invariants
- `[cfg.py:CFG.__init__]`: Preserves basic block definitions verbatim in `blocks`.
- `[ssa.py:SSAForm.__init__]`: Initializes `variables` mapping from symbol names to SSA versions as an empty dictionary.
- `[summaries.py:FunctionSummary.__init__]`: Preserves canonical `qualified_name` string across summary lifecycles.

## Side Effects
- None: Pure in-memory analysis data structures with no disk I/O, network calls, or external mutations.

## Verification
- Run: `pytest`
