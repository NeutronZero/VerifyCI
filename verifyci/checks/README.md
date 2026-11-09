# verifyci.checks

## Overview
The `verifyci.checks` package contains the five core verification checks of VerifyCI (`grounding`, `deletion`, `contract`, `security`, and `semantic`) alongside shared check contexts, finding constructors, and isolated witness replay execution harnesses. Each check operates over Git diff entries and changed scopes to detect regressions, ungrounded edits, contract breakage, security hazards, and semantic discrepancies before pull requests are merged.

## Interface
- `[base.py:CheckContext]`: Immutable, frozen execution context carrying Git repository access, policy rules, diff entries, changed scopes, toolchain fingerprint, and resource budgets.
- `[base.py:make_finding]`: Constructs a normalized finding with a stable SHA-256 fingerprint.
- `[base.py:entity_budget_exceeded]`: Determines whether entity or reference budgets have been exceeded for a check's target scope.
- `[base.py:unsupported_scope_gaps]`: Generates coverage gaps for files outside supported language subsets or containing unmodelled syntax.
- `[base.py:make_result]`: Constructs a normative `CheckResult` ensuring alignment between outcome, coverage, and gaps.
- `[base.py:error_result]`: Constructs a fail-closed `ERROR` `CheckResult` upon internal exceptions.
- `[base.py:gap]`: Helper function for creating `CoverageGap` instances.
- `[base.py:budget_exhausted_result]`: Constructs an `INCONCLUSIVE` `CheckResult` when analysis budgets or deadlines are exhausted.
- `[contract.py:run]`: Evaluates signature, export, and call-site compatibility across modified entities.
- `[deletion.py:run]`: Evaluates public symbol deletions and identifies dangling references in non-deleted code.
- `[grounding.py:run]`: Evaluates diff entries against policy prohibited change rules (`deny_changes`).
- `[security.py:run]`: Performs secret scanning, dangerous call detection, and taint flow analysis.
- `[semantic.py:run]`: Executes symbolic equivalence verification and semantic difference analysis using Z3.
- `[semantic.py:collect_target_sites]`: Identifies changed function pairs as candidates for semantic equivalence analysis.
- `[semantic.py:ast_to_z3]`: Translates AST nodes into Z3 symbolic expressions.
- `[semantic.py:SymbolicContext]`: Context manager and environment tracking symbolic variables and constraints.
- `[semantic.py:execute_function_isolated]`: Executes Python target functions in an isolated subprocess (`sys.executable -I`).
- `[semantic.py:execute_ts_function_isolated]`: Executes TypeScript target functions in an isolated Node.js child process.
- `[semantic.py:replay_witness]`: Replays candidate counterexample inputs against base and head functions to validate observable divergence.
- `[semantic.py:ExecutionTrace]`: Captures function execution traces and return values during replay.
- `[semantic.py:ReplayResult]`: Dataclass recording witness replay confirmation, observations, and divergence reason.
- `[semantic.py:UnsupportedExpressionError]`: Exception raised when encountering expressions outside supported symbolic grammar.
- `[semantic.py:UnsupportedControlFlowError]`: Exception raised on unsupported control flow constructs.
- `[semantic.py:ReplaySafetyViolation]`: Exception raised when witness replay exceeds memory or security boundaries.
- `[semantic.py:BudgetExhaustedError]`: Exception raised when solver resource limits (`rlimit`) or exploration depth is exhausted.

## Invariants
- `[base.py:CheckContext]`: Must remain frozen and immutable throughout check execution.
- `[base.py:make_result]`: Enforces fail-closed outcome logic: any active blocking finding forces an `Outcome.FAIL` disposition; zero findings with gaps forces `Outcome.INCONCLUSIVE` or `Outcome.CLEAN` per coverage rules.
- `[semantic.py:execute_function_isolated]`: Replay must run in isolated Python processes without inheriting environment variables or shell contexts.
- `[semantic.py:execute_ts_function_isolated]`: TypeScript replay must enforce strict execution timeouts and sandbox flags.

## Side Effects
- `[semantic.py:execute_function_isolated]`: Spawns isolated child Python subprocesses for concrete witness verification.
- `[semantic.py:execute_ts_function_isolated]`: Spawns isolated child Node.js processes for concrete TypeScript witness verification.

## Verification
- Run: `pytest`
