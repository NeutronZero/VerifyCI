# verifyci.scope

## Overview
The `verifyci.scope` package handles entity extraction, changed-scope discovery, and AST boundary correlation for Python and TypeScript/JavaScript files. It maps raw Git diff hunks to specific functions, classes, and methods in base and head trees, establishing the precise analysis perimeter for verification checks.

## Interface
- `[entities.py:Param]`: Dataclass capturing parameter name, kind, and default value flag.
- `[entities.py:CallSite]`: Dataclass recording call target name, line number, positional count, and keyword arguments.
- `[entities.py:ImportFact]`: Dataclass recording module imports, imported names, and alias mappings.
- `[entities.py:SourceFacts]`: Container for extracted entities, calls, imports, name loads, exports, and syntax status.
- `[entities.py:git_blob_id]`: Computes the Git blob hash for content bytes.
- `[entities.py:analyze_python]`: Extracts facts and entities from Python source code via AST.
- `[entities.py:analyze_typescript]`: Extracts facts and entities from TypeScript/JavaScript source code.
- `[entities.py:analyze_source]`: Dispatches source fact extraction based on file extension.
- `[entities.py:is_safe_module_construct]`: Checks whether code modifications outside functions/classes are restricted to safe declarative constructs.
- `[entities.py:find_matching_entity_detailed]`: Maps line ranges to an entity while flagging boundary conflicts.
- `[entities.py:find_matching_entity]`: Resolves the unique entity enclosing a given line range.
- `[entities.py:extract_entities]`: Extracts class and function entities from source ASTs.
- `[entities.py:ChangedScope]`: Comprehensive mapping of base/head facts, changed entity identifiers, unmapped hunks, and renames.
- `[entities.py:build_changed_scope]`: Correlates diff entries against base and head facts to construct the changed scope.
- `[entities.py:changed_hunks]`: Extracts changed line ranges from unified diff text.

## Invariants
- `[entities.py:ChangedScope]`: Hunks modifying code outside function or class boundaries are captured in `unmapped_hunks` to prevent unanalyzed edits from escaping scrutiny.
- `[entities.py:is_safe_module_construct]`: Fails closed: any non-declarative or side-effecting code outside entity boundaries requires broader scope analysis.

## Side Effects
- `[entities.py:analyze_typescript]`: May invoke Node.js child processes when executing TypeScript AST parsers.

## Verification
- Run: `pytest`
