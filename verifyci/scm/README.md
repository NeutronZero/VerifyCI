# verifyci.scm

## Overview
The `verifyci.scm` package provides a hardened, read-only Git plumbing adapter. All interactions with version control repositories and Git object databases within VerifyCI are strictly confined to this package, ensuring deterministic, offline analysis without modifying repository state.

## Interface
- `[git.py:GitError]`: Exception raised when a Git plumbing command returns a non-zero exit code or encounters an I/O error.
- `[git.py:GitResult]`: Dataclass containing stdout bytes, stderr bytes, and exit return code from a Git invocation.
- `[git.py:GitRepo]`: Read-only wrapper exposing plumbing methods: `rev_parse`, `diff_tree`, `cat_file`, `merge_base`, `log`, `show`, and commit querying.

## Invariants
- `[git.py:GitRepo]`: Strictly read-only; no mutating Git operations (`commit`, `checkout`, `push`, `branch`, `rebase`) are permitted.
- `[git.py:GitRepo]`: Commands are executed directly via `subprocess` with `shell=False` to prevent shell injection.

## Side Effects
- `[git.py:GitRepo]`: Spawns `git` CLI subprocesses and reads from the local Git repository database.

## Verification
- Run: `pytest`
