# Docker Worker

## Overview
The `docker/worker` component provides the containerized sandbox launcher and runtime environment for executing untrusted candidate VerifyCI evaluations under strict isolation (§15.10 Component A). It encapsulates `launch_candidate.py`, an unprivileged container entrypoint that dynamically loads candidate packages from a mounted directory, dispatches benchmark test cases or gate CLI workflows, and streams structured JSON results to standard output.

## Interface
- `[launch_candidate.py:parse_args]`: Parses command-line arguments configuring worker execution modes (`check-case` and `gate` subcommands).
- `[launch_candidate.py:main]`: Main execution entrypoint validating `--candidate-root`, configuring module import paths, executing requested gate/check actions, and mapping verification outcomes to process exit codes.
- `[Dockerfile:ENTRYPOINT]`: Pinned Python 3.12-slim container image specification configured with non-root UID `10001:10001` running `/opt/verifyci-worker/launch_candidate.py` in isolated mode (`-I`).
- `[requirements.lock]`: Pinned runtime dependency manifest defining trusted wheel dependencies (tree-sitter grammars, z3-solver, cryptography) for worker evaluation containers.

## Invariants
- `[launch_candidate.py:main]`: The candidate root path (`--candidate-root`) must resolve to an existing directory; exits immediately with code 3 if non-existent.
- `[launch_candidate.py:main]`: Candidate source path is prepended to `sys.path` (`sys.path.insert(0, str(cand_root))`) so candidate modules take precedence over pre-installed packages.
- `[launch_candidate.py:main]`: Process exit codes for `check-case` strictly reflect verification outcomes: `0` for `PASS`, `1` for `FAIL`, `2` for `INCONCLUSIVE`, `3` for `ERROR`, and `4` for `NOT_APPLICABLE` (the worker-only mapping accepted by `verifyci_release_trust.ipc`).
- `[launch_candidate.py:main]`: In `check-case` mode, all unhandled exceptions are trapped to emit a fallback JSON payload (`outcome: "ERROR", coverage: "UNKNOWN", reason_codes: ["execution_exception"], findings: []`) before terminating with code 3.
- `[Dockerfile:USER]`: Container executes strictly under non-root unprivileged UID `10001:10001` with `PYTHONDONTWRITEBYTECODE=1` and `PYTHONUNBUFFERED=1`.

## Side Effects
- `[launch_candidate.py:main]`: Emits structured JSON check results or error payloads to `sys.stdout`.
- `[launch_candidate.py:main]`: Emits runtime errors and diagnostic messages to `sys.stderr`.
- `[launch_candidate.py:main]`: Modifies runtime module search path in-process via `sys.path.insert(0, ...)`.
- `[launch_candidate.py:main]`: Executes read operations against git repositories mounted at `--repo-root` via `GitRepo`.
- `[launch_candidate.py:main]`: Dynamically loads and executes Python code from the candidate root (`verifyci.checks.*`, `verifyci.gate.*`, `verifyci.scm.*`, `verifyci.cli`).

## Verification
- Run: `pytest`
