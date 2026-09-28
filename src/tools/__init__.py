"""Agent tool surface: file, shell, and LLM tools.

Trust model (conditional, read before extending): these tools run with the
invoking user's privileges against user-authored content. There is
deliberately no path allowlist today because absolute paths are load-bearing
(`ingest`, `verify`, `query`, `vuln` all take them) — not because allowlisting
is impossible. An `allowed_root` at construction would accept absolute paths
within a root and reject the rest.

That conditional expires the moment the agent processes content the user
didn't write (prompt injection via README/webhook/PR: hostile content
instructing writes elsewhere, executed with the user's privileges). At that
point revisit: path allowlists here, and real sandboxing for `shell_tool`
(V1.1 or later decision — `run_sandboxed` currently documents that it
performs no isolation).
"""
