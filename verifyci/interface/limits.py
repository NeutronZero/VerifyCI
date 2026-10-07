"""Single source of truth for interface size caps.

MAX_DIFF_CHARS / MAX_TASK_DIFF_CHARS / MAX_K were previously defined
separately in mcp_server, fastmcp_server, and http (same values, three
copies drifting apart). Every surface imports them from here. The values
are the most permissive previously in force, so no previously-valid
input is newly rejected: unification only removes the copies.
"""

MAX_DIFF_CHARS = 1_000_000
MAX_TASK_DIFF_CHARS = 100_000
MAX_K = 1000
MAX_QUERY_CHARS = 10_000
