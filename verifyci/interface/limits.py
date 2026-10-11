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

# Input complexity limits (single-pass diff pre-scan)
MAX_CHANGED_FILES = 200
MAX_CHANGED_LINES = 10_000  # Added + deleted lines combined

# Shared graph traversal limits
MAX_TRAVERSAL_NODES = 50_000
MAX_TRAVERSAL_EDGES = 100_000

# Monotonic deadline profiles (seconds)
TIMEOUT_PROFILE_HTTP = 30.0
TIMEOUT_PROFILE_CLI = 120.0
TIMEOUT_PROFILE_CI = 300.0

# HTTP server worker pool & queue
MAX_HTTP_QUEUE_SIZE = 16
MAX_HTTP_WORKERS = 4


class BudgetExceededError(RuntimeError):
    """Raised when an ExecutionBudget limit (nodes, edges, or monotonic deadline) is exceeded."""
    pass


class ExecutionBudget:
    """Request-scoped execution budget tracking cumulative resources and monotonic deadlines."""

    def __init__(
        self,
        deadline_monotonic: float,
        max_nodes: int = MAX_TRAVERSAL_NODES,
        max_edges: int = MAX_TRAVERSAL_EDGES,
    ):
        self.deadline_monotonic = deadline_monotonic
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.nodes_visited = 0
        self.edges_visited = 0

    @classmethod
    def create(
        cls,
        timeout_seconds: float = TIMEOUT_PROFILE_CLI,
        max_nodes: int = MAX_TRAVERSAL_NODES,
        max_edges: int = MAX_TRAVERSAL_EDGES,
    ) -> "ExecutionBudget":
        import time
        return cls(
            deadline_monotonic=time.monotonic() + timeout_seconds,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )

    def check_deadline(self) -> None:
        import time
        if time.monotonic() > self.deadline_monotonic:
            raise BudgetExceededError("execution_budget_deadline_exceeded")

    def record_node(self, count: int = 1) -> None:
        self.nodes_visited += count
        if self.nodes_visited > self.max_nodes:
            raise BudgetExceededError(f"execution_budget_nodes_exceeded:{self.max_nodes}")

    def record_edge(self, count: int = 1) -> None:
        self.edges_visited += count
        if self.edges_visited > self.max_edges:
            raise BudgetExceededError(f"execution_budget_edges_exceeded:{self.max_edges}")

