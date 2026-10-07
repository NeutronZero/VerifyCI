from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Revision:
    """Content identity of a repository state.

    ``revision_id`` is a pure function of ``repository_id`` + the full
    file manifest + the ingestion config — never of wall-clock time,
    commit id, or lineage. Two ingests of the same tree therefore share
    one revision row, and the row is immutable once written. Commit and
    parent are recorded here as the *first* observation's metadata for
    backward compatibility; the authoritative lineage lives in
    :class:`Ingest`.
    """
    revision_id: str
    repository_id: str
    commit_id: Optional[str]
    parent_revision_id: Optional[str]
    source_hash: str
    timestamp: float
    ingestion_config_hash: str


@dataclass(frozen=True)
class Ingest:
    """One ingest event: append-only lineage over content revisions.

    ``parent_ingest_id`` chains ingests; ``revision_id`` points at the
    (possibly already-stored) content revision. A revert re-points at an
    old revision with a fresh ingest, so lineage can never cycle and the
    stored revision row is never rewritten.
    """
    ingest_id: str
    revision_id: str
    repository_id: str
    parent_ingest_id: Optional[str]
    commit_id: Optional[str]
    timestamp: float
    branch: Optional[str] = None


class LineageIntegrityError(RuntimeError):
    """Raised when repository lineage, ancestry DAG, or anchor integrity is violated.

    Enforces the fail-closed invariant: when lineage integrity cannot be proven,
    the verifier must yield INCONCLUSIVE rather than fabricating a passing verdict.
    """