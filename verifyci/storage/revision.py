"""Deterministic revision identity.

revision_id = SHA256(canonical_json({
    repository_id,
    files: [{path, source_hash} sorted by path],
    ingestion_config_hash,
}))

Same repository state -> same revision_id. Commit id, lineage, and
wall-clock timestamp are *ingest metadata*, recorded on the append-only
``ingests`` row, never inputs to content identity: two ingests of the
same tree at different commits share one revision. A revert re-points a
new ingest at the old revision, so lineage cannot cycle and the stored
revision row is never rewritten.
"""
import hashlib
import json
import time
from typing import Optional

from verifyci.contracts.revision import Revision

INGESTION_CONFIG_HASH = hashlib.sha256(b"v1_default").hexdigest()


def canonical_manifest(
    repository_id: str,
    commit_id: Optional[str],
    parent_revision_id: Optional[str],
    files: list[tuple[str, str]] | None,
) -> bytes:
    """Canonical bytes of *content* identity.

    ``commit_id`` and ``parent_revision_id`` are accepted for signature
    compatibility with callers that still pass them, but are deliberately
    excluded from the hash: they are ingest metadata, not content.
    """
    manifest = {
        "repository_id": repository_id,
        "files": [
            {"path": path, "source_hash": source_hash}
            for path, source_hash in sorted(files or [])
        ],
        "ingestion_config_hash": INGESTION_CONFIG_HASH,
    }
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def create_revision(
    repository_id: str,
    commit_id: Optional[str] = None,
    parent_revision_id: Optional[str] = None,
    files: list[tuple[str, str]] | None = None,
) -> Revision:
    canonical = canonical_manifest(repository_id, commit_id, parent_revision_id, files)
    source_hash = hashlib.sha256(canonical).hexdigest()
    revision_id = hashlib.sha256(f"revision:{source_hash}".encode("utf-8")).hexdigest()
    return Revision(
        revision_id=revision_id,
        repository_id=repository_id,
        commit_id=commit_id,
        parent_revision_id=parent_revision_id,
        source_hash=source_hash,
        timestamp=time.time(),
        ingestion_config_hash=INGESTION_CONFIG_HASH,
    )