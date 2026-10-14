"""Deprecated frozen copy. Thin re-export of the live module (v1 remediation)."""
from verifyci.storage.graph_store import GraphStore, latest_revision_id

__all__ = ["GraphStore", "latest_revision_id"]
