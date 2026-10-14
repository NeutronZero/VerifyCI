"""Deprecated frozen copy. Thin re-export of the live module (v1 remediation)."""
from verifyci.ingestion.extractor import extract_edges, extract_entities

__all__ = ["extract_edges", "extract_entities"]
