from collections.abc import Mapping
from typing import Any

from verifyci.contracts.evidence import ProvenanceEntry
from verifyci.contracts.jsonio import to_json_dict

_REQUIRED_FIELDS = {
    "entry_id",
    "entity_id",
    "file_path",
    "line_start",
    "line_end",
    "source_hash",
    "revision_id",
}


def validate_provenance_chain(entries: list[ProvenanceEntry | Mapping[str, Any]]) -> bool:
    """Validate the canonical provenance-record shape.

    Dataclass instances are the in-process representation; mappings are the
    serialized boundary representation. Raw strings/lists are rejected.
    """
    for entry in entries:
        if isinstance(entry, ProvenanceEntry):
            record = to_json_dict(entry)
        elif isinstance(entry, Mapping):
            record = dict(entry)
        else:
            return False
        if not _REQUIRED_FIELDS.issubset(record):
            return False
        if not record["entry_id"] or not record["file_path"] or not record["source_hash"] or not record["revision_id"]:
            return False
        if record["line_start"] < 1 or record["line_end"] < record["line_start"]:
            return False
    return True
