from typing import Any


def validate_provenance_chain(entries: list[dict[str, Any]]) -> bool:
    for entry in entries:
        required = {"file_path", "source_hash", "revision_id"}
        if not required.issubset(entry.keys()):
            return False
    return True
