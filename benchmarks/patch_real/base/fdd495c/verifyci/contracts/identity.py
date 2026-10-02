import hashlib

from verifyci.contracts.entity import EntityType


def compute_logical_entity_id(
    repository_id: str, file_path: str, name: str, type: EntityType,
    scope: str = "",
) -> str:
    """Stable across revisions. Scope is the dotted parent scope
    (e.g. class name for a method, function name for a parameter);
    empty for top-level entities. A rename or move yields a new identity.
    """
    payload = f"{repository_id}\x1f{file_path}\x1f{scope}\x1f{name}\x1f{type.value}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_revision_entity_id(logical_entity_id: str, revision_id: str) -> str:
    payload = f"{logical_entity_id}\x1f{revision_id}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
