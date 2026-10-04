import hashlib

from verifyci.contracts.entity import EntityType


def compute_logical_entity_id(
    repository_id: str, file_path: str, name: str, type: EntityType,
    scope: str = "", signature: str = "",
) -> str:
    """Stable across revisions. Scope is the dotted parent scope
    (e.g. class name for a method, function name for a parameter);
    empty for top-level entities. A rename or move yields a new identity.
    For overloaded languages (C/C++), signature contains normalized parameter
    types in declaration order (excluding parameter names).
    For Python properties, signature contains the accessor kind (:getter/:setter/:deleter).
    For non-overloaded functions (Python), signature is empty to preserve
    cross-revision parameter continuity.
    """
    if signature:
        payload = f"{repository_id}\x1f{file_path}\x1f{scope}\x1f{name}\x1f{type.value}\x1f{signature}"
    else:
        payload = f"{repository_id}\x1f{file_path}\x1f{scope}\x1f{name}\x1f{type.value}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_revision_entity_id(logical_entity_id: str, revision_id: str) -> str:
    payload = f"{logical_entity_id}\x1f{revision_id}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
