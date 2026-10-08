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

    P3: file_path is normalized before hashing (backslash separators become
    posix, leading ./ stripped, duplicate slashes collapsed) so the same
    file reached by different spellings cannot split identities across
    platforms. Already-canonical paths hash exactly as before.
    """
    norm_path = file_path.replace("\\", "/")
    while norm_path.startswith("./"):
        norm_path = norm_path[2:]
    while "//" in norm_path:
        norm_path = norm_path.replace("//", "/")
    if signature:
        payload = f"{repository_id}\x1f{norm_path}\x1f{scope}\x1f{name}\x1f{type.value}\x1f{signature}"
    else:
        payload = f"{repository_id}\x1f{norm_path}\x1f{scope}\x1f{name}\x1f{type.value}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_revision_entity_id(logical_entity_id: str, revision_id: str) -> str:
    payload = f"{logical_entity_id}\x1f{revision_id}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
