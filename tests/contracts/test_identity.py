from src.contracts.identity import compute_logical_entity_id, compute_revision_entity_id
from src.contracts.entity import EntityType


def test_logical_entity_id_stable_across_revisions():
    id1 = compute_logical_entity_id("repo1", "src/auth.py", "authenticate", EntityType.FUNCTION)
    id2 = compute_logical_entity_id("repo1", "src/auth.py", "authenticate", EntityType.FUNCTION)
    assert id1 == id2


def test_logical_entity_id_changes_with_name():
    id1 = compute_logical_entity_id("repo1", "src/auth.py", "authenticate", EntityType.FUNCTION)
    id2 = compute_logical_entity_id("repo1", "src/auth.py", "authenticate_user", EntityType.FUNCTION)
    assert id1 != id2


def test_logical_entity_id_changes_with_file():
    id1 = compute_logical_entity_id("repo1", "src/auth.py", "authenticate", EntityType.FUNCTION)
    id2 = compute_logical_entity_id("repo1", "src/session.py", "authenticate", EntityType.FUNCTION)
    assert id1 != id2


def test_logical_entity_id_changes_with_repository():
    id1 = compute_logical_entity_id("repo1", "src/auth.py", "authenticate", EntityType.FUNCTION)
    id2 = compute_logical_entity_id("repo2", "src/auth.py", "authenticate", EntityType.FUNCTION)
    assert id1 != id2


def test_logical_entity_id_no_collision_with_separator():
    id1 = compute_logical_entity_id("repo1", "a/b", "c", EntityType.FUNCTION)
    id2 = compute_logical_entity_id("repo1", "a", "b/c", EntityType.FUNCTION)
    assert id1 != id2


def test_revision_entity_id_changes_with_revision():
    logical = compute_logical_entity_id("repo1", "src/auth.py", "authenticate", EntityType.FUNCTION)
    id1 = compute_revision_entity_id(logical, "rev1")
    id2 = compute_revision_entity_id(logical, "rev2")
    assert id1 != id2


def test_revision_entity_id_stable():
    logical = compute_logical_entity_id("repo1", "src/auth.py", "authenticate", EntityType.FUNCTION)
    id1 = compute_revision_entity_id(logical, "rev1")
    id2 = compute_revision_entity_id(logical, "rev1")
    assert id1 == id2
