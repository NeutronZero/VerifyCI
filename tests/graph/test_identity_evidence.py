"""Identity evidence: ambiguity measured before any ID migration."""
from verifyci.contracts.entity import Entity, EntityType
from verifyci.graph.identity_evidence import collision_report


def _e(name, file, type=EntityType.FUNCTION, scope="", qualified="",
       start=1, end=5):
    meta = {}
    if scope:
        meta["scope"] = scope
    if qualified:
        meta["qualified_name"] = qualified
    return Entity(
        repository_id="r", logical_entity_id=f"lid-{name}-{file}-{start}",
        revision_entity_id=f"rid-{name}-{file}-{start}", type=type,
        name=name, file_path=file, line_start=start, line_end=end,
        language="cpp", source_hash="h", revision_id="rev1", metadata=meta)


def test_no_collisions_no_groups():
    rep = collision_report([_e("solo", "a.cpp")])
    assert rep["summary"] == {"n_groups": 0, "n_collided_entities": 0,
                              "separable_by_signal": {s: 0 for s in
                                                       ("qualified_name", "scope",
                                                        "file_path", "type", "span")},
                              "unseparable_groups": 0}
    assert rep["groups"] == []


def test_scope_separates_methods_file_separates_functions():
    rep = collision_report([
        _e("run", "app.cpp", EntityType.METHOD, scope="App"),
        _e("run", "srv.cpp", EntityType.METHOD, scope="Server"),
        _e("help", "a.cpp", start=1, end=3),
        _e("help", "b.cpp", start=1, end=3),
    ])
    by_name = {g["name"]: g for g in rep["groups"]}
    assert set(by_name) == {"run", "help"}
    assert "scope" in by_name["run"]["distinguished_by"]
    assert "file_path" in by_name["help"]["distinguished_by"]
    assert rep["summary"]["n_groups"] == 2
    assert rep["summary"]["n_collided_entities"] == 4


def test_qualified_name_pair_separates_by_file_not_empty_signals():
    # ns::helper vs top-level helper: qualified_name and scope each
    # have an empty side, so neither separates (empties never do) —
    # file_path does. Finding: for pure separability, qualified_name
    # adds nothing over (scope, file); its value is canonical
    # MATCHING in the resolver, not separation here.
    rep = collision_report([
        _e("helper", "base.cpp", scope="ns", qualified="ns::helper"),
        _e("helper", "other.cpp"),
    ])
    (group,) = rep["groups"]
    assert group["distinguished_by"] == ["file_path"]


def test_empty_signals_never_separate():
    # Same name, same file, same span, no scope: file_path ties and
    # span ties, so nothing separates — the true migration residual.
    rep = collision_report([
        _e("dup", "a.cpp", start=1, end=5),
        _e("dup", "a.cpp", start=1, end=5),
    ])
    (group,) = rep["groups"]
    assert group["distinguished_by"] == []
    assert rep["summary"]["unseparable_groups"] == 1


def test_type_separates_class_from_function():
    rep = collision_report([
        _e("Thing", "a.cpp", EntityType.CLASS, start=1, end=9),
        _e("Thing", "a.cpp", EntityType.FUNCTION, start=12, end=15),
    ])
    (group,) = rep["groups"]
    assert "type" in group["distinguished_by"]


def test_parameters_and_imports_never_collide():
    rep = collision_report([
        _e("x", "a.cpp", EntityType.PARAMETER, scope="f"),
        _e("x", "a.cpp", EntityType.PARAMETER, scope="g"),
        _e("os", "a.cpp", EntityType.IMPORT),
        _e("os", "b.cpp", EntityType.IMPORT),
        _e("m", "a.cpp", EntityType.MODULE),
        _e("m", "b.cpp", EntityType.MODULE),
    ])
    assert rep["summary"]["n_groups"] == 0
