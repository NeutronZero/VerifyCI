"""Deferred cross-file reference resolution.

Extraction resolves what it can intra-file and emits CALLS_UNRESOLVED /
INHERITS_UNRESOLVED for the rest; GraphBuilder links them post-build when
exactly one entity with the referenced name exists. Zero candidates
(builtins, libc, unmodeled) and ambiguous names (same name in two files)
stay unlinked: a wrong link invents impact, a missing one merely
undercounts it.
"""
from src.contracts.edge import EdgeType
from src.contracts.entity import EntityType
from src.graph.builder import GraphBuilder
from src.ingestion.extractor import extract_edges, extract_entities
from src.ingestion.parser import TreeSitterParser


def _build(files: dict[str, tuple[bytes, str]]):
    parser = TreeSitterParser()
    entities, edges = [], []
    for name, (source, language) in files.items():
        parsed = parser.parse(name, source, language)
        file_entities = extract_entities(parsed, "repo1", "rev1")
        entities.extend(file_entities)
        edges.extend(extract_edges(parsed, file_entities, "rev1"))
    builder = GraphBuilder()
    return builder, builder.build(entities, edges), entities, edges


def _links(graph):
    out = []
    for _, (src, dst, payload) in graph.edge_index_map().items():
        out.append((graph[src].name, graph[dst].name, payload.type))
    return out


def test_cross_file_call_resolves():
    builder, graph, _, edges = _build({
        "a.cpp": (b"void helper() {}\n", "cpp"),
        "b.cpp": (b"void user() { helper(); }\n", "cpp"),
    })
    assert any(e.type == EdgeType.CALLS_UNRESOLVED for e in edges)
    assert ("user", "helper", EdgeType.CALLS) in _links(graph)
    assert builder.resolution_stats["resolved"] == 1


def test_ambiguous_name_stays_unlinked():
    builder, graph, _, _ = _build({
        "a.cpp": (b"void load() {}\n", "cpp"),
        "b.cpp": (b"void load(int x) { (void)x; }\n", "cpp"),
        "c.cpp": (b"void user() { load(); }\n", "cpp"),
    })
    assert ("user", "load", EdgeType.CALLS) not in _links(graph)
    assert builder.resolution_stats == {"resolved": 0, "ambiguous": 1, "missing": 0}


def test_unknown_callee_stays_unlinked():
    builder, graph, _, edges = _build({
        "b.cpp": (b"void user() { printf(\"x\"); }\n", "cpp"),
    })
    assert any(e.type == EdgeType.CALLS_UNRESOLVED for e in edges)
    assert builder.resolution_stats["missing"] == 1
    # No phantom external node per call site: unresolved refs never link.
    assert [e for e in _links(graph) if e[2] == EdgeType.CALLS] == []


def test_cross_file_inheritance_resolves():
    builder, graph, _, _ = _build({
        "base.h": (b"class Base {};\n", "cpp"),
        "app.cpp": (b"class App : public Base, protected Mixin {};\n", "cpp"),
    })
    assert ("App", "Base", EdgeType.INHERITS) in _links(graph)
    assert builder.resolution_stats["resolved"] == 1
    assert builder.resolution_stats["missing"] == 1  # Mixin undefined


def test_same_file_inheritance_links_directly():
    _, graph, _, edges = _build({
        "app.cpp": (b"class Base {};\nclass App : public Base {};\n", "cpp"),
    })
    assert ("App", "Base", EdgeType.INHERITS) in _links(graph)
    assert not [e for e in edges if e.type == EdgeType.INHERITS_UNRESOLVED]


def test_out_of_class_definition_is_method():
    _, _, entities, _ = _build({
        "app.cpp": (b"class App {\n  void run();\n};\nvoid App::run() {}\n"
                    b"static void freeFn() {}\n", "cpp"),
    })
    by_name = {e.name: e for e in entities
               if e.type in (EntityType.FUNCTION, EntityType.METHOD)}
    assert by_name["run"].type == EntityType.METHOD
    assert by_name["run"].metadata.get("scope") == "App"
    assert by_name["freeFn"].type == EntityType.FUNCTION
    # The in-class declaration is not an entity; the definition is.
    assert sum(1 for e in entities if e.name == "run") == 1


def test_out_of_class_method_calls_resolve_in_scope():
    builder, graph, _, _ = _build({
        "app.cpp": (b"class App {\n  void run();\n  void help();\n};\n"
                    b"void App::run() { help(); }\nvoid App::help() {}\n",
                    "cpp"),
    })
    assert ("run", "help", EdgeType.CALLS) in _links(graph)


def test_qualified_base_resolves_canonically():
    # `ns::Base` must link the namespaced definition even with a
    # same-named top-level class in the revision: flat lookup would
    # see two `Base` candidates and give up (or guess).
    builder, graph, _, _ = _build({
        "base.h": (b"namespace ns {\nclass Base {};\n}\n", "cpp"),
        "other.cpp": (b"class Base {};\n", "cpp"),
        "app.cpp": (b"class App : public ns::Base {\n};\n", "cpp"),
    })
    targets = [(graph[src].name, graph[dst].file_path)
               for _, (src, dst, payload) in graph.edge_index_map().items()
               if payload.type == EdgeType.INHERITS]
    assert targets == [("App", "base.h")]
    assert builder.resolution_stats == {"resolved": 1, "ambiguous": 0, "missing": 0}


def test_template_base_emits_no_parent():
    # `Box<int>`: the template argument must not become a bogus parent.
    # Direct-children filter pins this; a _walk would catch `int`.
    _, _, _, edges = _build({
        "app.cpp": (b"template<class T> class Box {};\n"
                    b"class Mine : public Box<int> {};\n"
                    b"class Root {};\n", "cpp"),
    })
    assert [e for e in edges if "UNRESOLVED" in e.type.value] == []


def test_global_anchor_matches_only_top_level():
    builder, graph, _, _ = _build({
        "a.cpp": (b"class GlobalBase {};\n", "cpp"),
        "b.cpp": (b"namespace ns {\nclass GlobalBase {};\n}\n", "cpp"),
        "c.cpp": (b"class App : public ::GlobalBase {};\n", "cpp"),
    })
    targets = [graph[dst].file_path
               for _, (src, dst, payload) in graph.edge_index_map().items()
               if payload.type == EdgeType.INHERITS]
    assert targets == ["a.cpp"]
    assert builder.resolution_stats["resolved"] == 1


def test_bare_base_with_two_definitions_stays_ambiguous():
    builder, _, _, _ = _build({
        "a.cpp": (b"namespace n1 {\nclass Base {};\n}\n", "cpp"),
        "b.cpp": (b"namespace n2 {\nclass Base {};\n}\n", "cpp"),
        "c.cpp": (b"class App : public Base {};\n", "cpp"),
    })
    assert builder.resolution_stats == {"resolved": 0, "ambiguous": 1, "missing": 0}


def test_qualified_name_recorded_and_ids_stable():
    # `qualified_name` is additive metadata; the logical id still uses
    # the namespace-free scope, so wrapping code in a namespace renames
    # nothing already stored (no duplicate live rows on re-ingest).
    from src.contracts.identity import compute_logical_entity_id
    from src.contracts.entity import EntityType
    _, _, entities, _ = _build({
        "x.cpp": (b"namespace ns {\nvoid helper() {}\n}\nvoid top() {}\n", "cpp"),
    })
    by_name = {e.name: e for e in entities if e.type == EntityType.FUNCTION}
    assert by_name["helper"].metadata["qualified_name"] == "ns::helper"
    assert "qualified_name" not in (by_name["top"].metadata or {})
    assert by_name["helper"].logical_entity_id == compute_logical_entity_id(
        "repo1", "x.cpp", "helper", EntityType.FUNCTION, "")
    assert by_name["top"].logical_entity_id == compute_logical_entity_id(
        "repo1", "x.cpp", "top", EntityType.FUNCTION, "")


def test_resolution_is_deterministic():
    first, _, _, _ = _build({
        "a.cpp": (b"void helper() {}\n", "cpp"),
        "b.cpp": (b"void user() { helper(); }\n", "cpp"),
    })
    second, _, _, _ = _build({
        "b.cpp": (b"void user() { helper(); }\n", "cpp"),
        "a.cpp": (b"void helper() {}\n", "cpp"),
    })
    assert first.resolution_stats == second.resolution_stats == {
        "resolved": 1, "ambiguous": 0, "missing": 0}
