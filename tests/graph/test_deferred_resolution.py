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
