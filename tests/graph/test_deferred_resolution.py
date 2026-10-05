"""Deferred cross-file reference resolution.

Extraction resolves what it can intra-file and emits CALLS_UNRESOLVED /
INHERITS_UNRESOLVED for the rest; GraphBuilder links them post-build when
exactly one entity with the referenced name exists. Zero candidates
(builtins, libc, unmodeled) and ambiguous names (same name in two files)
stay unlinked: a wrong link invents impact, a missing one merely
undercounts it.
"""
from verifyci.contracts.edge import EdgeType
from verifyci.contracts.entity import EntityType
from verifyci.graph.builder import GraphBuilder
from verifyci.ingestion.extractor import extract_edges, extract_entities
from verifyci.ingestion.parser import TreeSitterParser


def _build(files: dict[str, tuple[bytes, str]], **kwargs):
    parser = TreeSitterParser()
    entities, edges = [], []
    for name, (source, language) in files.items():
        parsed = parser.parse(name, source, language)
        file_entities = extract_entities(parsed, "repo1", "rev1")
        entities.extend(file_entities)
        edges.extend(extract_edges(parsed, file_entities, "rev1"))
    builder = GraphBuilder(**kwargs)
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
    from verifyci.contracts.identity import compute_logical_entity_id
    from verifyci.contracts.entity import EntityType
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


def test_cross_language_same_name_does_not_link():
    # Python `obj.add(x)` must not link the C `add`: unique-name
    # resolution is gated on same language.
    builder, graph, _, _ = _build({
        "a.py": (b"class Something:\n    def run(self):\n        self.add(x)\n",
                 "python"),
        "b.c": (b"int add(int a, int b) { return a + b; }\n", "c"),
    })
    assert [link for link in _links(graph) if link[2] == EdgeType.CALLS] == []
    assert builder.resolution_stats["missing"] == 1


def test_nested_calls_attribute_once_to_inner():
    _, graph, _, _ = _build({
        "a.py": (b"def outer():\n    def inner():\n        target()\n"
                 b"    inner()\n\ndef target():\n    pass\n", "python"),
    })
    calls = sorted((s, t) for s, t, typ in _links(graph) if typ == EdgeType.CALLS)
    assert calls == [("inner", "target"), ("outer", "inner")]
    # ("outer", "target") must NOT appear: descending into the nested
    # def double-attributed every inner call to the outer function.


def test_decorator_calls_captured():
    # `@app.route` lives outside the function body; without decorator
    # scanning it produces no reference at all. `route` is undefined,
    # so the reference stays unresolved rather than linking wrongly.
    from verifyci.ingestion.extractor import extract_edges, extract_entities
    from verifyci.ingestion.parser import TreeSitterParser
    parsed = TreeSitterParser().parse(
        "a.py", b"import app\n\n@app.route(\"/x\")\ndef view():\n    pass\n",
        "python")
    entities = extract_entities(parsed, "r", "rev1")
    edges = extract_edges(parsed, entities, "rev1")
    unres = [e for e in edges if e.type == EdgeType.CALLS_UNRESOLVED]
    assert [(e.metadata or {}).get("callee") for e in unres] == ["route"]


def test_decorator_call_links_when_defined():
    _, graph, _, _ = _build({
        "a.py": (b"def route(p):\n    return p\n\n"
                 b"@route(\"/x\")\ndef view():\n    pass\n", "python"),
    })
    calls = [(s, t) for s, t, typ in _links(graph) if typ == EdgeType.CALLS]
    assert ("view", "route") in calls


def test_module_level_calls_attribute_to_module():
    _, graph, _, _ = _build({
        "a.py": (b"def main():\n    pass\n\nif __name__ == \"__main__\":\n    main()\n",
                 "python"),
    })
    calls = [(s, t) for s, t, typ in _links(graph) if typ == EdgeType.CALLS]
    assert ("a.py", "main") in calls


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


def test_c_file_links_header_defined_function():
    builder, graph, _, _ = _build({
        "util.h": (b"int shared_add(int a, int b) { return a + b; }\n", "cpp"),
        "main.c": (b"int main() { return shared_add(1, 2); }\n", "c"),
    })
    assert ("main", "shared_add", EdgeType.CALLS) in _links(graph)
    assert builder.resolution_stats["resolved"] == 1


def test_qualified_call_resolves_canonically():
    # `ns::helper()` must link the namespaced definition even with a
    # same-named top-level function in the revision: the bare fallback
    # would see two `helper` candidates and give up.
    builder, graph, _, _ = _build({
        "base.cpp": (b"namespace ns {\nvoid helper() {}\n}\n", "cpp"),
        "other.cpp": (b"void helper() {}\n", "cpp"),
        "app.cpp": (b"void user() { ns::helper(); }\n", "cpp"),
    })
    targets = [(graph[src].name, graph[dst].file_path)
               for _, (src, dst, payload) in graph.edge_index_map().items()
               if payload.type == EdgeType.CALLS]
    assert targets == [("user", "base.cpp")]
    assert builder.resolution_stats == {"resolved": 1, "ambiguous": 0, "missing": 0}


def test_qualified_call_to_missing_stays_unlinked():
    # `ns::ghost()` must NOT fall back to the unique top-level `ghost`:
    # a namespaced reference never links a bare same-named entity.
    builder, graph, _, _ = _build({
        "other.cpp": (b"void ghost() {}\n", "cpp"),
        "app.cpp": (b"void user() { ns::ghost(); }\n", "cpp"),
    })
    assert [link for link in _links(graph) if link[2] == EdgeType.CALLS] == []
    assert builder.resolution_stats["missing"] == 1


def test_bare_call_with_two_namespaced_defs_stays_ambiguous():
    builder, _, _, _ = _build({
        "a.cpp": (b"namespace n1 {\nvoid helper() {}\n}\n", "cpp"),
        "b.cpp": (b"namespace n2 {\nvoid helper() {}\n}\n", "cpp"),
        "c.cpp": (b"void user() { helper(); }\n", "cpp"),
    })
    assert builder.resolution_stats == {"resolved": 0, "ambiguous": 1, "missing": 0}


def _resolved_payloads(graph):
    return [payload
            for _, (_, _, payload) in graph.edge_index_map().items()
            if (getattr(payload, "metadata", None) or {}).get("deferred")]


def test_resolved_links_carry_resolver_provenance():
    _, graph, _, _ = _build({
        "a.cpp": (b"void helper() {}\n", "cpp"),
        "b.cpp": (b"void user() { helper(); }\n", "cpp"),
    })
    stamped = _resolved_payloads(graph)
    assert len(stamped) == 1
    assert stamped[0].metadata["resolver"] == "unique-bare-name"
    # The original reference survives alongside the stamp.
    assert stamped[0].metadata["callee"] == "helper"


def test_qualified_resolved_links_carry_canonical_resolver():
    _, graph, _, _ = _build({
        "base.cpp": (b"namespace ns {\nvoid helper() {}\n}\n", "cpp"),
        "other.cpp": (b"void helper() {}\n", "cpp"),
        "app.cpp": (b"void user() { ns::helper(); }\n", "cpp"),
    })
    stamped = _resolved_payloads(graph)
    assert len(stamped) == 1
    assert stamped[0].metadata["resolver"] == "qualified-canonical"
    assert stamped[0].metadata["callee_qualified"] == "ns::helper"


def test_explicit_class_call_prefers_that_class_method():
    # Module-level `App.run()` names its scope: it links App.run even
    # though a same-named top-level `run` shares the file.
    _, graph, _, _ = _build({
        "a.py": (b"class App:\n    def run(self):\n        pass\n"
                 b"\n\ndef run():\n    pass\n\nApp.run()\n",
                 "python"),
    })
    calls = [(s, t) for s, t, typ in _links(graph) if typ == EdgeType.CALLS]
    assert ("a.py", "run") in calls
    targets = [t for s, t in calls if s == "a.py"]
    assert len(targets) == 1


def test_explicit_class_call_target_is_the_method():
    _, graph, _, _ = _build({
        "a.py": (b"class App:\n    def run(self):\n        pass\n"
                 b"\n\ndef run():\n    pass\n\nApp.run()\n",
                 "python"),
    })
    methods = [graph[dst] for _, (src, dst, payload) in graph.edge_index_map().items()
               if payload.type == EdgeType.CALLS]
    assert [m.name for m in methods] == ["run"]
    assert [m.type for m in methods] == [EntityType.METHOD]


def test_instance_receiver_invents_no_edge():
    # `self.help()` with no `help` anywhere: no type proof, no edge.
    builder, graph, _, _ = _build({
        "a.py": (b"class App:\n    def run(self):\n        self.help()\n",
                 "python"),
    })
    assert [link for link in _links(graph) if link[2] == EdgeType.CALLS] == []
    assert builder.resolution_stats["missing"] == 1


def test_unknown_class_receiver_stays_unlinked():
    # `Widget().run()`: the receiver call and the method call both
    # stay unresolved — no type proof, no edge either way.
    builder, graph, _, _ = _build({
        "a.py": (b"def user():\n    Widget().run()\n", "python"),
    })
    assert [link for link in _links(graph) if link[2] == EdgeType.CALLS] == []
    assert builder.resolution_stats == {"resolved": 0, "ambiguous": 0, "missing": 2}


def test_resolution_events_off_by_default():
    builder, _, _, _ = _build({
        "a.cpp": (b"void helper() {}\n", "cpp"),
        "b.cpp": (b"void user() { helper(); }\n", "cpp"),
    })
    assert builder.resolution_events == []


def test_resolution_events_record_decision_inputs():
    builder, _, _, _ = _build({
        "a.cpp": (b"void helper() {}\n", "cpp"),
        "b.cpp": (b"void user() { helper(); }\n", "cpp"),
        "c.cpp": (b"void load() {}\n", "cpp"),
        "d.cpp": (b"void load(int x) { (void)x; }\n", "cpp"),
        "e.cpp": (b"void other() { load(); load(); }\n", "cpp"),
    }, collect_events=True)
    by_ref = {}
    for ev in builder.resolution_events:
        by_ref.setdefault(ev["ref"], []).append(ev)
    assert by_ref["helper"][0]["resolver"] == "unique-bare-name"
    assert by_ref["helper"][0]["outcome"] == "resolved"
    # `load` spelled twice at two sites, two same-named defs: two
    # ambiguous rows with candidate counts, fail closed.
    assert len(by_ref["load"]) == 2
    assert all(ev["outcome"] == "ambiguous" for ev in by_ref["load"])
    assert all(ev["candidates"] == 2 for ev in by_ref["load"])
    assert all(set(ev) >= {"edge_id", "kind", "ref", "resolver", "outcome",
                           "candidates", "caller_language",
                           "caller_scope_depth", "spelled_qualified"}
               for ev in builder.resolution_events)


def test_resolution_events_capture_qualified_rows():
    builder, _, _, _ = _build({
        "base.cpp": (b"namespace ns {\nvoid helper() {}\n}\n", "cpp"),
        "other.cpp": (b"void helper() {}\n", "cpp"),
        "app.cpp": (b"void user() { ns::helper(); }\n", "cpp"),
    }, collect_events=True)
    (ev,) = builder.resolution_events
    assert ev["resolver"] == "qualified-canonical"
    assert ev["outcome"] == "resolved"
    assert ev["ref"] == "ns::helper"
    assert ev["spelled_qualified"] is True
