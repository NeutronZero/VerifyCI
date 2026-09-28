from src.graph.builder import GraphBuilder
from src.ingestion.extractor import extract_edges, extract_entities
from src.ingestion.parser import TreeSitterParser
from src.retrieval.blast_radius import compute_blast_radius

SOURCE = b"""import os

def execute(sql):
    return query(sql)

def query(sql):
    return sql

class Service:
    def run(self):
        return execute("select 1")

def unrelated():
    pass
"""


def _graph():
    parsed = TreeSitterParser().parse("svc.py", SOURCE, "python")
    entities = extract_entities(parsed, "repo", "rev1")
    edges = extract_edges(parsed, entities, "rev1")
    builder = GraphBuilder()
    graph = builder.build(entities, edges)
    return graph, builder.get_node_map(), entities


def _ids(entities, *names):
    return [e.revision_entity_id for e in entities if e.name in names]


def test_blast_finds_true_caller():
    graph, node_map, entities = _graph()
    (query_id,) = _ids(entities, "query")
    blast = compute_blast_radius(graph, [query_id], set(), node_map=node_map)
    assert "execute" in [ _name(entities, e) for e in blast.affected_callers ]


def _name(entities, eid):
    return next(e.name for e in entities if e.revision_entity_id == eid)


def test_blast_excludes_structural_nodes():
    graph, node_map, entities = _graph()
    (query_id,) = _ids(entities, "query")
    blast = compute_blast_radius(graph, [query_id], set(), node_map=node_map)
    names = {_name(entities, e) for e in blast.affected_callers + blast.affected_callees}
    assert "svc.py" not in names  # MODULE via CONTAINS must not pollute
    assert "sql" not in names  # PARAMETER via CONTAINS must not pollute


def test_blast_unrelated_function_untouched():
    graph, node_map, entities = _graph()
    (query_id,) = _ids(entities, "query")
    blast = compute_blast_radius(graph, [query_id], set(), node_map=node_map)
    names = {_name(entities, e) for e in blast.affected_callers + blast.affected_callees}
    assert "unrelated" not in names
