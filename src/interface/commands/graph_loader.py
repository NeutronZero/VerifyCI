"""Load the persisted code graph for verification commands."""
from src.graph.builder import GraphBuilder
from src.storage.graph_store import GraphStore


def payload_entities(graph) -> list:
    nodes_fn = getattr(graph, "nodes", None)
    if graph is None or not callable(nodes_fn):
        return []
    try:
        return [d for d in nodes_fn()
                if hasattr(d, "file_path") and hasattr(d, "revision_entity_id")]
    except Exception:  # noqa: BLE001, S110
        return []


def load_graph(db_path: str, revision_id: str = ""):
    """Return (graph, node_map, entities). Empty graph when DB is missing."""
    try:
        store = GraphStore(db_path)
    except Exception:  # noqa: BLE001
        return None, {}, []
    try:
        if not revision_id:
            rows = store.conn.execute(
                "SELECT revision_id FROM revisions ORDER BY timestamp DESC LIMIT 1"
            ).fetchall()
            revision_id = rows[0][0] if rows else ""
        if not revision_id:
            return None, {}, []
        entities = store.get_entities_by_revision(revision_id)
        edges = store.get_edges_by_revision(revision_id)
        builder = GraphBuilder()
        graph = builder.build(entities, edges) if entities else None
        return graph, builder.get_node_map(), entities
    finally:
        store.close()
