"""Load the persisted code graph for verification commands."""
from verifyci.graph.builder import GraphBuilder
from verifyci.interface.commands import resolve_repository
from verifyci.storage.graph_store import GraphStore, latest_revision_id


def payload_entities(graph) -> list:
    nodes_fn = getattr(graph, "nodes", None)
    if graph is None or not callable(nodes_fn):
        return []
    try:
        return [d for d in nodes_fn()
                if hasattr(d, "file_path") and hasattr(d, "revision_entity_id")]
    except Exception:  # noqa: BLE001, S110
        return []


def load_graph(db_path: str, revision_id: str = "", return_revision: bool = False):
    """Return (graph, node_map, entities). Empty graph when DB is missing.

    Fail closed on a missing path: constructing a GraphStore would
    mkdir and materialize an empty database at a client-chosen path.
    With return_revision=True, also return the resolved revision id
    (the requested one, or the latest lookup) as a fourth element.
    """
    import os as _os
    empty = (None, {}, [], "") if return_revision else (None, {}, [])
    if not _os.path.exists(db_path):
        return empty
    try:
        store = GraphStore(db_path)
    except Exception:  # noqa: BLE001
        return empty
    try:
        if not revision_id:
            revision_id = latest_revision_id(
                store.conn, resolve_repository(db_path))
        if not revision_id:
            return empty
        entities = store.get_entities_by_revision(revision_id)
        edges = store.get_edges_by_revision(revision_id)
        builder = GraphBuilder()
        graph = builder.build(entities, edges) if entities else None
        if return_revision:
            return graph, builder.get_node_map(), entities, revision_id
        return graph, builder.get_node_map(), entities
    finally:
        store.close()
