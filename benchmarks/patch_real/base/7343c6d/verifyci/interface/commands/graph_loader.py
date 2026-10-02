"""Load the persisted code graph for verification commands."""
from verifyci.graph.builder import GraphBuilder
from verifyci.interface.commands import InfraError, resolve_repository
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
    mkdir and materialize an empty database at a client-chosen path
    (readers use mode=ro and never create). A path that EXISTS but
    cannot be read (locked, corrupt, WAL-mode on a sealed mount)
    raises InfraError — the old code swallowed that into an empty
    graph, letting a gate that never ran masquerade as INCONCLUSIVE.
    With return_revision=True, also return the resolved revision id
    (the requested one, or the latest lookup) as a fourth element.
    """
    import os as _os
    import sqlite3 as _sqlite3
    empty = (None, {}, [], "") if return_revision else (None, {}, [])
    if not _os.path.exists(db_path):
        return empty
    try:
        store = GraphStore(db_path, read_only=True)
    except _sqlite3.Error as e:
        raise _infra_kind(db_path, e)
    except OSError as e:
        raise InfraError("db_not_found", f"{db_path}: {e}")
    except Exception as e:  # noqa: BLE001
        raise InfraError("db_unreadable", f"{db_path}: {type(e).__name__}: {e}")
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
    except InfraError:
        raise
    except _sqlite3.Error as e:
        raise _infra_kind(db_path, e)
    except Exception as e:  # noqa: BLE001
        raise InfraError("db_unreadable", f"{db_path}: {type(e).__name__}: {e}")
    finally:
        store.close()


def _infra_kind(db_path: str, e: Exception) -> InfraError:
    msg = str(e)
    kind = "db_locked" if ("locked" in msg or "busy" in msg) else "db_unreadable"
    return InfraError(kind, f"{db_path}: {msg}")
