from typing import Any

from src.contracts.entity import Entity, EntityType
from src.contracts.edge import Edge
from src.contracts.identity import compute_logical_entity_id


class GraphBuilder:
    def __init__(self, allow_external: bool = True):
        self._graph = None
        self._node_map = {}
        self._allow_external = allow_external

    def build(self, entities: list[Entity], edges: list[Edge]):
        import rustworkx as rx

        self._graph = rx.PyDiGraph()
        self._node_map = {}

        for entity in entities:
            idx = self._graph.add_node(entity)
            self._node_map[entity.revision_entity_id] = idx

        for edge in edges:
            src_idx = self._node_map.get(edge.src_entity_id)
            dst_idx = self._node_map.get(edge.dst_entity_id)
            if src_idx is None and self._allow_external:
                src_idx = self._add_external(edge.src_entity_id, edge)
            if dst_idx is None and self._allow_external:
                dst_idx = self._add_external(edge.dst_entity_id, edge)
            if src_idx is not None and dst_idx is not None:
                self._graph.add_edge(src_idx, dst_idx, edge)

        return self._graph

    def _add_external(self, endpoint: str, edge: Edge) -> int:
        """Materialize string endpoints (e.g. SBOM `pypi:requests`) as nodes
        so DEPENDS_ON edges reach the graph instead of being dropped."""
        existing = self._node_map.get(endpoint)
        if existing is not None:
            return existing
        logical = compute_logical_entity_id("external", "", endpoint, EntityType.IMPORT)
        entity = Entity(
            repository_id="external",
            logical_entity_id=logical,
            revision_entity_id=endpoint,
            type=EntityType.IMPORT,
            name=endpoint,
            file_path="",
            line_start=0,
            line_end=0,
            language="",
            source_hash="",
            revision_id=edge.revision_id,
            metadata={"external": True,
                      "ecosystem": (edge.metadata or {}).get("ecosystem", "")},
        )
        idx = self._graph.add_node(entity)
        self._node_map[endpoint] = idx
        return idx

    def get_graph(self):
        return self._graph

    def get_node_map(self) -> dict[str, int]:
        return dict(self._node_map)

    def stats(self) -> dict[str, Any]:
        if self._graph is None:
            return {"nodes": 0, "edges": 0}
        return {
            "nodes": self._graph.num_nodes(),
            "edges": self._graph.num_edges(),
        }
