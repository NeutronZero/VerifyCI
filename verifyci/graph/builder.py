from typing import Any

from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.edge import CPGEdgeSubtype, Edge, EdgeType
from verifyci.contracts.identity import compute_logical_entity_id

UNRESOLVED_TYPES = frozenset({EdgeType.CALLS_UNRESOLVED, EdgeType.INHERITS_UNRESOLVED})

#: Entity types eligible as resolution targets, per reference kind.
_CALL_TARGET_TYPES = frozenset({EntityType.FUNCTION, EntityType.METHOD, EntityType.CLASS})
_BASE_TARGET_TYPES = frozenset({EntityType.CLASS, EntityType.TYPE})

#: Languages that link calls freely across each other. C and C++ share
#: headers and `extern "C"`; TypeScript, TSX, and JavaScript link together;
#: every other language links only itself.
_LANGUAGE_FAMILIES = {
    "c": "c-family",
    "cpp": "c-family",
    "typescript": "js-family",
    "tsx": "js-family",
    "javascript": "js-family",
}


def _same_lang_family(a: str, b: str) -> bool:
    return _LANGUAGE_FAMILIES.get(a, a) == _LANGUAGE_FAMILIES.get(b, b)


class GraphBuilder:
    def __init__(self, allow_external: bool = True):
        self._graph = None
        self._node_map = {}
        self._allow_external = allow_external
        self.resolution_stats: dict[str, int] = {}

    def build(self, entities: list[Entity], edges: list[Edge],
              now: float | None = None):
        import rustworkx as rx
        import time as _time

        # One timestamp per build: resolved edges stamped per-link with
        # time.time() each got distinct valid_from values, so identical
        # builds never agreed on edge intervals.
        if now is None:
            now = _time.time()

        self._graph = rx.PyDiGraph()
        self._node_map = {}
        self.resolution_stats = {"resolved": 0, "ambiguous": 0, "missing": 0}

        pending: list[Edge] = []
        for entity in entities:
            idx = self._graph.add_node(entity)
            self._node_map[entity.revision_entity_id] = idx

        for edge in edges:
            # Unresolved references are never graph links (their dst is
            # empty — linking them would materialize a phantom external
            # node per call site). They resolve below, post-build, once
            # the full entity set is known.
            if edge.type in UNRESOLVED_TYPES:
                pending.append(edge)
                continue
            src_idx = self._node_map.get(edge.src_entity_id)
            dst_idx = self._node_map.get(edge.dst_entity_id)
            if src_idx is None and self._allow_external:
                src_idx = self._add_external(edge.src_entity_id, edge)
            if dst_idx is None and self._allow_external:
                dst_idx = self._add_external(edge.dst_entity_id, edge)
            if src_idx is not None and dst_idx is not None:
                self._graph.add_edge(src_idx, dst_idx, edge)

        self._resolve_deferred(pending, now)
        return self._graph

    def _resolve_deferred(self, pending: list[Edge], now: float) -> None:
        """Link references extraction could not resolve intra-file.

        Policy, stated plainly: exactly one eligible entity with the
        referenced name links; zero means the callee is outside the
        revision (builtins, libc, unmodeled) and two or more means the
        name is ambiguous across files. Both stay unlinked — a wrong
        link invents impact, a missing one merely undercounts it, and
        for a verification gate the former is the worse error.
        Deterministic: pending edges process in id order; resolution
        depends only on the loaded entity set, so every load of the
        same revision resolves identically.
        """
        by_lang: dict[str, str] = {}
        by_name: dict[str, list[str]] = {}
        # Qualified-name index built once per build: matching every
        # `ns::Base` reference against every node was O(pending x nodes).
        qual_index: dict[str, list[str]] = {}
        top_index: dict[str, list[str]] = {}
        for eid, idx in self._node_map.items():
            payload = self._graph[idx]
            if not hasattr(payload, "type") or not hasattr(payload, "name"):
                continue  # external placeholder nodes never resolve targets
            if payload.type in (EntityType.IMPORT, EntityType.MODULE,
                                EntityType.PARAMETER):
                continue
            by_name.setdefault(payload.name, []).append(eid)
            if payload.type in _BASE_TARGET_TYPES:
                qualified = (getattr(payload, "metadata", None) or {}).get(
                    "qualified_name")
                if qualified:
                    qual_index.setdefault(qualified, []).append(eid)
                else:
                    top_index.setdefault(payload.name, []).append(eid)
            language = getattr(payload, "language", "") or ""
            if language:
                by_lang[eid] = language

        for edge in sorted(pending, key=lambda e: e.id):
            src_idx = self._node_map.get(edge.src_entity_id)
            if src_idx is None:
                self.resolution_stats["missing"] += 1
                continue
            if edge.type == EdgeType.CALLS_UNRESOLVED:
                name = (edge.metadata or {}).get("callee", "")
                caller_lang = getattr(self._graph[src_idx], "language", "") or ""
                candidates = [
                    e for e in by_name.get(name, [])
                    if self._graph[self._node_map[e]].type in _CALL_TARGET_TYPES
                    # Same language family only: a Python `obj.add(x)`
                    # must not link a C `add` across the repo (unique-name
                    # policy is necessary but not sufficient). C and C++
                    # are one family — `.c` files routinely call
                    # header-defined functions (`.h` parses as C++) and
                    # `extern "C"` bridges both ways. Entities without
                    # recorded language (test fakes) match anything.
                    and (not caller_lang or _same_lang_family(
                        by_lang.get(e, caller_lang), caller_lang))]
                if len(candidates) != 1:
                    self.resolution_stats["ambiguous" if candidates else "missing"] += 1
                    continue
                self._link_resolved(edge, src_idx, candidates[0],
                                    EdgeType.CALLS, CPGEdgeSubtype.CALLS_DIRECT,
                                    now)
            elif edge.type == EdgeType.INHERITS_UNRESOLVED:
                name = (edge.metadata or {}).get("base", "")
                if "::" in name:
                    candidates = self._match_qualified(name, qual_index, top_index)
                else:
                    candidates = [e for e in by_name.get(name, [])
                                  if self._graph[self._node_map[e]].type in _BASE_TARGET_TYPES]
                if len(candidates) != 1:
                    self.resolution_stats["ambiguous" if candidates else "missing"] += 1
                    continue
                self._link_resolved(edge, src_idx, candidates[0],
                                    EdgeType.INHERITS, CPGEdgeSubtype.INHERITS,
                                    now)

    def _match_qualified(self, name: str, qual_index: dict | None = None,
                         top_index: dict | None = None) -> list[str]:
        """Match a qualified reference (`ns::Base`, `::Global`) against
        canonical `metadata["qualified_name"]` values.

        A leading `::` anchors to top level: it matches a top-level
        entity (no qualified name, bare name equal) but never a
        namespaced one. Unqualified refs never reach this path — flat
        `by_name` lookup handles them, unchanged.
        """
        anchored = name.startswith("::")
        bare = name.lstrip(":") if anchored else name
        if not bare:
            return []
        if qual_index is not None:
            if anchored:
                return list(qual_index.get(bare, ())) + list(
                    (top_index or {}).get(bare, ()))
            return list(qual_index.get(name, ()))
        matches = []
        for eid, idx in self._node_map.items():
            payload = self._graph[idx]
            if not hasattr(payload, "type") or not hasattr(payload, "name"):
                continue
            if payload.type not in _BASE_TARGET_TYPES:
                continue
            qualified = (getattr(payload, "metadata", None) or {}).get("qualified_name")
            if anchored:
                if qualified == bare or (not qualified and payload.name == bare):
                    matches.append(eid)
            elif qualified == name:
                matches.append(eid)
        return matches

    def _link_resolved(self, unresolved: Edge, src_idx: int, dst_eid: str,
                       edge_type: EdgeType, subtype: CPGEdgeSubtype,
                       now: float) -> None:
        dst_idx = self._node_map[dst_eid]
        self._graph.add_edge(src_idx, dst_idx, Edge(
            id=f"{unresolved.id}__{dst_eid}",
            revision_id=unresolved.revision_id,
            src_entity_id=unresolved.src_entity_id,
            dst_entity_id=dst_eid,
            type=edge_type,
            subtype=subtype,
            valid_from=now,
            observed_at=now,
            t_created=now,
            metadata={**(unresolved.metadata or {}), "deferred": True},
        ))
        self.resolution_stats["resolved"] += 1

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
