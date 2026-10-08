from typing import Any

from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.edge import CPGEdgeSubtype, Edge, EdgeType
from verifyci.contracts.identity import compute_logical_entity_id
from verifyci.contracts.validate import validate_edge, validate_entity

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
    def __init__(self, allow_external: bool = True, collect_events: bool = False):
        self._graph = None
        self._node_map = {}
        self._allow_external = allow_external
        self._collect_events = collect_events
        self.resolution_stats: dict[str, int] = {}
        # Per-reference resolution log (roadmap item C calibration
        # dataset): one row per deferred edge when collect_events is
        # on, recording HOW it resolved for later accuracy labeling.
        # Off by default: empty, zero overhead, zero behavior change.
        self.resolution_events: list[dict] = []

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
        # Local alias: ty does not narrow attribute types across calls,
        # so the build body works through a narrowed local.
        graph = self._graph
        assert graph is not None
        self.resolution_stats = {"resolved": 0, "ambiguous": 0, "missing": 0}
        self.resolution_events = []

        pending: list[Edge] = []
        for entity in entities:
            entity_errors = validate_entity(entity)
            if entity_errors:
                raise ValueError(
                    f"invalid_graph_entity:{entity.revision_entity_id}:{entity_errors}"
                )
            idx = graph.add_node(entity)
            self._node_map[entity.revision_entity_id] = idx

        for edge in edges:
            edge_errors = validate_edge(edge)
            if edge_errors:
                raise ValueError(f"invalid_graph_edge:{edge.id}:{edge_errors}")
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
                graph.add_edge(src_idx, dst_idx, edge)

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
        graph = self._graph
        assert graph is not None  # only called post-build
        by_lang: dict[str, str] = {}
        by_name: dict[str, list[str]] = {}
        # Qualified-name index built once per build: matching every
        # `ns::Base` reference against every node was O(pending x nodes).
        qual_index: dict[str, list[str]] = {}
        top_index: dict[str, list[str]] = {}
        # Same, for qualified CALL targets (FUNCTION/METHOD/CLASS). The
        # inherits pair above covers CLASS/TYPE bases only; calls need
        # their own eligible set.
        call_qual_index: dict[str, list[str]] = {}
        call_top_index: dict[str, list[str]] = {}
        for eid, idx in self._node_map.items():
            payload = graph[idx]
            if not hasattr(payload, "type") or not hasattr(payload, "name"):
                continue  # external placeholder nodes never resolve targets
            if payload.type in (EntityType.IMPORT, EntityType.MODULE,
                                EntityType.PARAMETER):
                continue
            by_name.setdefault(payload.name, []).append(eid)
            meta = getattr(payload, "metadata", None)
            meta_dict = meta if isinstance(meta, dict) else {}
            if payload.type in _BASE_TARGET_TYPES:
                qualified = meta_dict.get("qualified_name")
                if qualified:
                    qual_index.setdefault(qualified, []).append(eid)
                else:
                    top_index.setdefault(payload.name, []).append(eid)
            if payload.type in _CALL_TARGET_TYPES:
                qualified = meta_dict.get("qualified_name")
                if qualified:
                    call_qual_index.setdefault(qualified, []).append(eid)
                else:
                    call_top_index.setdefault(payload.name, []).append(eid)
            language = getattr(payload, "language", "") or ""
            if language:
                by_lang[eid] = language

        for edge in sorted(pending, key=lambda e: e.id):
            src_idx = self._node_map.get(edge.src_entity_id)
            if src_idx is None:
                self.resolution_stats["missing"] += 1
                self._record(edge, "calls"
                             if edge.type == EdgeType.CALLS_UNRESOLVED else "inherits",
                             (edge.metadata or {}).get(
                                 "callee_qualified",
                                 (edge.metadata or {}).get(
                                     "callee", (edge.metadata or {}).get("base", ""))),
                             "unresolved-source", "missing", 0)
                continue
            if edge.type == EdgeType.CALLS_UNRESOLVED:
                name = (edge.metadata or {}).get("callee", "")
                caller_lang = getattr(graph[src_idx], "language", "") or ""
                qualified_ref = (edge.metadata or {}).get("callee_qualified", "")
                if qualified_ref and "::" in qualified_ref:
                    # A spelled `ns::helper` resolves ONLY canonically: a
                    # same-file bare `helper` must not capture it (same
                    # rule as qualified bases), and it must never fall
                    # back to the bare unique-name path below — linking
                    # a namespaced call to a top-level same-named entity
                    # invents impact. Zero or several canonical hits stay
                    # unlinked, fail closed.
                    candidates = [
                        e for e in self._match_qualified(
                            qualified_ref, call_qual_index, call_top_index)
                        if graph[self._node_map[e]].type in _CALL_TARGET_TYPES
                        and (not caller_lang or _same_lang_family(
                            by_lang.get(e, caller_lang), caller_lang))]
                    if len(candidates) != 1:
                        self.resolution_stats["ambiguous" if candidates else "missing"] += 1
                        self._record(edge, "calls", qualified_ref,
                                     "qualified-canonical",
                                     "ambiguous" if candidates else "missing",
                                     len(candidates))
                        continue
                    self._link_resolved(edge, src_idx, candidates[0],
                                        EdgeType.CALLS, CPGEdgeSubtype.CALLS_DIRECT,
                                        now, resolver="qualified-canonical")
                    self._record(edge, "calls", qualified_ref,
                                 "qualified-canonical", "resolved", 1)
                    continue
                receiver = (edge.metadata or {}).get("receiver", "")
                candidates = [
                    e for e in by_name.get(name, [])
                    if graph[self._node_map[e]].type in _CALL_TARGET_TYPES
                    # Same language family only: a Python `obj.add(x)`
                    # must not link a C `add` across the repo (unique-name
                    # policy is necessary but not sufficient). C and C++
                    # are one family — `.c` files routinely call
                    # header-defined functions (`.h` parses as C++) and
                    # `extern "C"` bridges both ways. Entities without
                    # recorded language (test fakes) match anything.
                    and (not caller_lang or _same_lang_family(
                        by_lang.get(e, caller_lang), caller_lang))]
                if receiver:
                    # Receiver-aware check: an attribute access `receiver.attr()` must not
                    # be captured by top-level bare functions (e.g. def get():) or unrelated classes.
                    # Only match if candidate is in a class/scope matching the receiver.
                    candidates = [
                        e for e in candidates
                        if (getattr(graph[self._node_map[e]], "metadata", {}).get("scope") == receiver
                            or getattr(graph[self._node_map[e]], "metadata", {}).get("identity_scope") == receiver)
                    ]
                if len(candidates) != 1:
                    self.resolution_stats["ambiguous" if candidates else "missing"] += 1
                    self._record(edge, "calls", f"{receiver}.{name}" if receiver else name,
                                 "receiver-aware" if receiver else "unique-bare-name",
                                 "ambiguous" if candidates else "missing",
                                 len(candidates))
                    continue
                self._link_resolved(edge, src_idx, candidates[0],
                                    EdgeType.CALLS, CPGEdgeSubtype.CALLS_DIRECT,
                                    now, resolver="unique-bare-name")
                self._record(edge, "calls", name, "unique-bare-name",
                             "resolved", 1)
            elif edge.type == EdgeType.INHERITS_UNRESOLVED:
                name = (edge.metadata or {}).get("base", "")
                if "::" in name:
                    candidates = self._match_qualified(name, qual_index, top_index)
                else:
                    candidates = [e for e in by_name.get(name, [])
                                  if graph[self._node_map[e]].type in _BASE_TARGET_TYPES]
                if len(candidates) != 1:
                    self.resolution_stats["ambiguous" if candidates else "missing"] += 1
                    self._record(edge, "inherits", name,
                                 "qualified-canonical"
                                 if "::" in name else "unique-bare-name",
                                 "ambiguous" if candidates else "missing",
                                 len(candidates))
                    continue
                self._link_resolved(edge, src_idx, candidates[0],
                                    EdgeType.INHERITS, CPGEdgeSubtype.INHERITS,
                                    now,
                                    resolver="qualified-canonical"
                                    if "::" in name else "unique-bare-name")
                self._record(edge, "inherits", name,
                             "qualified-canonical"
                             if "::" in name else "unique-bare-name",
                             "resolved", 1)

    def _record(self, edge, kind: str, ref: str, resolver: str,
                outcome: str, candidates: int) -> None:
        """Append one calibration row when collection is enabled.

        `outcome` is resolved|ambiguous|missing. `ref` is the spelled
        reference (bare name, or `ns::name` when the site spelled one).
        Ground truth labeling happens elsewhere; this only records the
        decision inputs so accuracy can be measured per resolver later.
        """
        if not self._collect_events:
            return
        graph = self._graph
        assert graph is not None  # only called post-build
        meta = edge.metadata or {}
        scope = meta.get("caller_scope", meta.get("scope", "")) or ""
        src = graph[self._node_map[edge.src_entity_id]] \
            if edge.src_entity_id in self._node_map else None
        self.resolution_events.append({
            "edge_id": edge.id,
            "kind": kind,
            "ref": ref,
            "resolver": resolver,
            "outcome": outcome,
            "candidates": candidates,
            "caller_language": getattr(src, "language", "") or "",
            "caller_scope_depth": len([s for s in str(scope).split(".") if s]),
            "spelled_qualified": "::" in ref,
        })

    def _match_qualified(self, name: str, qual_index: dict | None = None,
                         top_index: dict | None = None) -> list[str]:
        """Match a qualified reference (`ns::Base`, `::Global`) against
        canonical `metadata["qualified_name"]` values.

        A leading `::` anchors to top level: it matches a top-level
        entity (no qualified name, bare name equal) but never a
        namespaced one. Unqualified refs never reach this path — flat
        `by_name` lookup handles them, unchanged.
        """
        graph = self._graph
        assert graph is not None  # only called post-build
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
            payload = graph[idx]
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
                       now: float, resolver: str = "unique-bare-name") -> None:
        """Materialize a deferred reference as a graph link, stamped with
        HOW it resolved. `resolver` is `unique-bare-name` (exactly one
        entity carries the bare name) or `qualified-canonical` (the
        spelled `ns::name` matched one canonical `qualified_name`).
        Direct intra-file links carry no stamp — they are AST-direct by
        construction. The stamp is audit provenance ("why does VerifyCI
        believe this edge exists?"), never a confidence weight: nothing
        consumes it yet, and weighting it into risk scores is a
        separately-measured change.
        """
        assert self._graph is not None  # only called post-build
        graph = self._graph
        dst_idx = self._node_map[dst_eid]
        graph.add_edge(src_idx, dst_idx, Edge(
            id=f"{unresolved.id}__{dst_eid}",
            revision_id=unresolved.revision_id,
            src_entity_id=unresolved.src_entity_id,
            dst_entity_id=dst_eid,
            type=edge_type,
            subtype=subtype,
            valid_from=now,
            observed_at=now,
            t_created=now,
            metadata={**(unresolved.metadata or {}), "deferred": True,
                      "resolver": resolver},
        ))
        self.resolution_stats["resolved"] += 1

    def _add_external(self, endpoint: str, edge: Edge) -> int:
        """Materialize string endpoints (e.g. SBOM `pypi:requests`) as nodes
        so DEPENDS_ON edges reach the graph instead of being dropped."""
        assert self._graph is not None  # only called post-build
        graph = self._graph
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
                      "ecosystem": ((edge.metadata if isinstance(edge.metadata, dict) else {}) or {}).get("ecosystem", "")},
        )
        entity_errors = validate_entity(entity)
        if entity_errors:
            raise ValueError(
                f"invalid_external_graph_entity:{endpoint}:{entity_errors}"
            )
        idx = graph.add_node(entity)
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
