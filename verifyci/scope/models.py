"""Data models for source facts and changed scope."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha1, sha256
from typing import Any, Mapping

from verifyci.contracts.model import Entity


@dataclass(frozen=True, slots=True)
class Param:
    name: str
    kind: str
    has_default: bool

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "has_default": self.has_default}


@dataclass(frozen=True, slots=True)
class CallSite:
    callee: str
    line: int
    positional: int
    keywords: tuple[str, ...]
    has_starargs: bool = False
    has_kwargs: bool = False
    is_shadowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "callee": self.callee,
            "line": self.line,
            "positional": self.positional,
            "keywords": list(self.keywords),
            "has_starargs": self.has_starargs,
            "has_kwargs": self.has_kwargs,
            "is_shadowed": self.is_shadowed,
        }


@dataclass(frozen=True, slots=True)
class ImportFact:
    module: str
    names: tuple[str, ...]
    line: int
    level: int = 0
    aliases: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class SourceFacts:
    path: str
    language: str
    supported: bool
    entities: tuple[Entity, ...] = ()
    calls: tuple[CallSite, ...] = ()
    imports: tuple[ImportFact, ...] = ()
    name_loads: frozenset[str] = frozenset()
    exports: frozenset[str] = frozenset()
    parse_error: str = ""
    has_dynamic_dispatch: bool = False
    has_unknown_decorator: bool = False
    _names: set[str] | None = field(
        default=None, init=False, repr=False, compare=False, hash=False
    )

    def names(self) -> set[str]:
        nms = self._names
        if nms is None:
            nms = {e.qname.rsplit(".", 1)[-1] for e in self.entities}
            object.__setattr__(self, "_names", nms)
        return nms


@dataclass(frozen=True, slots=True)
class ChangedScope:
    base_facts: Mapping[str, SourceFacts]
    head_facts: Mapping[str, SourceFacts]
    changed_entities: frozenset[str]
    base_entities: frozenset[str]
    head_entities: frozenset[str]
    unmapped_hunks: tuple[Mapping[str, Any], ...] = ()
    rename_limit_exceeded: bool = False
    mapped_hunks: tuple[Mapping[str, Any], ...] = ()
    mapped_entities: tuple[Mapping[str, Any], ...] = ()
    renames: tuple[Mapping[str, Any], ...] = ()
    _entity_index: dict[str, Entity] | None = field(
        default=None, repr=False, compare=False, hash=False
    )

    def __post_init__(self) -> None:
        if self._entity_index is not None:
            return
        idx: dict[str, Entity] = {}
        for facts in self.base_facts.values():
            for e in facts.entities:
                idx[e.qname] = e
        for facts in self.head_facts.values():
            for e in facts.entities:
                idx[e.qname] = e
        object.__setattr__(self, "_entity_index", idx)

    def entity(self, qname: str) -> Entity | None:
        return self._entity_index.get(qname) if self._entity_index is not None else None


def sha256_text(value: str) -> str:
    return "sha256:" + sha256(value.encode("utf-8")).hexdigest()


def git_blob_id(data: bytes) -> str:
    h = sha1()
    h.update(f"blob {len(data)}\0".encode("utf-8") + data)
    return h.hexdigest()


def blob_id_from_hash(blob_hash: str, source_bytes: bytes) -> str:
    if blob_hash:
        return blob_hash.split(":", 1)[1] if ":" in blob_hash else blob_hash
    return git_blob_id(source_bytes)


__all__ = [
    "CallSite",
    "ChangedScope",
    "ImportFact",
    "Param",
    "SourceFacts",
    "blob_id_from_hash",
    "git_blob_id",
    "sha256_text",
]
