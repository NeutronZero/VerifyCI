"""Identity evidence layer (roadmap item A).

Answers, WITHOUT changing any persistent identity: how often do
bare-name collisions currently exist, and which already-available
signal would separate each collision group?

A "collision group" is 2+ callable entities (FUNCTION/METHOD/CLASS)
sharing one bare name. For each group the report lists which of the
identity-evidence signals — qualified_name, scope, file_path,
entity type, source span — distinguishes every member from every
other. A group no signal separates is the residual that a logical-ID
migration must actually solve; everything else is already
disambiguated in stored metadata and needs no migration.

Read-only over the entity list. Deterministic: groups sorted by
(name, file, line); member rows sorted by file and span.
"""

CALLABLE_TYPES = frozenset({"FUNCTION", "METHOD", "CLASS"})

#: Evidence signals checked in this fixed order (strongest first).
SIGNALS = ("qualified_name", "scope", "file_path", "type", "span")


def _type_value(entity) -> str:
    t = getattr(entity, "type", None)
    return str(getattr(t, "value", t))


def _signal_value(entity, signal: str):
    meta = getattr(entity, "metadata", None) or {}
    if signal == "qualified_name":
        return meta.get("qualified_name") or ""
    if signal == "scope":
        return meta.get("scope") or ""
    if signal == "file_path":
        return getattr(entity, "file_path", "") or ""
    if signal == "type":
        return _type_value(entity)
    if signal == "span":
        return (getattr(entity, "line_start", 0) or 0,
                getattr(entity, "line_end", 0) or 0)
    raise ValueError(f"unknown identity signal: {signal}")


def _separates(members: list, signal: str) -> bool:
    """True when no two members share this signal's value.

    Empty values never separate: two entities that both lack a
    qualified_name are not distinguished by it.
    """
    seen = set()
    for m in members:
        v = _signal_value(m, signal)
        if not v:
            return False
        if v in seen:
            return False
        seen.add(v)
    return True


def collision_report(entities: list) -> dict:
    """Bare-name collision groups with per-signal separability.

    Returns {"groups": [...], "summary": {...}}. A group row holds
    the bare name, one member row per entity (file, type, scope,
    qualified_name, span), and the ordered list of signals that
    separate every member pair. The summary counts groups, collided
    entities, and groups separable by each signal (a group counts
    for every signal that separates it, strongest first in the row).
    """
    by_name: dict[str, list] = {}
    for e in entities:
        if _type_value(e) not in CALLABLE_TYPES:
            continue
        name = getattr(e, "name", "") or ""
        if not name:
            continue
        by_name.setdefault(name, []).append(e)

    groups = []
    for name in sorted(by_name):
        members = sorted(
            by_name[name],
            key=lambda e: (getattr(e, "file_path", "") or "",
                           getattr(e, "line_start", 0) or 0,
                           getattr(e, "line_end", 0) or 0),
        )
        if len(members) < 2:
            continue
        groups.append({
            "name": name,
            "size": len(members),
            "members": [{
                "file": getattr(e, "file_path", "") or "",
                "type": _type_value(e),
                "scope": (getattr(e, "metadata", None) or {}).get("scope") or "",
                "qualified_name": (getattr(e, "metadata", None) or {}).get(
                    "qualified_name") or "",
                "span": [getattr(e, "line_start", 0) or 0,
                         getattr(e, "line_end", 0) or 0],
            } for e in members],
            "distinguished_by": [s for s in SIGNALS if _separates(members, s)],
        })

    separable: dict[str, int] = {s: 0 for s in SIGNALS}
    for g in groups:
        for s in g["distinguished_by"]:
            separable[s] += 1
    return {
        "groups": groups,
        "summary": {
            "n_groups": len(groups),
            "n_collided_entities": sum(g["size"] for g in groups),
            "separable_by_signal": separable,
            "unseparable_groups": sum(
                1 for g in groups if not g["distinguished_by"]),
        },
    }
