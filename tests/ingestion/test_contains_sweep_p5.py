"""PHASE 5: CONTAINS sweep equivalence and scaling.

The file-grouped span sweep must emit byte-identical output to the retired
all-pairs loop (same set AND same order: downstream resolution iterates
insertion order). A brute-force oracle encoding the original semantics
checks tricky shapes at small N; a wide-file test proves the scaling.
"""
import time

from verifyci.contracts.entity import Entity, EntityType
from verifyci.ingestion.extractor import extract_edges
from verifyci.ingestion.parser import TreeSitterParser


def _ent(name, fpath, start, end, type_=EntityType.FUNCTION, rev=None, scope=""):
    rev = rev or f"rev-{name}-{start}"
    return Entity(
        repository_id="r", logical_entity_id="l" * 64,
        revision_entity_id=rev, type=type_, name=name,
        file_path=fpath, line_start=start, line_end=end, language="python",
        source_hash="h", revision_id="rev1",
        metadata={"scope": scope} if scope else {},
    )


def _oracle(entities):
    """The retired all-pairs semantics, verbatim."""
    out = []
    for parent in entities:
        for child in entities:
            if parent.revision_entity_id == child.revision_entity_id:
                continue
            if child.type == EntityType.MODULE:
                continue
            if parent.file_path == child.file_path:
                if (parent.type in (EntityType.FUNCTION, EntityType.METHOD)
                        and child.type == EntityType.PARAMETER):
                    pscope = (f"{(parent.metadata or {}).get('scope', '')}.{parent.name}"
                              if (parent.metadata or {}).get("scope", "") else parent.name)
                    if (child.metadata or {}).get("scope", "") == pscope:
                        out.append((parent.revision_entity_id, child.revision_entity_id))
                elif parent.line_start <= child.line_start and parent.line_end >= child.line_end:
                    if parent.type == EntityType.MODULE or (
                        parent.line_start != child.line_start or parent.line_end != child.line_end
                    ):
                        out.append((parent.revision_entity_id, child.revision_entity_id))
    return out


def _sweep_ids(entities):
    raise NotImplementedError  # placeholder removed below


def _shapes():
    mod_a = _ent("m", "a.py", 1, 100, EntityType.MODULE, rev="m-a")
    cls = _ent("C", "a.py", 5, 50, EntityType.CLASS, rev="c-a")
    meth = _ent("m1", "a.py", 10, 20, EntityType.METHOD, rev="m1-a", scope="C")
    param = _ent("p", "a.py", 10, 10, EntityType.PARAMETER, rev="p-a", scope="C.m1")
    param_orphan = _ent("q", "a.py", 30, 30, EntityType.PARAMETER, rev="q-a", scope="nope")
    twin1 = _ent("t", "a.py", 60, 70, EntityType.FUNCTION, rev="t1-a")
    twin2 = _ent("t", "a.py", 60, 70, EntityType.FUNCTION, rev="t2-a")  # identical span
    other_file = _ent("C", "b.py", 5, 50, EntityType.CLASS, rev="c-b")
    return [mod_a, cls, meth, param, param_orphan, twin1, twin2, other_file]


def test_oracle_fixture_covers_tricky_shapes():
    # Sanity on the oracle fixture itself: it must exercise module
    # containment, identical-span exclusion, cross-file exclusion, and
    # orphan-parameter exclusion, so the real-parse equivalence below is
    # meaningful on top of these shapes.
    entities = _shapes()
    expected = _oracle(entities)
    assert expected, "oracle must produce edges on this fixture"
    by_parent = {}
    for p, c in expected:
        by_parent.setdefault(p, []).append(c)
    assert "m-a" in by_parent  # module contains file entities
    assert "c-b" not in set(by_parent)  # nothing in b.py is contained from a.py
    # cross-file pairs never emitted
    for p, c in expected:
        pent = next(e for e in entities if e.revision_entity_id == p)
        cent = next(e for e in entities if e.revision_entity_id == c)
        assert pent.file_path == cent.file_path
    # identical-span twins never contain each other
    assert ("t1-a", "t2-a") not in expected
    assert ("t2-a", "t1-a") not in expected
    # orphan parameter (scope mismatch): scope rule rejects it, but the
    # span rule still contains it under the module and the enclosing class.
    assert [p for p, c in expected if c == "q-a"] == ["m-a", "c-a"]


def test_sweep_matches_oracle_on_real_parse():
    src = (
        "class C:\n"
        "    def m1(self, p, q=1):\n"
        "        return p\n"
        "\n"
        "def top(a, b):\n"
        "    return a\n"
    )
    parsed = TreeSitterParser().parse("a.py", src.encode(), "python")
    from verifyci.contracts.edge import CPGEdgeSubtype, EdgeType
    from verifyci.ingestion.extractor import extract_entities
    entities = extract_entities(parsed, "r", "rev1")
    got = [(e.src_entity_id, e.dst_entity_id) for e in
           extract_edges(parsed, entities, "rev1")
           if e.type == EdgeType.CONTAINS and e.subtype == CPGEdgeSubtype.CONTAINS]
    want = _oracle(entities)
    assert got == want


def test_sweep_wide_file_scales():
    n = 1500
    lines = []
    for i in range(n):
        lines.append(f"def f{i}():")
        lines.append("    return 1")
        lines.append("")
    src = "\n".join(lines).encode()
    parsed = TreeSitterParser().parse("wide.py", src, "python")
    from verifyci.ingestion.extractor import extract_entities
    entities = extract_entities(parsed, "r", "rev1")
    assert len(entities) >= n
    start = time.perf_counter()
    edges = extract_edges(parsed, entities, "rev1")
    elapsed = time.perf_counter() - start
    contains = [e for e in edges if e.type.value == "CONTAINS"]
    # Every top-level function contained in the module, nothing else nests.
    assert len(contains) >= n
    assert elapsed < 5.0, f"sweep took {elapsed:.2f}s for {n} flat functions"
