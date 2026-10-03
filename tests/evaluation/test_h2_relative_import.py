"""H2-B failing-first: relative imports resolve via package hierarchy.

Residual `v2-gap-relative-import`: `from ..config import Config` never
links, so `forbid_import:config` misses. These tests pin the intended
OUTCOME (not the mechanism): the residual fires, unrelated relative
imports stay quiet, absolute imports behave exactly as before. They
FAIL until the resolver uses the source file's package hierarchy.
"""
from verifyci.contracts.verification_ir import Invariant
from verifyci.graph.builder import GraphBuilder
from verifyci.ingestion.extractor import extract_edges, extract_entities
from verifyci.ingestion.parser import TreeSitterParser
from verifyci.verification.intent_align import evaluate_invariants


def _inv(iid, query):
    return Invariant(invariant_id=iid, rule=iid, compiled_query=query, blocking=True)


def _graph(name, source: bytes):
    parsed = TreeSitterParser().parse(name, source, "python")
    ents = extract_entities(parsed, "repo", "rev1")
    edges = extract_edges(parsed, ents, "rev1")
    return GraphBuilder().build(ents, edges)


REL = b"from ..config import Config\n\ndef order():\n    return Config.load()\n"
OTHER = b"from ..other import Widget\n\ndef order():\n    return Widget()\n"
ABSOLUTE = b"import config\n\ndef order():\n    return config.load()\n"


def test_b_relative_import_fires_forbid():
    # The residual itself: whole-graph semantics (unattributed diff),
    # violation must be found once `..config` resolves.
    checks, _ = evaluate_invariants(
        "x", [_inv("i", "forbid_import:config")],
        graph=_graph("pkg/sub/mod.py", REL), evidence=[])
    assert checks[0].passed is False


def test_b_raw_dots_preserved_but_no_longer_defeat_matching():
    # extractor.py is whole-file hash-pinned by the latency guard, so
    # extraction keeps the raw `..config` form (see
    # test_relative_import_records_module_not_symbol): the dots stop
    # defeating the check at the MATCHING layer instead. Both facts
    # pinned together — raw form preserved, outcome correct.
    from verifyci.contracts.entity import EntityType
    parsed = TreeSitterParser().parse("pkg/sub/mod.py", REL, "python")
    ents = extract_entities(parsed, "repo", "rev1")
    imports = [e.name for e in ents if e.type == EntityType.IMPORT]
    assert imports == ["..config"]
    checks, _ = evaluate_invariants(
        "x", [_inv("i", "forbid_import:config")],
        graph=_graph("pkg/sub/mod.py", REL), evidence=[])
    assert checks[0].passed is False


def test_b_unrelated_relative_import_stays_quiet():
    checks, _ = evaluate_invariants(
        "x", [_inv("i", "forbid_import:config")],
        graph=_graph("pkg/sub/mod.py", OTHER), evidence=[])
    assert checks[0].passed is True


def test_b_absolute_import_behavior_unchanged():
    checks, _ = evaluate_invariants(
        "x", [_inv("i", "forbid_import:config")],
        graph=_graph("shop.py", ABSOLUTE), evidence=[])
    assert checks[0].passed is False
