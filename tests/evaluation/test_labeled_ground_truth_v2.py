'''Expanded labeled corpus for secrets/forbid/provenance detection (B1).

Scanner implementation frozen — this file only measures. Labels were
frozen from the rule text BEFORE any scoring run (generator wrote the
jsonl; the scorer ran exactly once; the constants below record that
measurement). Two `known gap` cases are deliberately labeled violated
even though the documented residual does not reach them: unquoted values
below the scanner's stated 12-char floor, and a relative import the
graph resolver never links. Recording those misses is the point.

Mechanism diversity is structural, not decorative: the audited
triple-quoted pattern appears exactly ONCE. Eleven positive secret
mechanisms (aws, pem, jwt, credential-url, json-colon, keyword-quoted,
unquoted-env, triple, backslash-continuation, paren-continuation, yaml)
plus graph-direct forbid, diff-added forbid call/import, provenance
present/absent, unknown-kind fail-closed, and eight true negatives
(env/config lookups, comment, name-only, plain string, empty string,
graph-absent, evidence-present).

Measurement 2026-10-01, 26 cases: recall 16/18 = 0.889, precision
16/16 = 1.0. All 16 non-gap positives flagged; the only misses are the
two pre-declared known gaps; no negative fired. secrets_scan alone
11/12 = 0.917. Review note: v1 corpus measured 6/9 = 0.667; expansion
moved the number but the >=0.90 target is NOT met, and a 26-case corpus
would not "establish" the gate even above 0.90 — it remains
measured-not-established. Gates below are baselines-minus-epsilon: a
regression fails; improvements require updating the constant with a note.
'''
import json
from pathlib import Path

from verifyci.contracts.verification_ir import FileEvidence, Invariant
from verifyci.graph.builder import GraphBuilder
from verifyci.ingestion.extractor import extract_edges, extract_entities
from verifyci.ingestion.parser import TreeSitterParser
from verifyci.verification.intent_align import score_labeled

LABELS = Path(__file__).parent / "labels" / "invariants_v2.jsonl"

BASELINE_RECALL = 16 / 18
BASELINE_PRECISION = 1.0
EPSILON = 0.05

# Graph fixtures for the forbid_* cases, shared shape with the v1 corpus.
SHOP = b'def order():\n    return checkout("cart")\n\ndef checkout(cart):\n    return cart\n'
SHOP_REL = b"from ..config import Config\n\ndef order():\n    return Config.load()\n"


def _graph(source: bytes, name: str = "shop.py"):
    parsed = TreeSitterParser().parse(name, source, "python")
    entities = extract_entities(parsed, "repo", "rev1")
    edges = extract_edges(parsed, entities, "rev1")
    return GraphBuilder().build(entities, edges)


GRAPHS = {"shop": lambda: _graph(SHOP), "shop-rel": lambda: _graph(SHOP_REL)}


def _evidence(raw):
    return [FileEvidence(**e) for e in (raw or [])]


def load_v2_cases():
    cases = []
    for line in LABELS.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        inv = item["invariant"]
        invariant = Invariant(
            invariant_id=item["id"], rule=inv["id"],
            compiled_query=inv["query"], blocking=inv.get("blocking", True))
        graph = GRAPHS[item["graph"]]() if item.get("graph") else None
        cases.append((item["diff"], invariant, graph,
                      _evidence(item.get("evidence")), bool(item["expected_violated"])))
    return cases


def _items():
    return [json.loads(line) for line in
            LABELS.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_v2_meets_recorded_baseline():
    metrics = score_labeled(load_v2_cases())
    assert metrics.check_coverage == 1.0
    assert metrics.detection_recall >= BASELINE_RECALL - EPSILON
    assert metrics.detection_precision >= BASELINE_PRECISION - EPSILON


def test_v2_labels_are_frozen_and_bounded():
    items = _items()
    assert len(items) == 26
    assert {i["label_provenance"] for i in items} == {"author-informed"}
    assert {i["bucket"] for i in items} == {"true positive", "true negative", "known gap"}
    # The audited triple-quoted pattern must not dominate the evidence.
    triples = [i for i in items if "triple" in i["mechanism"]]
    assert len(triples) == 1
    # Distinct positive secret mechanisms: diversity floor.
    pos_mech = {i["mechanism"] for i in items
                if i["expected_violated"] and i["invariant"]["query"] == "secrets_scan"}
    assert len(pos_mech) >= 11
    # Exactly the two documented residual classes are intended misses.
    gaps = {i["id"] for i in items if i["bucket"] == "known gap"}
    assert gaps == {"v2-gap-short-unquoted", "v2-gap-relative-import"}


def test_v2_target_not_established_documented():
    # The >=0.90 V1 gate is NOT met at 16/18, and this corpus size would
    # not establish it even if met. Pinned so the number cannot be
    # quietly repackaged as a passed gate.
    metrics = score_labeled(load_v2_cases())
    assert metrics.detection_recall < 0.90
