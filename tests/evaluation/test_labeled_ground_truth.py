"""Labeled ground truth for invariant detection, loaded from data.

Each case carries a `source` (synthetic | flask-history:<sha> |
adversarial) so the provenance of every label is visible. Labels were
assigned from the rule text and the Flask history WITHOUT reading the
checker implementation first — near-misses were chosen from the shape of
real inputs (env files, aliased imports, relative imports, split
literals), not from knowledge of what the regex/graph walk matches.

Measured baseline (2026-09-28, 12 cases): recall 4/9, precision 4/4.
The fixture case (`flask-fixture-secret`) is a designed non-flag: the
allowlist demotes it to pass-with-`established=False` instead of a
violation flag, costing one recall point by design (pinned separately in
`test_fixture_demotes_instead_of_flagging`). Near-misses cost the other
four honestly.
Gates assert >= baseline - epsilon: regressions fail, improvements require
updating the recorded baseline with a review note.
"""
import json
from pathlib import Path

from src.contracts.verification_ir import FileEvidence, Invariant
from src.graph.builder import GraphBuilder
from src.ingestion.extractor import extract_edges, extract_entities
from src.ingestion.parser import TreeSitterParser
from src.verification.intent_align import score_labeled

LABELS = Path(__file__).parent / "labels" / "invariants.jsonl"

BASELINE_RECALL = 4 / 9
BASELINE_PRECISION = 1.0
EPSILON = 0.05

SHOP = b"""def order():
    return checkout("cart")

def checkout(cart):
    return cart
"""

SHOP_ALIAS = b"""import checkout as co

def order():
    return co("cart")

def checkout(cart):
    return cart
"""

SHOP_REL = b"""from ..config import Config

def order():
    return Config.load()
"""


def _graph(source: bytes, name: str = "shop.py"):
    parsed = TreeSitterParser().parse(name, source, "python")
    entities = extract_entities(parsed, "repo", "rev1")
    edges = extract_edges(parsed, entities, "rev1")
    builder = GraphBuilder()
    return builder.build(entities, edges)


GRAPHS = {
    "shop": lambda: _graph(SHOP),
    "shop-alias": lambda: _graph(SHOP_ALIAS),
    "shop-rel": lambda: _graph(SHOP_REL),
}


def _evidence(raw):
    return [FileEvidence(**e) for e in (raw or [])]


def load_cases():
    cases = []
    for line in LABELS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        inv = item["invariant"]
        invariant = Invariant(
            invariant_id=item["id"] + ":" + inv["id"],
            rule=inv["id"],
            compiled_query=inv["query"],
            blocking=inv.get("blocking", True),
        )
        graph = GRAPHS[item["graph"]]() if item.get("graph") else None
        cases.append((
            item["diff"], invariant, graph,
            _evidence(item.get("evidence")), bool(item["expected_violated"]),
        ))
    return cases


def test_labeled_ground_truth_meets_baseline():
    cases = load_cases()
    assert len(cases) == 12
    sources = {json.loads(l)["source"] for l in
               LABELS.read_text(encoding="utf-8").splitlines() if l.strip()}
    assert {"synthetic", "adversarial"} <= sources
    assert any(s.startswith("flask-history:") for s in sources)
    metrics = score_labeled(cases)
    assert metrics.check_coverage == 1.0
    assert metrics.detection_recall >= BASELINE_RECALL - EPSILON
    assert metrics.detection_precision >= BASELINE_PRECISION - EPSILON


def test_fixture_demotes_instead_of_flagging():
    # The allowlist path: fixture secrets pass with established=False, so
    # policy routes INCONCLUSIVE rather than FAIL — and the labeled-set
    # recall honestly excludes this case instead of claiming the flag.
    from src.contracts.verification_ir import Invariant
    from src.verification.intent_align import evaluate_invariants
    inv = Invariant(invariant_id="s", rule="s", compiled_query="secrets_scan",
                    blocking=True)
    diff = ("diff --git a/examples/tutorial/tests/conftest.py "
            "b/examples/tutorial/tests/conftest.py\n"
            "--- a/examples/tutorial/tests/conftest.py\n"
            "+++ b/examples/tutorial/tests/conftest.py\n"
            "@@ -1 +1 @@\n"
            '+    def login(self, username="test", password="test"):\n')
    (check,), _ = evaluate_invariants(diff, [inv], graph=None)
    assert check.passed is True
    assert check.established is False
    assert "allowlisted" in check.explanation
