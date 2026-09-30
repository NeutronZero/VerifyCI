"""C3 latency repro guard (opt-in rerun; pinned protocol integrity).

Pins: sample counts, frozen-source hashes, protocol hash, and the
STABLE claims from the recorded run — median-level latencies (within a
machine-variance allowance) and the resulting gate classification.
Tail percentiles (p95/p99) are host-noisy (recorded run-to-run p99
crossed the 5ms limit in both directions on this box); they are stored
for attribution, asserted only within a 3x envelope. This guard proves
the protocol was not quietly changed; it never re-derives thresholds.

Run: set VERIFYCI_LATENCY_RERUN=1 && pytest tests/evaluation/test_latency_repro.py
Skips otherwise (loads tree-sitter grammars; slow).
"""
import json
import os
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
CORPUS = Path(HERE, "..", "..", "benchmarks", "latency")


def _recorded():
    return json.loads((CORPUS / "results.json").read_text(encoding="utf-8"))


def test_recorded_report_shape():
    r = _recorded()
    for key in ("protocol_sha256", "frozen_sources", "environment",
                "incremental_parse", "temporal_query", "gates",
                "classification"):
        assert key in r, key
    ip, tq, g = r["incremental_parse"], r["temporal_query"], r["gates"]
    # Recorded classification (2026-10-03, host run): temporal MET with
    # enormous margin; incremental median MET; p95/p99 NOT met, with the
    # mechanism recorded (edit-position re-lex distance, split-half +
    # per-line medians), not retuned.
    assert g["incremental_median_lt_0.2ms"] is True
    assert g["incremental_p95_lt_1ms"] is False
    assert g["temporal_gate_established_this_host"] is True
    assert tq["edges"] == 10_000 and tq["entity_rows"] == 10_000
    assert tq["hit_rate"] == 1.0
    # stability claims that held across BOTH recorded runs
    assert ip["warm_us"]["median"] < 200.0
    assert tq["ms"]["p99"] < 200.0  # 0.16ms - three orders of margin


def test_frozen_sources_match_working_tree():
    """The five measured-path sources must still equal the corpus copies."""
    r = _recorded()
    src_root = Path(HERE, "..", "..", "verifyci")
    mapping = {
        "graph_store.py": src_root / "storage" / "graph_store.py",
        "extractor.py": src_root / "ingestion" / "extractor.py",
        "intent_align.py": src_root / "verification" / "intent_align.py",
        "provider.py": src_root / "retrieval" / "provider.py",
        "env.py": src_root / "env.py",
    }
    import hashlib
    for name, live in mapping.items():
        want = r["frozen_sources"][name]
        got = hashlib.sha256(live.read_bytes()).hexdigest()
        assert got[:len(want)] == want, (
            f"verifyci/{name} changed since the frozen latency measurement "
            f"- re-run benchmarks/latency/measure.py and update the record")


@pytest.mark.skipif(os.environ.get("VERIFYCI_LATENCY_RERUN") != "1",
                    reason="re-measures (loads grammars); set VERIFYCI_LATENCY_RERUN=1")
def test_rerun_reproduces_stable_claims():
    import sys
    sys.path.insert(0, str(CORPUS))
    import measure
    os.environ["VERIFYCI_LATENCY"] = "1"
    r = measure.measure()
    rec = _recorded()
    assert r["protocol_sha256"] == rec["protocol_sha256"]
    assert r["frozen_sources"] == rec["frozen_sources"]
    assert r["sample_counts"] == rec["sample_counts"]
    im, rm = r["incremental_parse"], rec["incremental_parse"]
    # medians within +/-50%; tail within 3x (recorded host noise on p99
    # crossed its limit both ways - see guard docstring)
    assert abs(im["warm_us"]["median"] - rm["warm_us"]["median"]) \
        < 0.5 * rm["warm_us"]["median"]
    assert im["warm_us"]["p95"] < 3 * rm["warm_us"]["p95"]
    assert im["warm_us"]["p99"] < 3 * rm["warm_us"]["p99"]
    assert im["warm_us"]["median"] < 200.0  # median gate claim holds
    tm, rt = r["temporal_query"], rec["temporal_query"]
    assert tm["edges"] == rt["edges"] == 10_000
    assert tm["hit_rate"] == rt["hit_rate"] == 1.0
    assert tm["ms"]["median"] < 200.0 and tm["ms"]["p99"] < 200.0
