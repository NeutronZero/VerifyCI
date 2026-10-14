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


def test_fixture_shims_reexport_live_api():
    import importlib
    pairs = [
        ("benchmarks.latency.fixture.extractor", "verifyci.ingestion.extractor",
         ["extract_entities", "extract_edges"]),
        ("benchmarks.latency.fixture.env", "verifyci.env",
         ["env_name", "get_env"]),
        ("benchmarks.latency.fixture.provider", "verifyci.retrieval.provider",
         ["EmbeddingProvider", "HashEmbeddingProvider", "SentenceTransformerProvider",
          "OllamaEmbeddingProvider", "CachedEmbeddingProvider", "default_dense_provider"]),
        ("benchmarks.latency.fixture.graph_store", "verifyci.storage.graph_store",
         ["GraphStore", "latest_revision_id"]),
        ("benchmarks.latency.fixture.intent_align", "verifyci.verification.intent_align",
         ["evaluate_invariants", "score_labeled"]),
    ]
    for fix_name, live_name, symbols in pairs:
        fix, live = importlib.import_module(fix_name), importlib.import_module(live_name)
        for sym in symbols:
            assert getattr(fix, sym) is getattr(live, sym), (fix_name, sym)


def test_frozen_sources_match_working_tree():
    """Attribution points at live sources, not fixture copies.

    The five fixture modules are thin re-exports (proved by
    test_fixture_shims_reexport_live_api), so hashing their bytes would
    pin shim boilerplate instead of the code the harness times.
    measure.LIVE_SOURCES maps each recorded name to the file whose bytes
    produce the recorded hash; workload.py stays a real file whose bytes
    the harness parses. Recorded-vs-live value equality after this
    change is enforced by test_rerun_reproduces_stable_claims (opt-in
    rerun, post-refresh); here the wiring is pinned so a renamed map or
    a fixture copy reintroduced under the same key fails without a
    re-measure.
    """
    import hashlib
    import sys
    test_fixture_shims_reexport_live_api()
    sys.path.insert(0, str(CORPUS))
    import measure
    recorded = _recorded()["frozen_sources"]
    assert set(measure.LIVE_SOURCES) == {
        "extractor.py", "graph_store.py", "intent_align.py",
        "provider.py", "env.py", "workload.py"}
    assert set(measure.LIVE_SOURCES) == set(recorded), (
        "LIVE_SOURCES keys drifted from recorded frozen_sources")
    for name, path in measure.LIVE_SOURCES.items():
        assert path.exists(), f"live source {name} missing: {path}"
        if name == "workload.py":
            assert path.resolve() == (CORPUS / "fixture" / "workload.py").resolve(), path
        else:
            assert "verifyci" in path.parts, (
                f"{name} not attributed to live tree: {path}")
            assert "fixture" not in path.parts, (
                f"{name} still hashed from fixture copy: {path}")
    recomputed = {n: hashlib.sha256(path.read_bytes()).hexdigest()
                  for n, path in measure.LIVE_SOURCES.items()}
    assert set(recomputed) == set(recorded)


def test_measured_path_does_not_import_provenance_sources():
    """Reproves, in a FRESH interpreter, that the provenance listings are
    off the timed call graph, so reconciling them is bookkeeping. A
    subprocess is required: in the full suite other tests have already
    loaded these modules, which would poison a sys.modules check."""
    import subprocess
    import sys
    code = (
        "import sys; import verifyci.ingestion.incremental; "
        "import verifyci.storage.graph_store; "
        "bad=[m for m in ('verifyci.verification.intent_align',"
        "'verifyci.retrieval.provider') if m in sys.modules]; "
        "print(','.join(bad))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, cwd=str(Path(HERE, "..", "..")))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "", f"on timed path: {out.stdout.strip()}"


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
