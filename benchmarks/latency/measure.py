"""C3 latency measurement: incremental parse percentiles + temporal query at
10K edges. Protocol frozen in config.json BEFORE any timing; nothing under
verifyci/ changes (fixture/ pins sha256 of the five source files the
measured paths run through). The harness times the existing
IncrementalParser (tree-sitter reparse with edited tree) and
GraphStore.get_entity_as_of paths on THIS machine; a passing gate is
measured-and-estimated-on-this-host, not cross-machine-established.

Run:   set VERIFYCI_LATENCY=1 && python benchmarks/latency/measure.py
       (deliberate: this loads tree-sitter grammars and takes ~tens of
       seconds; not something CI should run silently.)

Opt-in rerun guard: tests/evaluation/test_latency_repro.py
       (set VERIFYCI_LATENCY_RERUN=1 to compare against recorded).
"""
import gc
import hashlib
import json
import math
import os
import platform
import random
import shutil
import socket
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

FIXTURE = HERE / "fixture"
FROZEN_SOURCES = ["extractor.py", "graph_store.py", "intent_align.py",
                  "provider.py", "env.py", "workload.py"]
# PLAN gate thresholds
MEDIAN_NS_LIMIT = 200_000      # < 0.2 ms
P95_NS_LIMIT = 1_000_000       # < 1.0 ms
P99_NS_LIMIT = 5_000_000       # < 5.0 ms
TEMPORAL_MS_LIMIT = 200.0
N_PARSE = 1000
N_QUERY = 1000
N_ENTS, N_VERSIONS, N_EDGES = 2000, 5, 10_000


def _sha(p: Path):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def env_block():
    mem = "unknown"
    try:
        import psutil  # noqa: PLC0415
        mem = f"{psutil.virtual_memory().total / 2**30:.1f} GiB"
    except Exception:  # noqa: BLE001 - psutil optional
        try:
            mem = f"{os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / 2**30:.1f} GiB"
        except Exception:  # noqa: BLE001
            pass
    return {"python": platform.python_version(),
            "build": platform.python_build()[0],
            "platform": platform.platform(),
            "machine": socket.gethostname(),
            "cpu_count": os.cpu_count(),
            "memory": mem,
            "run_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def pct(sorted_vals, q):
    if not sorted_vals:
        return float("nan")
    idx = max(0, math.ceil(q * len(sorted_vals)) - 1)
    return sorted_vals[idx]


# --------------------------- incremental parse ------------------------------
def _insertion_at_eol(src: bytes, line_0based: int, comment: bytes):
    """Return (new_src, edit-args-tuple) for a pure insertion of `comment`
    at end of line `line_0based` (before its newline). Coordinates follow
    the tree-sitter Tree.edit contract: (start_byte, old_end_byte,
    new_end_byte, start_point, old_end_point, new_end_point)."""
    lines = src.split(b"\n")
    ln = min(line_0based, len(lines) - 2)   # never touch last (usually empty) line
    old_line = lines[ln]
    start_byte = sum(len(x) + 1 for x in lines[:ln]) + len(old_line)
    new_end_byte = start_byte + len(comment)
    new_src = src[:start_byte] + comment + src[start_byte:]
    p0 = (ln, len(old_line))
    p1 = (ln, len(old_line) + len(comment))
    return new_src, (start_byte, start_byte, new_end_byte, p0, p0, p1)


def _preflight_shape(src0: bytes):
    """One-shot check: after one edit, incremental parse yields the SAME
    tree shape as a cold parse of the new source. If coords are wrong the
    reparse still returns *something*, so we must validate once before
    trusting the timings."""
    from verifyci.ingestion.incremental import IncrementalParser
    inc = IncrementalParser("python")
    inc.parse(src0)
    new_src, coords = _insertion_at_eol(src0, 12, b"  # v0")
    inc.edit(*coords)
    warm_root = inc.parse(new_src).root_node
    cold = IncrementalParser("python")
    cold_root = cold.parse(new_src).root_node
    assert (warm_root.type, warm_root.child_count,
            warm_root.start_byte, warm_root.end_byte) == (
            cold_root.type, cold_root.child_count,
            cold_root.start_byte, cold_root.end_byte), \
        "incremental reparse tree shape != cold parse - edit coords are wrong"


def measure_incremental():
    from verifyci.ingestion.incremental import IncrementalParser
    src0 = (FIXTURE / "workload.py").read_bytes()
    _preflight_shape(src0)   # raises loudly if the harness is broken

    cold = IncrementalParser("python")
    gc.collect()
    gc.disable()
    try:
        t0 = time.perf_counter_ns()
        cold.parse(src0)
        cold_ns = time.perf_counter_ns() - t0

        ip = IncrementalParser("python")
        ip.parse(src0)
        src = src0
        warm = []
        for i in range(N_PARSE):
            comment = f"  # v{i}".encode()
            line = (i % 37) + 8            # interior lines only
            new_src, coords = _insertion_at_eol(src, line, comment)
            ip.edit(*coords)
            t = time.perf_counter_ns()
            ip.parse(new_src)
            warm.append(time.perf_counter_ns() - t)
            src = new_src
    finally:
        gc.enable()
    w = sorted(warm)
    half = len(warm) // 2
    first, second = warm[:half], warm[half:]
    sf, ss = sorted(first), sorted(second)
    return {
        "cold_ms": round(cold_ns / 1e6, 3),
        "warm_us": {"n": len(w),
                    "median": round(pct(w, 0.50) / 1e3, 2),
                    "p95": round(pct(w, 0.95) / 1e3, 2),
                    "p99": round(pct(w, 0.99) / 1e3, 2),
                    "max": round(w[-1] / 1e3, 2)},
        # ordered split: distinguishes cumulative degradation (second half
        # slower) from uniform host noise (halves similar)
        "warm_us_first_half": {"median": round(pct(sf, 0.50) / 1e3, 2),
                               "p95": round(pct(sf, 0.95) / 1e3, 2)},
        "warm_us_second_half": {"median": round(pct(ss, 0.50) / 1e3, 2),
                                "p95": round(pct(ss, 0.95) / 1e3, 2)},
        "warm_samples_ns": warm,
        "raw_median_ns": pct(w, 0.50),
        "raw_p95_ns": pct(w, 0.95),
        "raw_p99_ns": pct(w, 0.99),
    }


# --------------------------- temporal query at 10K -------------------------
def build_scale_db(tmp_path: Path) -> tuple[str, int, int]:
    """Deterministic 10K-edge temporal DB via the frozen GraphStore."""
    from verifyci.contracts.edge import CPGEdgeSubtype, Edge, EdgeType
    from verifyci.contracts.entity import Entity, EntityType
    from verifyci.contracts.revision import Revision
    from verifyci.storage.graph_store import GraphStore
    db = tmp_path / "scale10k.db"
    store = GraphStore(str(db))
    rng = random.Random(20261003)
    t0 = 1_577_836_800.0                      # 2020-01-01 UTC
    span = 4 * 366 * 86_400.0                 # ~4 years incl. leap
    lids = [f"logical:{i:05d}" for i in range(N_ENTS)]
    try:
        with store.batch():
            # Writer connections enforce revision FKs: seed the revision
            # rows the entities/edges below point at (rev_0..rev_4).
            for v in range(N_VERSIONS):
                store.insert_revision(Revision(
                    revision_id=f"rev_{v}", repository_id="bench",
                    commit_id=None, parent_revision_id=None,
                    source_hash=f"bench_rev_{v}", timestamp=t0,
                    ingestion_config_hash="bench"))
            for k, lid in enumerate(lids):
                # N_VERSIONS temporal versions per logical id
                cuts = sorted(rng.uniform(t0, t0 + span) for _ in range(N_VERSIONS - 1))
                starts = [t0] + [c + 0.5 for c in cuts]
                ends = cuts + [None]
                for v in range(N_VERSIONS):
                    eid = hashlib.sha256(f"{lid}#{v}".encode()).hexdigest()
                    store.insert_entity(Entity(
                        repository_id="bench", logical_entity_id=lid,
                        revision_entity_id=eid, type=EntityType.FUNCTION,
                        name=f"f_{k}", file_path=f"src/mod_{k % 50}.py",
                        line_start=v + 1, line_end=v + 3, language="python",
                        source_hash=f"h_{k}_{v}", revision_id=f"rev_{v}",
                        valid_from=starts[v], valid_until=ends[v],
                        t_created=starts[v], t_expired=None))
                # one outgoing edge per entity to start
                store.insert_edge(Edge(
                    id=f"e_seed_{k}", revision_id="rev_4",
                    src_entity_id=lids[k],
                    dst_entity_id=lids[rng.randrange(N_ENTS)],
                    type=EdgeType.CALLS, subtype=CPGEdgeSubtype.CALLS_DIRECT,
                    valid_from=t0, valid_until=None, observed_at=t0,
                    t_created=t0))
            made = store.conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
            j = 0
            while made < N_EDGES:
                a = lids[rng.randrange(N_ENTS)]
                b = lids[rng.randrange(N_ENTS)]
                store.insert_edge(Edge(
                    id=f"e_pad_{j}", revision_id="rev_4", src_entity_id=a,
                    dst_entity_id=b, type=EdgeType.CALLS,
                    subtype=CPGEdgeSubtype.CALLS_DIRECT, valid_from=t0,
                    valid_until=None, observed_at=t0, t_created=t0))
                made += 1
                j += 1
            n_edges = store.conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
            n_ents = store.conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
            assert n_edges == N_EDGES and n_ents == N_ENTS * N_VERSIONS, (n_edges, n_ents)
    finally:
        store.close()
    return str(db), n_edges, n_ents


def measure_temporal():
    from verifyci.storage.graph_store import GraphStore
    tmp = Path(tempfile.mkdtemp())
    try:
        db, n_edges, n_ents = build_scale_db(tmp)
        store = GraphStore(db)
        rng = random.Random(20261004)
        lids = [r[0] for r in store.conn.execute(
            "SELECT DISTINCT logical_entity_id FROM entities ORDER BY logical_entity_id").fetchall()]
        t0, span = 1_577_836_800.0, 4 * 366 * 86_400.0
        mid = t0 + span / 2
        samples, hits = [], 0
        gc.collect()
        gc.disable()
        try:
            for _ in range(N_QUERY):
                lid = lids[rng.randrange(len(lids))]
                as_of = mid + rng.uniform(-span / 4, span / 4)
                t = time.perf_counter_ns()
                row = store.get_entity_as_of(lid, as_of)
                dt = time.perf_counter_ns() - t
                samples.append(dt)
                if row is not None:
                    hits += 1
        finally:
            gc.enable()
        db_mb = (Path(db).stat().st_size if Path(db).exists() else 0) / 1e6
        store.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    s = sorted(samples)
    return {"edges": n_edges, "entity_rows": n_ents, "db_mb": round(db_mb, 1),
            "n": len(s), "hit_rate": round(hits / len(s), 3),
            "ms": {"median": round(pct(s, 0.50) / 1e6, 4),
                   "p95": round(pct(s, 0.95) / 1e6, 4),
                   "p99": round(pct(s, 0.99) / 1e6, 4),
                   "max": round(s[-1] / 1e6, 4)},
            "raw_median_ns": pct(s, 0.50),
            "raw_p99_ns": pct(s, 0.99)}


def classify(ip, tq):
    gates = {
        "incremental_median_lt_0.2ms": ip["warm_us"]["median"] < MEDIAN_NS_LIMIT / 1e3,
        "incremental_p95_lt_1ms": ip["warm_us"]["p95"] < P95_NS_LIMIT / 1e3,
        "incremental_p99_lt_5ms": ip["warm_us"]["p99"] < P99_NS_LIMIT / 1e3,
        "temporal_p99_lt_200ms": tq["ms"]["p99"] < TEMPORAL_MS_LIMIT,
    }
    gates["incremental_gate_established_this_host"] = (
        gates["incremental_median_lt_0.2ms"]
        and gates["incremental_p95_lt_1ms"]
        and gates["incremental_p99_lt_5ms"])
    gates["temporal_gate_established_this_host"] = gates["temporal_p99_lt_200ms"]
    return gates


def measure():
    if not os.environ.get("VERIFYCI_LATENCY"):
        raise SystemExit("set VERIFYCI_LATENCY=1 to run (loads tree-sitter "
                         "grammars + tens of seconds; never silently in CI)")
    ip = measure_incremental()
    tq = measure_temporal()
    gates = classify(ip, tq)
    report = {
        "protocol": "benchmarks/latency/config.json (frozen)",
        "protocol_sha256": _sha(HERE / "config.json"),
        "frozen_sources": {n: _sha(FIXTURE / n) for n in FROZEN_SOURCES},
        "environment": env_block(),
        "sample_counts": {"parse": N_PARSE, "query": N_QUERY},
        "incremental_parse": ip,
        "temporal_query": tq,
        "gates": gates,
        "classification": "measured + gate-estimated on this host; "
                          "cross-machine establishment NOT claimed "
                          "(latency is host-specific; only the protocol, "
                          "source hashes, and environment are portable)",
    }
    return report


def main():
    report = measure()
    (HERE / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    ip, tq, g = report["incremental_parse"], report["temporal_query"], report["gates"]
    print("== incremental parse (warm = tree-sitter reparse with edited tree, n=%d) ==" % ip["warm_us"]["n"])
    print("  cold full-parse baseline: %.3f ms" % ip["cold_ms"])
    print(f"  median {ip['warm_us']['median']:.1f} us | p95 {ip['warm_us']['p95']:.1f} us | "
          f"p99 {ip['warm_us']['p99']:.1f} us | max {ip['warm_us']['max']:.1f} us")
    print(f"  gates  median<200us {'MET' if g['incremental_median_lt_0.2ms'] else 'MIS'} | "
          f"p95<1000us {'MET' if g['incremental_p95_lt_1ms'] else 'MIS'} | "
          f"p99<5000us {'MET' if g['incremental_p99_lt_5ms'] else 'MIS'}")
    print("== temporal query at 10K edges (get_entity_as_of, n=%d) ==" % tq["n"])
    print(f"  DB: {tq['edges']:,} edges, {tq['entity_rows']:,} entity rows, {tq['db_mb']} MB, hit_rate {tq['hit_rate']}")
    print(f"  median {tq['ms']['median']:.4f} ms | p95 {tq['ms']['p95']:.4f} ms | "
          f"p99 {tq['ms']['p99']:.4f} ms | max {tq['ms']['max']:.4f} ms")
    print(f"  gate   p99 <200ms {'MET' if g['temporal_p99_lt_200ms'] else 'MIS'}")
    print("\n" + report["classification"])
    print(f"report -> {HERE/'results.json'}")


if __name__ == "__main__":
    main()
