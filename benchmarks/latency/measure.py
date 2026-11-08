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
from __future__ import annotations

from enum import Enum
import gc
import hashlib
import json
import math
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
import platform
import random
import shutil
import socket
import sys
import tempfile
import time
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

FIXTURE = HERE / "fixture"
LIVE_SOURCES = {
    "extractor.py": ROOT / "verifyci/ingestion/extractor.py",
    "graph_store.py": ROOT / "verifyci/storage/graph_store.py",
    "intent_align.py": ROOT / "verifyci/verification/intent_align.py",
    "provider.py": ROOT / "verifyci/retrieval/provider.py",
    "env.py": ROOT / "verifyci/env.py",
    "workload.py": FIXTURE / "workload.py",
}

FROZEN_SOURCE_HASHES = {
    "extractor.py": "cfb36a36e3e66792e692694815dbdf21e891b9a6c59a60d764ad7e30767dfd44",
    "graph_store.py": "7796d1fd82529a9b991a05b49ff59830ddc8f1847ad0494639f3becb8e79a074",
    "intent_align.py": "3abd0a48099bb3d2f06d2fce7de236be8a9d137fc187f25857d7001229393f87",
    "provider.py": "42f15e3fac5d5622aeacc5b0c6ee15f8e41bc37dccad70f887552565408efec9",
    "env.py": "7b373677981a73d392d8e3455395accefbcfe39fb06f7fe4ea3ae8f8a2e8d85a",
    "workload.py": "8e81eaa5901a7e301bede318e4a0bfc7efbb200c16e877ba05f9b071d9f903ea",
}
PROTOCOL_SHA256 = "fa87403543f0663403c22c557cad809cfbfd8233ae02c5c021f70790e346bcb1"
PROTOCOL_SHA256_CRLF = "efc6451e97f6fc65a731edab19f2043bb16a53f653d6b5c27bdb9a8f0e73d375"

# PLAN gate thresholds
MEDIAN_NS_LIMIT = 200_000      # < 0.2 ms
P95_NS_LIMIT = 1_000_000       # < 1.0 ms
P99_NS_LIMIT = 5_000_000       # < 5.0 ms
TEMPORAL_MS_LIMIT = 200.0
N_PARSE = 1000
N_QUERY = 1000
N_ENTS, N_VERSIONS, N_EDGES = 2000, 5, 10_000
MIN_SAMPLES = 30
MIN_P95_SAMPLES = 200
MIN_P99_SAMPLES = 1000
NOT_REPRODUCIBLE_STATUS = "NOT_REPRODUCIBLE_FROM_CURRENT_V3_CHECKOUT"


class BenchmarkIntegrityError(Exception):
    """Raised when benchmark inputs, protocol, or measurements fail integrity invariants."""


class MeasurementState(str, Enum):
    MEASURED = "MEASURED"
    NOT_MEASURED = "NOT_MEASURED"
    INVALID = "INVALID"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


MEASURED = MeasurementState.MEASURED.value
NOT_MEASURED = MeasurementState.NOT_MEASURED.value
INVALID = MeasurementState.INVALID.value
INSUFFICIENT_DATA = MeasurementState.INSUFFICIENT_DATA.value
VALID_STATES = frozenset({MEASURED, NOT_MEASURED, INVALID, INSUFFICIENT_DATA})


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _sha_normalized(p: Path) -> str:
    data = p.read_bytes()
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def check_protocol_integrity() -> tuple[bool, str | None]:
    """Verify that protocol configuration, workload fixtures, and sources match frozen hashes."""
    issues = []
    cfg = HERE / "config.json"
    if not cfg.is_file():
        issues.append("config.json missing")
    else:
        cfg_sha = _sha(cfg)
        cfg_sha_norm = _sha_normalized(cfg)
        if cfg_sha != PROTOCOL_SHA256 and cfg_sha_norm != PROTOCOL_SHA256 and cfg_sha != PROTOCOL_SHA256_CRLF:
            issues.append(f"config.json hash mismatch: expected {PROTOCOL_SHA256}, got {cfg_sha}")

    workload = FIXTURE / "workload.py"
    if not workload.is_file():
        issues.append("fixture/workload.py missing")
    else:
        wl_sha = _sha(workload)
        if wl_sha != FROZEN_SOURCE_HASHES["workload.py"]:
            issues.append(
                f"fixture/workload.py hash mismatch: expected {FROZEN_SOURCE_HASHES['workload.py']}, got {wl_sha}"
            )

    for name, src_path in LIVE_SOURCES.items():
        if name == "workload.py":
            continue
        if not src_path.is_file():
            issues.append(f"Required module missing: {name} (path: {src_path})")
        else:
            actual_sha = _sha(src_path)
            if actual_sha != FROZEN_SOURCE_HASHES[name]:
                issues.append(
                    f"Module {name} hash mismatch: expected {FROZEN_SOURCE_HASHES[name]}, got {actual_sha}"
                )

    if issues:
        return False, "; ".join(issues)
    return True, None


def _validate_samples(
    samples: Sequence[float | int], min_samples: int = MIN_SAMPLES
) -> tuple[str, str | None]:
    if not samples or len(samples) == 0:
        return NOT_MEASURED, "Zero samples recorded"
    if len(samples) < min_samples:
        return INSUFFICIENT_DATA, f"Insufficient sample count: {len(samples)} < {min_samples}"
    for s in samples:
        if not isinstance(s, (int, float)):
            return INVALID, f"Non-numeric sample: {s!r}"
        if math.isnan(s):
            return INVALID, "NaN duration detected"
        if math.isinf(s):
            return INVALID, "Infinite duration detected"
        if s < 0:
            return INVALID, f"Negative duration detected: {s}"
    return MEASURED, None


def _validate_measurement_record(
    record: Mapping[str, Any], record_type: str
) -> tuple[str, str | None]:
    if not isinstance(record, Mapping):
        return INVALID, f"{record_type} record is not a dictionary"
    state = record.get("state")
    if state not in VALID_STATES:
        return INVALID, f"{record_type} has invalid or missing state: {state!r}"
    if state != MEASURED:
        return state, record.get("error") or f"{record_type} state is {state}"

    if record_type == "incremental_parse":
        if "cold_ms" not in record or "warm_us" not in record:
            return INVALID, "incremental_parse record missing required fields ('cold_ms', 'warm_us')"
        cold = record["cold_ms"]
        if cold is None or not isinstance(cold, (int, float)) or math.isnan(cold) or math.isinf(cold) or cold < 0:
            return INVALID, f"cold_ms has invalid value: {cold!r}"
        warm = record["warm_us"]
        if not isinstance(warm, Mapping):
            return INVALID, "warm_us is not a dictionary"
        for key in ("n", "median", "p95", "p99", "max"):
            if key not in warm:
                return INVALID, f"warm_us missing required key: {key}"
            val = warm[key]
            if val is None or not isinstance(val, (int, float)) or math.isnan(val) or math.isinf(val) or val < 0:
                return INVALID, f"warm_us.{key} has invalid metric value: {val!r}"
        if warm["n"] < MIN_SAMPLES:
            return INSUFFICIENT_DATA, f"warm_us sample count {warm['n']} < {MIN_SAMPLES}"

    elif record_type == "temporal_query":
        if "ms" not in record or "n" not in record:
            return INVALID, "temporal_query record missing required fields ('ms', 'n')"
        if record["n"] < MIN_SAMPLES:
            return INSUFFICIENT_DATA, f"temporal_query sample count {record['n']} < {MIN_SAMPLES}"
        ms = record["ms"]
        if not isinstance(ms, Mapping):
            return INVALID, "ms is not a dictionary"
        for key in ("median", "p95", "p99", "max"):
            if key not in ms:
                return INVALID, f"temporal_query ms missing required key: {key}"
            val = ms[key]
            if val is None or not isinstance(val, (int, float)) or math.isnan(val) or math.isinf(val) or val < 0:
                return INVALID, f"temporal_query ms.{key} has invalid metric value: {val!r}"

    return MEASURED, None


def env_block() -> dict[str, Any]:
    mem = "unknown"
    try:
        import psutil  # noqa: PLC0415
        mem = f"{psutil.virtual_memory().total / 2**30:.1f} GiB"
    except Exception:  # noqa: BLE001 - psutil optional
        try:
            mem = f"{os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / 2**30:.1f} GiB"
        except Exception:  # noqa: BLE001
            pass
    return {
        "python": platform.python_version(),
        "build": platform.python_build()[0],
        "platform": platform.platform(),
        "machine": socket.gethostname(),
        "cpu_count": os.cpu_count(),
        "memory": mem,
        "run_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def pct(sorted_vals: Sequence[float | int], q: float) -> float | int:
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


def _preflight_shape(src0: bytes) -> None:
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


def measure_incremental() -> dict[str, Any]:
    try:
        from verifyci.ingestion.incremental import IncrementalParser
    except (ImportError, ModuleNotFoundError) as exc:
        return {
            "state": NOT_MEASURED,
            "error": f"ImportError: {exc}",
            "cold_ms": None,
            "warm_us": {"n": 0, "median": None, "p95": None, "p99": None, "max": None},
            "warm_us_first_half": {"median": None, "p95": None},
            "warm_us_second_half": {"median": None, "p95": None},
            "warm_samples_ns": [],
            "raw_median_ns": None,
            "raw_p95_ns": None,
            "raw_p99_ns": None,
        }

    workload_path = FIXTURE / "workload.py"
    if not workload_path.is_file():
        return {
            "state": INVALID,
            "error": "fixture/workload.py missing",
            "cold_ms": None,
            "warm_us": {"n": 0, "median": None, "p95": None, "p99": None, "max": None},
            "warm_samples_ns": [],
        }

    src0 = workload_path.read_bytes()
    expected_workload_hash = FROZEN_SOURCE_HASHES["workload.py"]
    if hashlib.sha256(src0).hexdigest() != expected_workload_hash:
        return {
            "state": INVALID,
            "error": "fixture/workload.py hash mismatch",
            "cold_ms": None,
            "warm_us": {"n": 0, "median": None, "p95": None, "p99": None, "max": None},
            "warm_samples_ns": [],
        }

    try:
        _preflight_shape(src0)   # raises loudly if the harness is broken
    except Exception as exc:
        return {
            "state": INVALID,
            "error": f"Preflight shape check failed: {exc}",
            "cold_ms": None,
            "warm_us": {"n": 0, "median": None, "p95": None, "p99": None, "max": None},
            "warm_samples_ns": [],
        }

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

    sample_state, sample_err = _validate_samples(warm, MIN_SAMPLES)
    if sample_state != MEASURED:
        return {
            "state": sample_state,
            "error": sample_err,
            "cold_ms": round(cold_ns / 1e6, 3) if cold_ns >= 0 and not math.isnan(cold_ns) else None,
            "warm_us": {"n": len(warm), "median": None, "p95": None, "p99": None, "max": None},
            "warm_samples_ns": warm,
        }

    w = sorted(warm)
    half = len(warm) // 2
    first, second = warm[:half], warm[half:]
    sf, ss = sorted(first), sorted(second)
    return {
        "state": MEASURED,
        "cold_ms": round(cold_ns / 1e6, 3),
        "warm_us": {
            "n": len(w),
            "median": round(pct(w, 0.50) / 1e3, 2),
            "p95": round(pct(w, 0.95) / 1e3, 2),
            "p99": round(pct(w, 0.99) / 1e3, 2),
            "max": round(w[-1] / 1e3, 2),
        },
        "warm_us_first_half": {
            "median": round(pct(sf, 0.50) / 1e3, 2),
            "p95": round(pct(sf, 0.95) / 1e3, 2),
        },
        "warm_us_second_half": {
            "median": round(pct(ss, 0.50) / 1e3, 2),
            "p95": round(pct(ss, 0.95) / 1e3, 2),
        },
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
            for v in range(N_VERSIONS):
                store.insert_revision(Revision(
                    revision_id=f"rev_{v}", repository_id="bench",
                    commit_id=None, parent_revision_id=None,
                    source_hash=f"bench_rev_{v}", timestamp=t0,
                    ingestion_config_hash="bench"))
            for k, lid in enumerate(lids):
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


def measure_temporal() -> dict[str, Any]:
    try:
        from verifyci.storage.graph_store import GraphStore
    except (ImportError, ModuleNotFoundError) as exc:
        return {
            "state": NOT_MEASURED,
            "error": f"ImportError: {exc}",
            "edges": 0,
            "entity_rows": 0,
            "db_mb": 0.0,
            "n": 0,
            "hit_rate": 0.0,
            "ms": {"median": None, "p95": None, "p99": None, "max": None},
            "raw_median_ns": None,
            "raw_p99_ns": None,
        }

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

    sample_state, sample_err = _validate_samples(samples, MIN_SAMPLES)
    if sample_state != MEASURED:
        return {
            "state": sample_state,
            "error": sample_err,
            "edges": n_edges,
            "entity_rows": n_ents,
            "db_mb": round(db_mb, 1),
            "n": len(samples),
            "hit_rate": round(hits / len(samples), 3) if samples else 0.0,
            "ms": {"median": None, "p95": None, "p99": None, "max": None},
            "raw_median_ns": None,
            "raw_p99_ns": None,
        }

    s = sorted(samples)
    return {
        "state": MEASURED,
        "edges": n_edges,
        "entity_rows": n_ents,
        "db_mb": round(db_mb, 1),
        "n": len(s),
        "hit_rate": round(hits / len(s), 3),
        "ms": {
            "median": round(pct(s, 0.50) / 1e6, 4),
            "p95": round(pct(s, 0.95) / 1e6, 4),
            "p99": round(pct(s, 0.99) / 1e6, 4),
            "max": round(s[-1] / 1e6, 4),
        },
        "raw_median_ns": pct(s, 0.50),
        "raw_p99_ns": pct(s, 0.99),
    }


def classify(
    ip: Mapping[str, Any], tq: Mapping[str, Any], *, strict: bool = True
) -> dict[str, Any]:
    """Classify benchmark measurements against performance thresholds.

    Invariant: NOT_MEASURED, INVALID, and INSUFFICIENT_DATA measurements can
    never establish a performance gate. Percentile gates require statistical
    sufficiency (>=200 for p95, >=1000 for p99).
    """
    ip_state, ip_err = _validate_measurement_record(ip, "incremental_parse")
    tq_state, tq_err = _validate_measurement_record(tq, "temporal_query")

    if ip_state != MEASURED or tq_state != MEASURED:
        err_msg = f"Integrity check failed: ip={ip_state} ({ip_err}), tq={tq_state} ({tq_err})"
        if strict:
            raise BenchmarkIntegrityError(err_msg)
        return {
            "incremental_median_lt_0.2ms": False,
            "incremental_p95_lt_1ms": False,
            "incremental_p99_lt_5ms": False,
            "temporal_p99_lt_200ms": False,
            "incremental_gate_established_this_host": False,
            "temporal_gate_established_this_host": False,
            "overall_status": "NOT_ESTABLISHED",
            "error": err_msg,
        }

    ip_n = ip["warm_us"]["n"]
    tq_n = tq["n"]

    median_sufficient = ip_n >= MIN_SAMPLES
    ip_p95_sufficient = ip_n >= MIN_P95_SAMPLES
    ip_p99_sufficient = ip_n >= MIN_P99_SAMPLES
    tq_p99_sufficient = tq_n >= MIN_P99_SAMPLES

    if strict and (not ip_p95_sufficient or not ip_p99_sufficient or not tq_p99_sufficient):
        raise BenchmarkIntegrityError(
            f"Percentile sample insufficiency: ip_n={ip_n} (need {MIN_P99_SAMPLES} for p99, "
            f"{MIN_P95_SAMPLES} for p95), tq_n={tq_n} (need {MIN_P99_SAMPLES} for p99)"
        )

    gates = {
        "incremental_median_lt_0.2ms": bool(median_sufficient and ip["warm_us"]["median"] < MEDIAN_NS_LIMIT / 1e3),
        "incremental_p95_lt_1ms": bool(ip_p95_sufficient and ip["warm_us"]["p95"] < P95_NS_LIMIT / 1e3),
        "incremental_p99_lt_5ms": bool(ip_p99_sufficient and ip["warm_us"]["p99"] < P99_NS_LIMIT / 1e3),
        "temporal_p99_lt_200ms": bool(tq_p99_sufficient and tq["ms"]["p99"] < TEMPORAL_MS_LIMIT),
    }
    gates["incremental_gate_established_this_host"] = (
        gates["incremental_median_lt_0.2ms"]
        and gates["incremental_p95_lt_1ms"]
        and gates["incremental_p99_lt_5ms"]
    )
    gates["temporal_gate_established_this_host"] = gates["temporal_p99_lt_200ms"]
    gates["sample_sufficiency"] = {
        "incremental_n": ip_n,
        "temporal_n": tq_n,
        "median_sufficient": median_sufficient,
        "incremental_p95_sufficient": ip_p95_sufficient,
        "incremental_p99_sufficient": ip_p99_sufficient,
        "temporal_p99_sufficient": tq_p99_sufficient,
    }
    gates["overall_status"] = (
        "MET"
        if gates["incremental_gate_established_this_host"] and gates["temporal_gate_established_this_host"]
        else "NOT_MET"
    )
    return gates


def save_results(target_path: Path | str, report: Mapping[str, Any]) -> None:
    """Save benchmark results to target_path, enforcing immutability of frozen results."""
    dest = Path(target_path).resolve()
    frozen = (HERE / "results.json").resolve()
    if dest == frozen:
        raise BenchmarkIntegrityError(
            "Attempt to overwrite frozen historical results.json is strictly forbidden."
        )
    dest.write_text(json.dumps(report, indent=2), encoding="utf-8")


def measure(*, strict: bool = False) -> dict[str, Any]:
    if not os.environ.get("VERIFYCI_LATENCY"):
        raise SystemExit(
            "set VERIFYCI_LATENCY=1 to run (loads tree-sitter grammars + tens of seconds; never silently in CI)"
        )
    valid, reason = check_protocol_integrity()
    ip = measure_incremental()
    tq = measure_temporal()
    gates = classify(ip, tq, strict=strict)

    status = (
        MEASURED
        if (valid and ip.get("state") == MEASURED and tq.get("state") == MEASURED)
        else NOT_REPRODUCIBLE_STATUS
    )

    report = {
        "protocol": "benchmarks/latency/config.json (frozen)",
        "protocol_sha256": _sha_normalized(HERE / "config.json"),
        "frozen_sources": {n: _sha(p) for n, p in LIVE_SOURCES.items() if p.is_file()},
        "environment": env_block(),
        "sample_counts": {"parse": N_PARSE, "query": N_QUERY},
        "integrity": {"valid": valid, "reason": reason},
        "state": status,
        "incremental_parse": ip,
        "temporal_query": tq,
        "gates": gates,
        "classification": (
            "measured + gate-estimated on this host; "
            "cross-machine establishment NOT claimed "
            "(latency is host-specific; only the protocol, "
            "source hashes, and environment are portable)"
            if status == MEASURED
            else f"C3 benchmark {NOT_REPRODUCIBLE_STATUS}: {reason or ip.get('error') or tq.get('error')}"
        ),
    }
    return report


def main() -> None:
    try:
        report = measure(strict=False)
    except Exception as exc:
        print(f"Benchmark error: {exc}", file=sys.stderr)
        raise SystemExit(1)

    ip = report["incremental_parse"]
    tq = report["temporal_query"]
    g = report["gates"]
    state = report.get("state")
    valid = report["integrity"]["valid"]

    if state != MEASURED or not valid:
        print(f"== BENCHMARK INTEGRITY FAILURE: {NOT_REPRODUCIBLE_STATUS} ==", file=sys.stderr)
        print(f"  Reason: {report['integrity']['reason'] or ip.get('error') or tq.get('error')}", file=sys.stderr)
        print("  All gates evaluated to FALSE (Fail-Closed).", file=sys.stderr)
        print("  Frozen results.json remains unmodified.", file=sys.stderr)
        raise SystemExit(1)

    print("== incremental parse (warm = tree-sitter reparse with edited tree, n=%d) ==" % ip["warm_us"]["n"])
    print("  cold full-parse baseline: %.3f ms" % ip["cold_ms"])
    print(
        f"  median {ip['warm_us']['median']:.1f} us | p95 {ip['warm_us']['p95']:.1f} us | "
        f"p99 {ip['warm_us']['p99']:.1f} us | max {ip['warm_us']['max']:.1f} us"
    )
    print(
        f"  gates  median<200us {'MET' if g['incremental_median_lt_0.2ms'] else 'MIS'} | "
        f"p95<1000us {'MET' if g['incremental_p95_lt_1ms'] else 'MIS'} | "
        f"p99<5000us {'MET' if g['incremental_p99_lt_5ms'] else 'MIS'}"
    )
    print("== temporal query at 10K edges (get_entity_as_of, n=%d) ==" % tq["n"])
    print(f"  DB: {tq['edges']:,} edges, {tq['entity_rows']:,} entity rows, {tq['db_mb']} MB, hit_rate {tq['hit_rate']}")
    print(
        f"  median {tq['ms']['median']:.4f} ms | p95 {tq['ms']['p95']:.4f} ms | "
        f"p99 {tq['ms']['p99']:.4f} ms | max {tq['ms']['max']:.4f} ms"
    )
    print(f"  gate   p99 <200ms {'MET' if g['temporal_p99_lt_200ms'] else 'MIS'}")
    print("\n" + report["classification"])


if __name__ == "__main__":
    main()
