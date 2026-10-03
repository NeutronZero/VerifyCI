"""H3-B profiling scratch (NOT part of the frozen protocol).

Re-derives two predeclared mechanism claims OUTSIDE the frozen
measurement path, printing to stdout only (writes nothing):
  (1) per-edit-line cost spread reproduces (~20us...4ms by position);
  (2) wrapper-only cost is >=10x below p95-sample magnitudes.
Reuses the frozen harness's deterministic edit script verbatim; the
timed path itself is untouched. Any failure here stops H3 (protocol
is not adapted).
"""
import gc
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import measure as M  # noqa: E402 frozen harness, read-only use
from verifyci.ingestion.incremental import IncrementalParser  # noqa: E402


def per_line_spread() -> dict[int, list[int]]:
    src0 = (M.FIXTURE / "workload.py").read_bytes()
    M._preflight_shape(src0)
    ip = IncrementalParser("python")
    ip.parse(src0)
    src = src0
    by_line: dict[int, list[int]] = {}
    gc.collect()
    gc.disable()
    try:
        for i in range(M.N_PARSE):
            comment = f"  # v{i}".encode()
            line = (i % 37) + 8
            new_src, coords = M._insertion_at_eol(src, line, comment)
            ip.edit(*coords)
            t = time.perf_counter_ns()
            ip.parse(new_src)
            by_line.setdefault(line, []).append(time.perf_counter_ns() - t)
            src = new_src
    finally:
        gc.enable()
    return by_line


def wrapper_cost() -> dict[str, float]:
    ip = IncrementalParser("python")
    ip.parse(b"x = 1\n")
    n = 20000
    t = time.perf_counter_ns()
    for _ in range(n):
        ip._get_parser()
    lookup_ns = (time.perf_counter_ns() - t) / n
    tiny = b"x = 1\n"
    t = time.perf_counter_ns()
    for _ in range(2000):
        ip2 = IncrementalParser("python")
        ip2.parse(tiny)
    full_tiny_ns = (time.perf_counter_ns() - t) / 2000
    return {"get_parser_ns": lookup_ns, "tiny_parse_ns": full_tiny_ns}


def main() -> None:
    by_line = per_line_spread()
    medians = {ln: M.pct(sorted(v), 0.50) / 1e3 for ln, v in by_line.items()}
    lo_ln = min(medians, key=medians.get)
    hi_ln = max(medians, key=medians.get)
    print(f"lines measured: {len(medians)} (edit lines 8..44)")
    print(f"min-line median: line {lo_ln} = {medians[lo_ln]:.1f} us")
    print(f"max-line median: line {hi_ln} = {medians[hi_ln]:.1f} us")
    print(f"position spread reproduced: "
          f"{medians[lo_ln] < 100 and medians[hi_ln] > 1000}")
    w = wrapper_cost()
    print(f"wrapper _get_parser/call: {w['get_parser_ns']:.1f} ns")
    print(f"tiny-source full parse: {w['tiny_parse_ns']:.1f} ns")
    print(f"wrapper >=10x below p95 magnitudes (~4.2ms): "
          f"{w['tiny_parse_ns'] * 10 < 4.2e6}")


if __name__ == "__main__":
    main()
