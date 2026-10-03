"""H3-C final measurement (ONE run, no tuning).

Runs the frozen harness's measure() (read-only; never writes
results.json), classifies mechanically against the H3-A reproduction
and V1.0.2, and writes results_h3.json only. Branch stops (median /
temporal / preflight / pin regressions) raise instead of recording.
"""
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import measure as M  # noqa: E402 frozen harness, read-only use

H3A = {"median_us": 34.4, "p95_us": 4167.9, "p99_us": 6324.8,
       "temporal_p99_ms": 0.0622}
V102 = {"median_us": 35.7, "p95_us": 4250.0, "p99_us": 5110.0}


def main() -> None:
    r = M.measure()
    ip, tq, g = r["incremental_parse"], r["temporal_query"], r["gates"]
    measured = {
        "median_us": ip["warm_us"]["median"],
        "p95_us": ip["warm_us"]["p95"],
        "p99_us": ip["warm_us"]["p99"],
        "cold_ms": ip["cold_ms"],
        "temporal_p99_ms": tq["ms"]["p99"],
        "gates": g,
    }
    # Branch stops: median / temporal / preflight(_preflight_shape
    # raises inside measure_incremental) regressions fail loudly here.
    assert g["incremental_median_lt_0.2ms"], "median regressed past 0.2ms"
    assert g["temporal_p99_lt_200ms"], "temporal regressed"
    move = (measured["p95_us"] - H3A["p95_us"]) / H3A["p95_us"]
    if not g["incremental_p95_lt_1ms"] and abs(move) < 0.15:
        classification = "NEUTRAL"
    elif g["incremental_p95_lt_1ms"]:
        classification = "IMPROVED"
    else:
        classification = "REGRESSED"
    report = {
        "campaign": "H3-C final measurement (hoisted parse binding)",
        "frozen_reference": "v1.0.2-correctness",
        "h3a_reproduction": H3A,
        "v102_baseline": V102,
        "measured": measured,
        "p95_move_vs_h3a": round(move, 4),
        "classification": classification,
    }
    dest = HERE / "results_h3.json"
    if dest.exists() and not os.environ.get("VERIFYCI_REBENCHMARK"):
        raise SystemExit(f"{dest} exists; set VERIFYCI_REBENCHMARK=1 to overwrite")
    dest.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"H3-C: median={measured['median_us']}us p95={measured['p95_us']}us "
          f"p99={measured['p99_us']}us move={move:+.2%} -> {classification}")


if __name__ == "__main__":
    main()
