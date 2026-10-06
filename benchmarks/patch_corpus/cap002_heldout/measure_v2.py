#!/usr/bin/env python3
"""CAP-002 held-out measurement: verifier vs frozen-labeled new corpus.

Reads cap002_heldout/cases.jsonl (frozen BEFORE any run), ingests the
shared frozen base/, runs run_verify per case, writes results.json in the
revision dir. Frozen v1 artifacts untouched. Fails closed on missing corpus.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE.parent))


def main() -> None:
    import measure as m

    cases_path = HERE / "cases.jsonl"
    if not cases_path.exists():
        raise SystemExit("held-out corpus not frozen: run author_v2.py first")
    new_cases = [json.loads(line) for line in
                 cases_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    m.load_cases = lambda: new_cases
    table = m.run()
    metrics = m.compute_metrics(table)
    for t, c in zip(table, new_cases):
        t["expected"] = c["expected_status"]
    metrics = m.compute_metrics(table)
    print(f"{'id':22}{'expected':14}{'status':14}rationale")
    for t in table:
        flag = "" if t["status"] == t["expected"] else "   <-- differs"
        print(f"{t['id']:22}{t['expected']:14}{t['status']:14}{t['rationale'][:40]}{flag}")
    print("\nmetrics:", json.dumps({k: (dict(v) if not isinstance(v, (str, int, float, list, type(None))) else v)
                                   for k, v in metrics.items()}, indent=1, default=str))
    report = {"frozen": {"cases_sha256": hashlib.sha256(
                cases_path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()[:16]},
              "verdicts": table,
              "metrics": {k: (dict(v) if not isinstance(v, (str, int, float, list, type(None))) else v)
                          for k, v in metrics.items()}}
    out = HERE / "results.json"
    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"\nreport -> {out}")


if __name__ == "__main__":
    main()
