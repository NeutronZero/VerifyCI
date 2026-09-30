"""One-time authoring: emit the FROZEN blast_corpus/cases.jsonl.

Expected impacted sets are derived BY HAND from the fixture topology
(core.py + app.py CALLS edges) and the documented blast contract (2 hops,
incoming+outgoing along CALL_FLOW_TYPES, seed excluded) BEFORE any blast
computation runs. difflib builds byte-valid hunks; `mode` documents the
predicted seeding path (normal vs the C1-exposed tail-insertion gap) but
the scorer compares detected-vs-frozen-topology-truth regardless.

Topology (caller -> callee):
  leaf  <- mid1, mid2
  mid1  -> leaf ;  <- hub
  mid2  -> leaf ;  <- hub
  hub   -> mid1, mid2 ; <- far, remote, handle
  far   -> hub
  isolated (no in/out)
  remote(app.py) -> hub ; Gateway.handle(app.py) -> hub
"""
import difflib
import json
from pathlib import Path

FIX = Path(__file__).resolve().parent / "fixture"


def text(rel):
    return (FIX / rel).read_text(encoding="utf-8")


def modify(rel, lineno, new_line):
    lines = text(rel).splitlines(keepends=True)
    assert lines[lineno - 1].strip(), f"line {lineno} is blank"
    lines[lineno - 1] = new_line + "\n"
    d = "".join(difflib.unified_diff(
        text(rel).splitlines(keepends=True), lines,
        fromfile=f"a/{rel}", tofile=f"b/{rel}", n=3))
    return f"diff --git a/{rel} b/{rel}\n" + d


def insert_after(rel, lineno, new_line):
    lines = text(rel).splitlines(keepends=True)
    lines.insert(lineno, new_line + "\n")
    d = "".join(difflib.unified_diff(
        text(rel).splitlines(keepends=True), lines,
        fromfile=f"a/{rel}", tofile=f"b/{rel}", n=3))
    return f"diff --git a/{rel} b/{rel}\n" + d


# hub 2-hop: in={far,remote,handle} out={mid1,mid2,leaf}
HUB = ["far", "remote", "handle", "mid1", "mid2", "leaf"]

CASES = [
    {"id": "B1-hub-midline", "seed": "hub",
     "diff": modify("src/core.py", 23, "    return mid1(x) + mid2(x)  # audit"),
     "expected_impacted": HUB, "mode": "seeded"},
    {"id": "B2-leaf-midline", "seed": "leaf",
     "diff": modify("src/core.py", 11, "    return x  # clamp"),
     "expected_impacted": ["mid1", "mid2", "hub"], "mode": "seeded"},
    {"id": "B3-isolated-zero", "seed": "isolated",
     "diff": modify("src/core.py", 31, "    return x  # noop"),
     "expected_impacted": [], "mode": "seeded"},
    {"id": "B4-far-change", "seed": "far",
     "diff": modify("src/core.py", 27, "    return hub(x) * 2 + 1"),
     "expected_impacted": ["hub", "mid1", "mid2"], "mode": "seeded"},
    {"id": "B5-hub-defline", "seed": "hub",
     "diff": modify("src/core.py", 22, "def hub(x):  # typed"),
     "expected_impacted": HUB, "mode": "seeded"},
    # tail-insertion: expected = full topology exposure; current seeding
    # yields nothing -> the C1 structural gap, measured not fixed.
    {"id": "B6-hub-tail-insert", "seed": "hub",
     "diff": insert_after("src/core.py", 23, "    # trailing audit note"),
     "expected_impacted": HUB, "mode": "known_gap"},
    {"id": "B7-isolated-tail-insert", "seed": "isolated",
     "diff": insert_after("src/core.py", 31, "    # trailing note"),
     "expected_impacted": [], "mode": "known_gap_empty"},
    {"id": "B8-method-callee", "seed": "handle",
     "diff": modify("src/app.py", 14, "        return hub(2)  # timeout"),
     "expected_impacted": ["hub", "mid1", "mid2"], "mode": "seeded"},
    # mid2 2-hop: in={hub(1),far,remote,handle(2)} out={leaf(1)}
    {"id": "B9-mid2-branch", "seed": "mid2",
     "diff": modify("src/core.py", 19, "    return leaf(x) + 2"),
     "expected_impacted": ["hub", "far", "remote", "handle", "leaf"],
     "mode": "seeded"},
]

out = Path(__file__).resolve().parent / "cases.jsonl"
with out.open("w", encoding="utf-8") as fh:
    for c in CASES:
        c["file"] = "src/core.py" if c["id"] != "B8-method-callee" else "src/app.py"
        fh.write(json.dumps(c, ensure_ascii=False) + "\n")
print(f"wrote {len(CASES)} cases -> {out}")
