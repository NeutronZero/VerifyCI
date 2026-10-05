#!/usr/bin/env python3
"""CAP-003 mode generator: stdlib-only implementation of MODE_PROTOCOL.md.

Reads v1 cases + fixture, writes revised cases.jsonl + modes.json.
No verifyci imports. Deterministic.
"""
import ast
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
V1 = HERE.parent / "cases.jsonl"
FIXTURE = HERE.parent / "fixture"


def hunk_old_lines(diff: str) -> set[int]:
    lines: set[int] = set()
    for m in re.finditer(r"@@ -(\d+)(?:,(\d+))? \+", diff):
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) is not None else 1
        if count == 0:
            lines.add(start)
        else:
            lines.update(range(start, start + count))
    return lines


def function_spans(source: str) -> list[tuple[str, int, int]]:
    tree = ast.parse(source)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((node.name, node.lineno, node.end_lineno or node.lineno))
    return out


def main() -> None:
    cases = [json.loads(l) for l in V1.read_text(encoding="utf-8").splitlines() if l.strip()]
    revised = []
    modes = []
    for c in cases:
        src = (FIXTURE / c["file"]).read_text(encoding="utf-8")
        spans = function_spans(src)
        old = sorted(hunk_old_lines(c["diff"]))
        hits = sorted({name for name, s, e in spans if any(s <= ln <= e for ln in old)})
        if hits:
            mode = "seeded"
        else:
            mode = "known_gap" if c["expected_impacted"] else "known_gap_empty"
        modes.append({"id": c["id"], "old_lines": old,
                      "function_spans": [{"name": n, "start": s, "end": e} for n, s, e in spans],
                      "intersecting": hits, "mode": mode,
                      "mode_changed_vs_v1": mode != c["mode"]})
        r = dict(c)
        r["mode"] = mode
        revised.append(r)
    return revised, modes


def write_outputs(revised, modes, dest: Path) -> None:
    (dest / "cases.jsonl").write_text(
        "\n".join(json.dumps(c) for c in revised) + "\n", encoding="utf-8")
    (dest / "modes.json").write_text(json.dumps(modes, indent=1), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        import tempfile
        revised, modes = main()
        tmp = Path(tempfile.mkdtemp())
        write_outputs(revised, modes, tmp)
        for name in ("cases.jsonl", "modes.json"):
            a = hashlib.sha256((tmp / name).read_bytes()).hexdigest()
            b = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
            print(f"{name}: regenerated {'MATCHES' if a == b else 'DIFFERS'} committed")
        print("modes:", [(m["id"], m["mode"], "CHANGED" if m["mode_changed_vs_v1"] else "same") for m in modes])
    else:
        revised, modes = main()
        write_outputs(revised, modes, HERE)
        print("modes:", [(m["id"], m["mode"], "CHANGED" if m["mode_changed_vs_v1"] else "same") for m in modes])
