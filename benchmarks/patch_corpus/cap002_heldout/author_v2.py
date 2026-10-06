"""CAP-002 held-out authoring: NEW semantic corpus, labels BEFORE measurement.

Runs ONCE now (not part of the suite). Builds diffs with difflib against
the frozen base/ so hunks are byte-valid. ground_truth + expected_status
are set from the documented verification contract BEFORE any verifier run:

- deterministic violation (forbid_call/forbid_import/secret/fabricated)
  -> FAIL (invariant scanners; v1 4/4 + mechanism)
- correct benign insertion/no-op in low-blast file -> PASS (v1 5/5 pattern)
- correct change in high-blast send.py -> HUMAN_REVIEW (v1 C3 mechanism:
  exposure >= threshold routes non-blocking fail to review)
- wrong semantic the gate cannot prove unsafe -> HUMAN_REVIEW (safe
  decline; the v1 PASS expectation encoded the old weakness and is NOT
  repeated here — this is the deliberate contract correction)
- brand-new module -> INCONCLUSIVE (v1 C7 mechanism: nothing established)

Frozen v1 cases.jsonl/results.json are never read or modified here.
"""
import difflib
import json
from collections import Counter
from pathlib import Path

BASE = Path("benchmarks/patch_corpus/base")
OUTDIR = Path("benchmarks/patch_corpus/cap002_heldout")


def read(rel):
    return (BASE / rel).read_text(encoding="utf-8").splitlines(keepends=True)


def edit(rel, old, new):
    lines = read(rel)
    hit, out = False, []
    for ln in lines:
        if not hit and ln.rstrip("\n") == old:
            out.append(new + "\n")
            hit = True
        else:
            out.append(ln)
    assert hit, f"line not found in {rel}: {old!r}"
    return "".join(lines), "".join(out)


def insert_after(rel, anchor, added):
    lines = read(rel)
    new_lines = [added] if isinstance(added, str) else list(added)
    out, done = [], False
    for ln in lines:
        out.append(ln)
        if not done and ln.rstrip("\n") == anchor:
            for a in new_lines:
                out.append(a.rstrip("\n") + "\n")
            done = True
    assert done, f"anchor not found in {rel}: {anchor!r}"
    return "".join(lines), "".join(out)


def diff(rel, a_text, b_text, fromfile=None):
    a = a_text.splitlines(keepends=True)
    b = b_text.splitlines(keepends=True)
    src = fromfile or f"a/{rel}"
    body = "".join(difflib.unified_diff(a, b, fromfile=src, tofile=f"b/{rel}", n=3))
    header = f"diff --git a/{rel} b/{rel}\n" if fromfile is None else fromfile
    return header + body


def diff_newfile(rel, b_text):
    b = b_text.splitlines(keepends=True)
    body = "".join(difflib.unified_diff([], b, fromfile="/dev/null", tofile=f"b/{rel}", n=3))
    return f"diff --git a/{rel} b/{rel}\n" + body


CASES = []


def add(cid, intent, gt, cat, expected, rationale, dtext):
    CASES.append({"id": cid, "intent": intent, "ground_truth": gt,
                  "category": cat, "expected_status": expected,
                  "label_rationale": rationale, "diff": dtext})


# ============ CORRECT (7) ============
a, b = insert_after("src/auth.py", "    return token", ["    # token issued"])
add("N-C1", "comment annotation on login return", "correct", "pass", "PASS",
    "comment-only insertion in low-blast file; nothing verifiable changes (v1 C5/C8 mechanism)",
    diff("src/auth.py", a, b))

a, b = insert_after("src/db.py", "    return sql.strip()", ["    return sql.strip().upper()"])
add("N-C2", "normalize db statement case", "correct", "pass", "PASS",
    "benign insertion mirroring v1 C2; no invariant, no exposure",
    diff("src/db.py", a, b))

a, b = insert_after("src/send.py", "    return len(msg)", ["    return len(msg or '')"])
add("N-C3", "harden send against None", "correct", "human_review", "HUMAN_REVIEW",
    "correct change in highest-blast fixture (8 callers): exposure routes to review per contract (v1 C3 mechanism)",
    diff("src/send.py", a, b))

a, b = insert_after("src/callers.py", '    send_email("h")', ['    send_email("z")'])
add("N-C4", "extra call in a leaf caller", "correct", "pass", "PASS",
    "benign insertion mirroring v1 C4; leaf-caller addition, no invariant",
    diff("src/callers.py", a, b))

a, b = insert_after("src/util.py", "    return x * 2", ["    return x * 2  # doubled"])
add("N-C5", "comment the doubling", "correct", "pass", "PASS",
    "comment-only; behavior identical (v1 C5 mechanism)",
    diff("src/util.py", a, b))

add("N-C6", "add a brand-new audit module", "correct", "inconclusive", "INCONCLUSIVE",
    "new file has no baseline: nothing established (v1 C7 mechanism)",
    diff_newfile("src/audit_new.py", '"""Audit helper."""\n\n\ndef audit(user):\n    return user\n'))

a, b = insert_after("src/auth.py", "    token = hash_pw(pw)", ["    # authenticated"])
add("N-C7", "comment the token line", "correct", "pass", "PASS",
    "comment-only insertion; no behavior change",
    diff("src/auth.py", a, b))

# ============ WRONG deterministic (4 -> FAIL) ============
a, b = insert_after("src/util.py", "    return x * 2", ["    eval(user_input)"])
add("N-W1", "eval on user input in util", "wrong", "forbid_call", "FAIL",
    "forbid_call:eval invariant fires regardless of file (v1 W1 mechanism)",
    diff("src/util.py", a, b))

lines = read("src/db.py")
ins = lines[:2] + ["import subprocess\n"] + lines[2:]
add("N-W2", "import subprocess in db", "wrong", "forbid_import", "FAIL",
    "forbid_import:subprocess invariant (v1 W2 mechanism)",
    diff("src/db.py", "".join(lines), "".join(ins)))

a, b = insert_after("src/db.py", "    return sql.strip()",
                    ['    pwd = "sk-live-9f8a7b6c5d4e"'])
add("N-W3", "hardcoded key in db", "wrong", "secret", "FAIL",
    "secrets scanner is content-based, file-agnostic (v1 W3 mechanism)",
    diff("src/db.py", a, b))

N_W4_DIFF = (
    "diff --git a/src/util.py b/src/util.py\n"
    "--- a/src/util.py\n+++ b/src/util.py\n"
    "@@ -3,4 +3,4 @@\n"
    ' """Leaf helper (no callers in-graph)."""\n'
    " \n"
    " \n"
    " def double(x):\n"
    "-    launch_missiles()\n"
    "+    return x * 2\n"
)
add("N-W4", "claim to remove a line util.py never had", "wrong", "fabricated_removal", "FAIL",
    "removal provenance: old-side line absent from base (v1 W4 mechanism)",
    N_W4_DIFF)

# ============ WRONG semantic (6 -> HUMAN_REVIEW decline) ============
a, b = edit("src/db.py", "    return sql.strip()", "    return sql")
add("N-S1", "drop sql normalization", "wrong", "semantic", "HUMAN_REVIEW",
    "silent behavior change the gate cannot prove unsafe: must decline, never PASS (contract correction vs v1 S1-S4)",
    diff("src/db.py", a, b))

a, b = edit("src/util.py", "    return x * 2", "    return x * 4")
add("N-S2", "change doubling to quadrupling", "wrong", "semantic", "HUMAN_REVIEW",
    "same class as v1 S4; decline required", diff("src/util.py", a, b))

a, b = edit("src/auth.py", "    return len(pw) >= 8", "    return len(pw) >= 6")
add("N-S3", "weaken password length to 6", "wrong", "semantic", "HUMAN_REVIEW",
    "same class as v1 S1; decline required", diff("src/auth.py", a, b))

a, b = edit("src/callers.py", '    send_email("a")', '    send_email("b")')
add("N-S4", "misroute first caller to b", "wrong", "semantic", "HUMAN_REVIEW",
    "modification (not insertion) of call routing in blast-exposed file: exposure + unverifiable intent -> review",
    diff("src/callers.py", a, b))

a, b = edit("src/send.py", "    return len(msg)", "    return 0")
add("N-S5", "send returns constant 0", "wrong", "semantic", "HUMAN_REVIEW",
    "silently breaks send contract in highest-blast fixture: decline required",
    diff("src/send.py", a, b))

a, b = edit("src/auth.py", "    return token", "    return pw")
add("N-S6", "return password instead of token", "wrong", "semantic", "HUMAN_REVIEW",
    "credential leak the gate cannot prove from evidence: decline required (v1 S3 class)",
    diff("src/auth.py", a, b))

OUTDIR.mkdir(parents=True, exist_ok=True)
with (OUTDIR / "cases.jsonl").open("w", encoding="utf-8") as fh:
    for c in CASES:
        fh.write(json.dumps(c, ensure_ascii=False) + "\n")

print(f"wrote {len(CASES)} cases -> {OUTDIR / 'cases.jsonl'}")
print("by category:", dict(Counter(c["category"] for c in CASES)))
print("by ground_truth:", dict(Counter(c["ground_truth"] for c in CASES)))
