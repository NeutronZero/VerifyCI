"""One-time authoring tool: emit the FROZEN cases.jsonl.

Runs ONCE now (not part of the suite). Builds every diff with difflib
against the real base file text so context/offsets are byte-valid; the
fabricated-removal case is difflib of a real edit whose removed line's
content is then rewritten to a line that never existed (keeping the hunk
structurally valid). ground_truth + expected_status are set from the
documented contract BEFORE any measurement run; the produced jsonl is the
frozen data the measure step consumes.
"""
import difflib
import json
from collections import Counter
from pathlib import Path

BASE = Path("benchmarks/patch_corpus/base")


def read(rel):
    return (BASE / rel).read_text(encoding="utf-8").splitlines(keepends=True)


def edit(rel, old, new):
    """Return (a_text, b_text) with the first `old` line replaced by `new`."""
    lines = read(rel)
    hit = False
    out = []
    for ln in lines:
        if not hit and ln.rstrip("\n") == old:
            out.append(new + "\n")
            hit = True
        else:
            out.append(ln)
    assert hit, f"line not found in {rel}: {old!r}"
    return "".join(lines), "".join(out)


def insert_after(rel, anchor, added):
    """Insert `added` (str or list of lines) after the first line equal to `anchor`."""
    lines = read(rel)
    new_lines = [added] if isinstance(added, str) else list(added)
    out = []
    done = False
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


def add(cid, intent, gt, cat, expected, dtext):
    CASES.append({"id": cid, "intent": intent, "ground_truth": gt,
                  "category": cat, "expected_status": expected, "diff": dtext})


# =====================  CORRECT patches (ground_truth=correct) ============
a, b = insert_after("src/auth.py", "    token = hash_pw(pw)", ["    audit_log(user)"])
add("C1-login-audit", "record an audit log on login", "correct", "pass", "PASS",
    diff("src/auth.py", a, b))

a, b = insert_after("src/db.py", "    return sql.strip()", ["    return sql.strip().lower()"])
add("C2-db-normalize", "normalize db statement", "correct", "pass", "PASS",
    diff("src/db.py", a, b))

a, b = insert_after("src/send.py", "    return len(msg)", ["    notify_ops(msg)"])
add("C3-send-notify", "ops notification on send (high blast)", "correct", "human_review",
    "HUMAN_REVIEW", diff("src/send.py", a, b))

a, b = insert_after("src/callers.py", '    send_email("a")', ['    send_email("a2")'])
add("C4-caller-extra", "extra call in a leaf caller", "correct", "pass", "PASS",
    diff("src/callers.py", a, b))

a, b = insert_after("src/util.py", "    return x * 2", ["    return (x * 2)"])
add("C5-util-paren", "parenthesize util return (no-op)", "correct", "pass", "PASS",
    diff("src/util.py", a, b))

docs = read("README.md")
docs[-1] = "Documentation touch only.\n"
add("C6-readme-doc", "update documentation", "correct", "inconclusive", "INCONCLUSIVE",
    diff("README.md", "".join(read("README.md")), "".join(docs)))

add("C7-new-module", "add a brand-new helper module", "correct", "inconclusive", "INCONCLUSIVE",
    diff_newfile("src/brand_new.py", '"""New module."""\n\n\ndef fresh():\n    return 1\n'))

a, b = insert_after("src/auth.py", "    return pw[::-1]", ["    return pw[::-1]"])
add("C8-hash-echo", "restate hash return (no-op addition)", "correct", "pass", "PASS",
    diff("src/auth.py", a, b))

# ================= WRONG / deterministic (ground_truth=wrong, expected FAIL) ==
a, b = insert_after("src/auth.py", "    token = hash_pw(pw)", ["    eval(user_input)"])
add("W1-eval-call", "add eval on user input", "wrong", "forbid_call", "FAIL",
    diff("src/auth.py", a, b))

lines = read("src/auth.py")
ins = lines[:2] + ["import subprocess\n"] + lines[2:]
add("W2-subprocess-import", "import subprocess", "wrong", "forbid_import", "FAIL",
    diff("src/auth.py", "".join(lines), "".join(ins)))

a, b = insert_after("src/auth.py", "    token = hash_pw(pw)",
                    ['    api_key = "sk-live-9f8a7b6c5d4e"'])
add("W3-hardcoded-key", "store a hardcoded API key", "wrong", "secret", "FAIL",
    diff("src/auth.py", a, b))

# fabricated removal: hand-written valid hunk claiming to delete a line
# the base never had at that offset (old-side line 15 of login is
# `token = hash_pw(pw)`). Balanced -/+ keeps it a modification, not a
# deletion hunk, so FAIL comes from provenance, not inability.
W4_DIFF = (
    "diff --git a/src/auth.py b/src/auth.py\n"
    "--- a/src/auth.py\n+++ b/src/auth.py\n"
    "@@ -12,5 +12,5 @@\n"
    " def login(user, pw):\n"
    "     if not check_password(pw):\n"
    "         return None\n"
    "-    launch_missiles()\n"
    "+    token = hash_pw(pw)\n"
    "     return token\n"
)
add("W4-fabricated-removal", "claim to remove a line that never existed",
    "wrong", "fabricated_removal", "FAIL", W4_DIFF)

# ================= WRONG / semantic (ground_truth=wrong) ============
a, b = edit("src/auth.py", "    return len(pw) >= 8", "    return len(pw) >= 4")
add("S1-weak-validation", "weaken password length check", "wrong", "semantic", "PASS",
    diff("src/auth.py", a, b))

a, b = edit("src/auth.py", "    token = hash_pw(pw)", "    token = check_password(pw)")
add("S2-wrong-var", "use the wrong helper for the token", "wrong", "semantic", "PASS",
    diff("src/auth.py", a, b))

a, b = edit("src/auth.py", "    return token", "    return user")
add("S3-return-identity", "return the user instead of the token", "wrong", "semantic", "PASS",
    diff("src/auth.py", a, b))

a, b = edit("src/util.py", "    return x * 2", "    return x * 3")
add("S4-wrong-multiplier", "change doubling to tripling", "wrong", "semantic", "PASS",
    diff("src/util.py", a, b))

# semantic deletion of a security guard (net removal) -> declines
lines = read("src/auth.py")
kept = [ln for ln in lines if ln.rstrip("\n") not in
        ("    if not check_password(pw):", "        return None")]
add("S5-drop-guard", "remove the password validation guard", "wrong", "decline",
    "INCONCLUSIVE", diff("src/auth.py", "".join(lines), "".join(kept)))

OUT = Path("benchmarks/patch_corpus/cases.jsonl")
with OUT.open("w", encoding="utf-8") as fh:
    for c in CASES:
        fh.write(json.dumps(c, ensure_ascii=False) + "\n")

print(f"wrote {len(CASES)} cases -> {OUT}")
print("by category:", dict(Counter(c["category"] for c in CASES)))
print("by ground_truth:", dict(Counter(c["ground_truth"] for c in CASES)))
