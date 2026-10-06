#!/usr/bin/env python3
"""Build clean, syntactically valid base fixture repository for CAP-005."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import shutil

from verifyci.verification.diffmap import iter_hunks

HERE = Path(__file__).resolve().parent
BASE_DIR = HERE / "base"


def build_file(filepath: str, hunks: list) -> str:
    # Compute max line number
    max_ln = 1
    for cid, h in hunks:
        max_ln = max(max_ln, h.old_start + max(h.old_count, 1) + 20)
    max_ln = max(max_ln, 150)

    lines = [f"# line {i+1}\n" for i in range(max_ln + 20)]
    lines[0] = '"""Module docstring."""\n'

    # Special case REAL-REM-03: src/auth.py
    if filepath == "src/auth.py":
        lines[9] = "def validate_token(tok):\n"
        lines[10] = "    return check_jwt(tok)\n"
        lines[11] = "    return False\n"
        lines[12] = "    return True\n"
        return "".join(lines[:25])

    # Special case REAL-REM-05: app/handlers.py
    if filepath == "app/handlers.py":
        return '"""App handlers."""\ndef process_event(event):\n    return True\n'

    # Add enclosing class/def definitions based on known file structure
    if filepath == "flask/sessions.py":
        lines[23] = "class SecureCookieSessionInterface:\n"
    elif filepath == "requests/adapters.py":
        lines[47] = "class HTTPAdapter:\n"
        lines[48] = "    def init_poolmanager(self):\n"
        lines[53] = "        pass\n"
    elif filepath == "requests/models.py":
        lines[73] = "class Response:\n"
    elif filepath == "requests/sessions.py":
        lines[108] = "class Session:\n"
    elif filepath == "src/click/core.py":
        lines[58] = "class Command:\n"
    elif filepath == "src/click/decorators.py":
        lines[48] = "def command_wrapper():\n"
    elif filepath == "src/click/exceptions.py":
        lines[28] = "class ClickException(Exception):\n"
    elif filepath == "src/flask/app.py":
        lines[43] = "class Flask:\n"
    elif filepath == "verifyci/ingestion/deps.py":
        lines[33] = "def check_dependencies(file_list):\n"
    elif filepath == "verifyci/storage/atomic.py":
        lines[13] = "def atomic_write(tmp_path, dest_path, data):\n"
    elif filepath == "src/crypto/hasher.py":
        lines[1] = "def hash_data(data):\n"
        lines[2] = "    return hashlib.sha256(data).hexdigest()\n"

    # Place hunk lines
    for cid, h in hunks:
        old_lines = [line_str[1:] for line_str in h.lines if not line_str.startswith("+") and not line_str.startswith("\\")]
        if not old_lines:
            continue
        start_idx = h.old_start - 1
        for i, old_l in enumerate(old_lines):
            lines[start_idx + i] = old_l if old_l.endswith("\n") else old_l + "\n"

    # Fix indentation and gaps: any colon statement followed by a comment gets a pass statement
    for i in range(len(lines) - 1):
        line = lines[i]
        stripped = line.strip()
        if stripped.endswith(":") and not stripped.startswith("#"):
            next_line = lines[i+1]
            if next_line.startswith("#") or not next_line.strip():
                indent = len(line) - len(line.lstrip(" ")) + 4
                lines[i+1] = " " * indent + "pass\n"

    # Ensure class definitions aren't broken by subsequent comments
    in_class = False
    for i in range(len(lines)):
        curr_line = lines[i]
        s = curr_line.strip()
        if s.startswith("class ") and s.endswith(":"):
            in_class = True
        elif in_class:
            if s.startswith("def ") or (curr_line.startswith(" ") and not s.startswith("#")):
                continue
            elif s.startswith("class ") or (s and not curr_line.startswith(" ") and not s.startswith("#")):
                in_class = False
            elif s.startswith("#"):
                # Replace top-level comment inside class with indented comment or pass
                pass

    return "".join(lines)


def generate_clean_base():
    if BASE_DIR.exists():
        shutil.rmtree(BASE_DIR)
    BASE_DIR.mkdir(parents=True, exist_ok=True)

    cases_file = HERE / "cases.jsonl"
    cases = [json.loads(line) for line in cases_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    file_hunks: dict[str, list] = {}
    for c in cases:
        for h in iter_hunks(c["diff"]):
            if not h.file:
                continue
            file_hunks.setdefault(h.file, []).append((c["id"], h))

    # Add core/handlers.py for collision test (REAL-REM-05)
    coll = BASE_DIR / "core" / "handlers.py"
    coll.parent.mkdir(parents=True, exist_ok=True)
    coll.write_text('"""Core handlers."""\ndef process_event(event):\n    core_log_event(event)\n    return True\n', encoding="utf-8")

    # Add billing service callers for checkout (REAL-HAL-06 blast exposure)
    svc = BASE_DIR / "src" / "billing" / "service.py"
    svc.parent.mkdir(parents=True, exist_ok=True)
    svc_lines = ['"""Billing service."""\nfrom .checkout import checkout\n']
    for i in range(10):
        svc_lines.append(f"def process_order_{i}(card):\n    return checkout(card)\n")
    svc.write_text("".join(svc_lines), encoding="utf-8")

    # Add test suite files to witness modules
    tests_dir = BASE_DIR / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    (tests_dir / "conftest.py").write_text('"""Fixtures."""\n', encoding="utf-8")
    test_modules = [
        ("test_partition.py", "def test_classify_path(): pass\n"),
        ("test_globals.py", "def test_globals(): pass\n"),
        ("test_compat.py", "def test_compat(): pass\n"),
        ("test_click.py", "def test_click(): pass\n"),
        ("test_core.py", "def test_core(): pass\n"),
        ("test_pipeline.py", "def test_pipeline(): pass\n"),
        ("test_stages.py", "def test_stages(): pass\n"),
        ("test_env_prefix.py", "def test_resolve_prefix(): pass\n"),
        ("test_sessions.py", "def test_sessions(): pass\n"),
        ("test_adapters.py", "def test_adapters(): pass\n"),
        ("test_utils.py", "def test_utils(): pass\n"),
        ("test_session.py", "def test_session(): pass\n"),
        ("test_decorators.py", "def test_decorators(): pass\n"),
        ("test_exceptions.py", "def test_exceptions(): pass\n"),
        ("test_routes.py", "def test_routes(): pass\n"),
        ("test_checkout.py", "def test_checkout(): pass\n"),
        ("test_hasher.py", "def test_hasher(): pass\n"),
    ]
    for t_name, t_code in test_modules:
        (tests_dir / t_name).write_text(t_code, encoding="utf-8")

    # Non-python files
    for filepath, hunks in sorted(file_hunks.items()):
        dest = BASE_DIR / filepath
        dest.parent.mkdir(parents=True, exist_ok=True)

        if not filepath.endswith(".py"):
            lines = ["# Base config\n"] * 50
            for cid, h in hunks:
                old_lines = [line_str[1:] for line_str in h.lines if not line_str.startswith("+") and not line_str.startswith("\\")]
                if not old_lines:
                    continue
                start = h.old_start - 1
                while len(lines) < start + len(old_lines) + 5:
                    lines.append("# pad\n")
                for i, old_l in enumerate(old_lines):
                    lines[start + i] = (old_l if old_l.endswith("\n") else old_l + "\n")
            dest.write_text("".join(lines), encoding="utf-8")
            continue

        if filepath == "src/helpers/system.py":
            # newly added file in REAL-CMP-04
            continue

        content = build_file(filepath, hunks)
        try:
            ast.parse(content)
        except SyntaxError as e:
            print(f"ERROR in {filepath}: {e}")
            raise
        dest.write_text(content, encoding="utf-8")

    # Invariants config
    verifyci_dir = BASE_DIR / ".verifyci"
    verifyci_dir.mkdir(parents=True, exist_ok=True)
    (verifyci_dir / "invariants.yaml").write_text(
        "invariants:\n"
        "  - id: no-eval\n"
        "    rule: forbid eval\n"
        "    query: forbid_call:eval\n"
        "    blocking: true\n"
        "  - id: no-subprocess\n"
        "    rule: forbid subprocess\n"
        "    query: forbid_import:subprocess\n"
        "    blocking: true\n",
        encoding="utf-8"
    )
    print("Clean base fixtures generated successfully with 0 AST errors.")


if __name__ == "__main__":
    generate_clean_base()
