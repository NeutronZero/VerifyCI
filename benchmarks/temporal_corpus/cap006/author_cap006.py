"""Authoring script for CAP-006: Temporal Lineage & Multi-Branch Replay Attestation Benchmark.

Constructs 64 stratified adversarial history cases across 8 slices:
1. rename_edit_rename_back (8 cases: TEMP-REN-01..08)
2. delete_and_restore (8 cases: TEMP-DEL-01..08)
3. revert_cycles (8 cases: TEMP-REV-01..08)
4. cherry_pick_cross_branch (8 cases: TEMP-CP-01..08)
5. interleaved_branch_ingest (8 cases: TEMP-BR-01..08)
6. criss_cross_merges (8 cases: TEMP-MRG-01..08)
7. stale_cache_and_idempotence (8 cases: TEMP-IDEM-01..08)
8. truncated_lineage_tripwire (8 cases: TEMP-TRIP-01..08)

LOCK-2: Evaluates every case using the Independent Temporal Oracle (oracle.py)
to generate labels.jsonl and oracle_manifest.jsonl.
Computes and emits cryptographic hashes: CORPUS_SHA256, LABEL_SHA256, ORACLE_MANIFEST_SHA256.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

# Ensure oracle can be imported directly
BENCHMARK_DIR = Path(__file__).resolve().parent
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

import oracle  # noqa: E402  # Independent reference oracle (zero verifyci dependencies)


def build_rename_slice() -> list[dict]:
    cases = []

    # TEMP-REN-01: Function rename A->B, edit B, rename B->A
    cases.append({
        "id": "TEMP-REN-01",
        "slice": "rename_edit_rename_back",
        "name": "Function rename calculate_tax -> compute_tax, edit rate, rename back",
        "description": "Rename function calculate_tax to compute_tax, edit logic, rename back to calculate_tax",
        "repository": "repo_temp_ren_01",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Initial tax calculator",
                "files": {"src/calc.py": "def calculate_tax(amount):\n    return amount * 0.10\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Rename calculate_tax to compute_tax",
                "files": {"src/calc.py": "def compute_tax(amount):\n    return amount * 0.10\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Edit compute_tax tax rate",
                "files": {"src/calc.py": "def compute_tax(amount):\n    return amount * 0.15\n"},
            },
            {
                "commit_id": "c4", "parent_id": "c3", "branch": "main",
                "message": "Rename compute_tax back to calculate_tax",
                "files": {"src/calc.py": "def calculate_tax(amount):\n    return amount * 0.15\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
            {"commit_id": "c4", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c4", "target_branch": "main"},
        "falsifier_class": "temporal_rename_cycle",
        "license": "MIT",
    })

    # TEMP-REN-02: File rename service.py -> service_v2.py -> service.py
    cases.append({
        "id": "TEMP-REN-02",
        "slice": "rename_edit_rename_back",
        "name": "File rename service.py -> service_v2.py -> service.py",
        "description": "Rename file service.py to service_v2.py, edit process_order, rename file back",
        "repository": "repo_temp_ren_02",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Add order service",
                "files": {"src/service.py": "def process_order(oid):\n    return f'Order {oid} processed'\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Rename file to service_v2.py",
                "files": {"src/service_v2.py": "def process_order(oid):\n    return f'Order {oid} processed'\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Update process_order implementation",
                "files": {"src/service_v2.py": "def process_order(oid):\n    return f'V2 Order {oid} processed'\n"},
            },
            {
                "commit_id": "c4", "parent_id": "c3", "branch": "main",
                "message": "Rename back to service.py",
                "files": {"src/service.py": "def process_order(oid):\n    return f'V2 Order {oid} processed'\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
            {"commit_id": "c4", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c4", "target_branch": "main"},
        "falsifier_class": "temporal_rename_cycle",
        "license": "MIT",
    })

    # TEMP-REN-03: Chain rename A -> B -> C -> D with caller tracking
    cases.append({
        "id": "TEMP-REN-03",
        "slice": "rename_edit_rename_back",
        "name": "Multi-hop rename chain format_record -> format_entry -> format_row -> format_item",
        "description": "Rename target through 4-stage chain; caller report_summary updates call site at each step",
        "repository": "repo_temp_ren_03",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Initial format_record and caller",
                "files": {
                    "src/formatter.py": "def format_record(data):\n    return str(data)\n",
                    "src/report.py": "def report_summary(items):\n    return [format_record(x) for x in items]\n",
                },
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Rename to format_entry",
                "files": {
                    "src/formatter.py": "def format_entry(data):\n    return str(data)\n",
                    "src/report.py": "def report_summary(items):\n    return [format_entry(x) for x in items]\n",
                },
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Rename to format_row",
                "files": {
                    "src/formatter.py": "def format_row(data):\n    return str(data)\n",
                    "src/report.py": "def report_summary(items):\n    return [format_row(x) for x in items]\n",
                },
            },
            {
                "commit_id": "c4", "parent_id": "c3", "branch": "main",
                "message": "Rename to format_item",
                "files": {
                    "src/formatter.py": "def format_item(data):\n    return str(data)\n",
                    "src/report.py": "def report_summary(items):\n    return [format_item(x) for x in items]\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
            {"commit_id": "c4", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c4", "target_branch": "main"},
        "falsifier_class": "temporal_rename_cycle",
        "license": "MIT",
    })

    # TEMP-REN-04: Swap rename: f1 and f2 swap names in c2, swap back in c3
    cases.append({
        "id": "TEMP-REN-04",
        "slice": "rename_edit_rename_back",
        "name": "Function name swap foo <-> bar and swap-back",
        "description": "Functions foo and bar swap names and implementations in c2, then swap back in c3",
        "repository": "repo_temp_ren_04",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Add foo and bar",
                "files": {"src/handlers.py": "def foo():\n    return 1\n\ndef bar():\n    return 2\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Swap foo and bar definitions",
                "files": {"src/handlers.py": "def foo():\n    return 2\n\ndef bar():\n    return 1\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Swap back foo and bar",
                "files": {"src/handlers.py": "def foo():\n    return 1\n\ndef bar():\n    return 2\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_rename_cycle",
        "license": "MIT",
    })

    # TEMP-REN-05: Directory rename: pkg/auth -> pkg/security -> pkg/auth
    cases.append({
        "id": "TEMP-REN-05",
        "slice": "rename_edit_rename_back",
        "name": "Directory tree rename pkg/auth -> pkg/security -> pkg/auth",
        "description": "Relocate directory containing auth tokens, modify validator, rename directory back",
        "repository": "repo_temp_ren_05",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Initial auth module",
                "files": {"pkg/auth/tokens.py": "def validate_token(tok):\n    return len(tok) > 10\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Move to pkg/security",
                "files": {"pkg/security/tokens.py": "def validate_token(tok):\n    return len(tok) > 10\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Harden validator",
                "files": {"pkg/security/tokens.py": "def validate_token(tok):\n    return len(tok) >= 16\n"},
            },
            {
                "commit_id": "c4", "parent_id": "c3", "branch": "main",
                "message": "Move back to pkg/auth",
                "files": {"pkg/auth/tokens.py": "def validate_token(tok):\n    return len(tok) >= 16\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
            {"commit_id": "c4", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c4", "target_branch": "main"},
        "falsifier_class": "temporal_rename_cycle",
        "license": "MIT",
    })

    # TEMP-REN-06: Disambiguate rename vs new entity creation
    cases.append({
        "id": "TEMP-REN-06",
        "slice": "rename_edit_rename_back",
        "name": "Disambiguate rename authenticate->auth_v2 with concurrent new authenticate",
        "description": "Function renamed while new helper with same name created concurrently; then reverted",
        "repository": "repo_temp_ren_06",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Initial authenticate",
                "files": {"src/auth.py": "def authenticate(user, pwd):\n    return user == 'admin'\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Rename original to auth_v2 and introduce new lightweight authenticate",
                "files": {
                    "src/auth.py": (
                        "def auth_v2(user, pwd):\n    return user == 'admin'\n\n"
                        "def authenticate(user):\n    return user != ''\n"
                    )
                },
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Revert to original single authenticate",
                "files": {"src/auth.py": "def authenticate(user, pwd):\n    return user == 'admin'\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_rename_cycle",
        "license": "MIT",
    })

    # TEMP-REN-07: Class method rename: charge -> process_charge -> charge
    cases.append({
        "id": "TEMP-REN-07",
        "slice": "rename_edit_rename_back",
        "name": "Class method rename PaymentGateway.charge -> process_charge -> charge",
        "description": "Rename class member method, update caller method, then rename back",
        "repository": "repo_temp_ren_07",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Initial payment gateway",
                "files": {
                    "src/gateway.py": (
                        "class PaymentGateway:\n"
                        "    def charge(self, amount):\n        return True\n\n"
                        "    def pay(self, amount):\n        return self.charge(amount)\n"
                    )
                },
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Rename charge to process_charge",
                "files": {
                    "src/gateway.py": (
                        "class PaymentGateway:\n"
                        "    def process_charge(self, amount):\n        return True\n\n"
                        "    def pay(self, amount):\n        return self.process_charge(amount)\n"
                    )
                },
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Rename back to charge",
                "files": {
                    "src/gateway.py": (
                        "class PaymentGateway:\n"
                        "    def charge(self, amount):\n        return True\n\n"
                        "    def pay(self, amount):\n        return self.charge(amount)\n"
                    )
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_rename_cycle",
        "license": "MIT",
    })

    # TEMP-REN-08: Rapid rename ping-pong across 5 commits: A -> B -> A -> B -> A
    cases.append({
        "id": "TEMP-REN-08",
        "slice": "rename_edit_rename_back",
        "name": "Rapid rename ping-pong across 5 commits",
        "description": "Oscillating rename between dispatch_event and handle_event across 5 revisions",
        "repository": "repo_temp_ren_08",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Initial dispatch_event",
                "files": {"src/bus.py": "def dispatch_event(ev):\n    return ev.type\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Rename to handle_event",
                "files": {"src/bus.py": "def handle_event(ev):\n    return ev.type\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Rename back to dispatch_event",
                "files": {"src/bus.py": "def dispatch_event(ev):\n    return ev.type\n"},
            },
            {
                "commit_id": "c4", "parent_id": "c3", "branch": "main",
                "message": "Rename to handle_event again",
                "files": {"src/bus.py": "def handle_event(ev):\n    return ev.type\n"},
            },
            {
                "commit_id": "c5", "parent_id": "c4", "branch": "main",
                "message": "Rename back to dispatch_event final",
                "files": {"src/bus.py": "def dispatch_event(ev):\n    return ev.type\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
            {"commit_id": "c4", "branch": "main"},
            {"commit_id": "c5", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c5", "target_branch": "main"},
        "falsifier_class": "temporal_rename_cycle",
        "license": "MIT",
    })

    return cases


def build_delete_restore_slice() -> list[dict]:
    cases = []

    # TEMP-DEL-01: Delete function legacy_helper in c2, restore identically in c3
    cases.append({
        "id": "TEMP-DEL-01",
        "slice": "delete_and_restore",
        "name": "Delete helper in c2, restore identically in c3",
        "description": "Function legacy_helper removed then restored; checks valid_until closure and re-activation",
        "repository": "repo_temp_del_01",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Initial module with legacy_helper",
                "files": {"src/helpers.py": "def legacy_helper(x):\n    return x + 1\n\ndef active_helper(x):\n    return x * 2\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Remove legacy_helper",
                "files": {"src/helpers.py": "def active_helper(x):\n    return x * 2\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Restore legacy_helper",
                "files": {"src/helpers.py": "def legacy_helper(x):\n    return x + 1\n\ndef active_helper(x):\n    return x * 2\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_disappearance_closure",
        "license": "MIT",
    })

    # TEMP-DEL-02: Delete entire file in c2, restore with new helper in c3
    cases.append({
        "id": "TEMP-DEL-02",
        "slice": "delete_and_restore",
        "name": "Delete whole file utils.py in c2, restore with additions in c3",
        "description": "Entire file deleted in c2, restored with additional function in c3",
        "repository": "repo_temp_del_02",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Initial utils.py and main.py",
                "files": {
                    "src/main.py": "def run():\n    return 'running'\n",
                    "src/utils.py": "def string_clean(s):\n    return s.strip()\n",
                },
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Delete utils.py",
                "files": {
                    "src/main.py": "def run():\n    return 'running'\n",
                },
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Restore utils.py with string_clean and string_pad",
                "files": {
                    "src/main.py": "def run():\n    return 'running'\n",
                    "src/utils.py": "def string_clean(s):\n    return s.strip()\n\ndef string_pad(s):\n    return s.center(10)\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_disappearance_closure",
        "license": "MIT",
    })

    # TEMP-DEL-03: Delete function with external caller, caller edge breaks then re-binds
    cases.append({
        "id": "TEMP-DEL-03",
        "slice": "delete_and_restore",
        "name": "Delete function parse_header with caller, then restore to re-bind call edge",
        "description": "External call edge to parse_header breaks at c2, then re-establishes at c3",
        "repository": "repo_temp_del_03",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Add parser and server",
                "files": {
                    "src/parser.py": "def parse_header(raw):\n    return raw.lower()\n",
                    "src/server.py": "def handle(raw):\n    return parse_header(raw)\n",
                },
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Remove parse_header",
                "files": {
                    "src/parser.py": "def unused_helper():\n    return 0\n",
                    "src/server.py": "def handle(raw):\n    return parse_header(raw)\n",
                },
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Restore parse_header",
                "files": {
                    "src/parser.py": "def parse_header(raw):\n    return raw.lower()\n",
                    "src/server.py": "def handle(raw):\n    return parse_header(raw)\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_disappearance_closure",
        "license": "MIT",
    })

    # TEMP-DEL-04: Class deletion and restore
    cases.append({
        "id": "TEMP-DEL-04",
        "slice": "delete_and_restore",
        "name": "Class SessionStore deleted in c2, restored in c3",
        "description": "Class entity and all methods expired in c2, cleanly re-instated in c3",
        "repository": "repo_temp_del_04",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Add SessionStore",
                "files": {
                    "src/session.py": (
                        "class SessionStore:\n"
                        "    def get_session(self, sid):\n        return sid\n"
                        "    def clear_session(self, sid):\n        return True\n"
                    )
                },
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Delete SessionStore",
                "files": {"src/session.py": "# empty session module\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Restore SessionStore",
                "files": {
                    "src/session.py": (
                        "class SessionStore:\n"
                        "    def get_session(self, sid):\n        return sid\n"
                        "    def clear_session(self, sid):\n        return True\n"
                    )
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_disappearance_closure",
        "license": "MIT",
    })

    # TEMP-DEL-05: Partial deletion in multi-function file (4 funcs -> 2 funcs -> 3 funcs)
    cases.append({
        "id": "TEMP-DEL-05",
        "slice": "delete_and_restore",
        "name": "Partial function deletion and selective restore",
        "description": "File has 4 functions; c2 removes 2; c3 restores only 1; checks un-restored remains closed",
        "repository": "repo_temp_del_05",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Add f1, f2, f3, f4",
                "files": {"src/funcs.py": "def f1(): return 1\ndef f2(): return 2\ndef f3(): return 3\ndef f4(): return 4\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Delete f2 and f3",
                "files": {"src/funcs.py": "def f1(): return 1\ndef f4(): return 4\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Restore f2 only",
                "files": {"src/funcs.py": "def f1(): return 1\ndef f2(): return 2\ndef f4(): return 4\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_disappearance_closure",
        "license": "MIT",
    })

    # TEMP-DEL-06: Delete entity, substitute dummy, delete dummy, restore original
    cases.append({
        "id": "TEMP-DEL-06",
        "slice": "delete_and_restore",
        "name": "Delete validate_jwt, replace with stub, delete stub, restore original",
        "description": "Temporary stub with distinct AST body occupies the name before original is restored",
        "repository": "repo_temp_del_06",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Original validate_jwt",
                "files": {"src/jwt.py": "def validate_jwt(token, secret):\n    return token.startswith('bearer_') and len(secret) > 8\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Temporary stub",
                "files": {"src/jwt.py": "def validate_jwt(token):\n    return True\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Delete stub",
                "files": {"src/jwt.py": "# no jwt validation\n"},
            },
            {
                "commit_id": "c4", "parent_id": "c3", "branch": "main",
                "message": "Restore original validate_jwt",
                "files": {"src/jwt.py": "def validate_jwt(token, secret):\n    return token.startswith('bearer_') and len(secret) > 8\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
            {"commit_id": "c4", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c4", "target_branch": "main"},
        "falsifier_class": "temporal_disappearance_closure",
        "license": "MIT",
    })

    # TEMP-DEL-07: Delete file content to 0-byte file, then restore
    cases.append({
        "id": "TEMP-DEL-07",
        "slice": "delete_and_restore",
        "name": "Empty out module to empty file, then restore contents",
        "description": "File remains on disk but becomes empty; code entities close and then re-emerge",
        "repository": "repo_temp_del_07",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Add config module",
                "files": {"src/config.py": "def load_config():\n    return {'env': 'prod'}\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Empty file",
                "files": {"src/config.py": ""},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Restore config module",
                "files": {"src/config.py": "def load_config():\n    return {'env': 'prod'}\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_disappearance_closure",
        "license": "MIT",
    })

    # TEMP-DEL-08: Deletion oscillation across 5 commits (delete c2, restore c3, delete c4, restore c5)
    cases.append({
        "id": "TEMP-DEL-08",
        "slice": "delete_and_restore",
        "name": "Deletion-restore oscillation across 5 commits",
        "description": "Repeated removal and restoration of retry_policy; tests multiple valid_from/until intervals",
        "repository": "repo_temp_del_08",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Add retry policy",
                "files": {"src/policy.py": "def retry_policy(attempts):\n    return attempts < 3\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Delete retry policy",
                "files": {"src/policy.py": "# removed\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Restore retry policy",
                "files": {"src/policy.py": "def retry_policy(attempts):\n    return attempts < 3\n"},
            },
            {
                "commit_id": "c4", "parent_id": "c3", "branch": "main",
                "message": "Delete retry policy again",
                "files": {"src/policy.py": "# removed again\n"},
            },
            {
                "commit_id": "c5", "parent_id": "c4", "branch": "main",
                "message": "Restore retry policy final",
                "files": {"src/policy.py": "def retry_policy(attempts):\n    return attempts < 3\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
            {"commit_id": "c4", "branch": "main"},
            {"commit_id": "c5", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c5", "target_branch": "main"},
        "falsifier_class": "temporal_disappearance_closure",
        "license": "MIT",
    })

    return cases


def build_revert_slice() -> list[dict]:
    cases = []

    # TEMP-REV-01: Linear revert c1 (A) -> c2 (B) -> c3 (revert c2 -> A)
    cases.append({
        "id": "TEMP-REV-01",
        "slice": "revert_cycles",
        "name": "Standard linear git revert c1 -> c2 -> c3(revert c2)",
        "description": "Baseline state A modified to B, then reverted cleanly back to A; replay matches c1",
        "repository": "repo_temp_rev_01",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "State A: original algorithm",
                "files": {"src/algo.py": "def compute(x):\n    return x * 2\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "State B: experimental change",
                "files": {"src/algo.py": "def compute(x):\n    return x * 4\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Revert State B back to State A",
                "files": {"src/algo.py": "def compute(x):\n    return x * 2\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_revert_cycle",
        "license": "MIT",
    })

    # TEMP-REV-02: Revert of a revert: A -> B -> revert(B)[=A] -> revert(revert(B))[=B]
    cases.append({
        "id": "TEMP-REV-02",
        "slice": "revert_cycles",
        "name": "Revert of a revert: A -> B -> revert(B) -> revert(revert(B))",
        "description": "Reverting a revert restores State B; checks identity handling across duplicate content",
        "repository": "repo_temp_rev_02",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "State A",
                "files": {"src/engine.py": "def run():\n    return 'v1'\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "State B",
                "files": {"src/engine.py": "def run():\n    return 'v2'\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Revert c2 (back to State A)",
                "files": {"src/engine.py": "def run():\n    return 'v1'\n"},
            },
            {
                "commit_id": "c4", "parent_id": "c3", "branch": "main",
                "message": "Revert c3 (back to State B)",
                "files": {"src/engine.py": "def run():\n    return 'v2'\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
            {"commit_id": "c4", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c4", "target_branch": "main"},
        "falsifier_class": "temporal_revert_cycle",
        "license": "MIT",
    })

    # TEMP-REV-03: Partial revert: commit c2 modified 2 files, c3 reverts changes in only 1 file
    cases.append({
        "id": "TEMP-REV-03",
        "slice": "revert_cycles",
        "name": "Partial revert of multi-file commit",
        "description": "Commit modified models.py and views.py; c3 reverts models.py only while views.py remains modified",
        "repository": "repo_temp_rev_03",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base models and views",
                "files": {
                    "src/models.py": "def get_user(): return 'user'\n",
                    "src/views.py": "def render(): return 'view_v1'\n",
                },
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Upgrade models and views to v2",
                "files": {
                    "src/models.py": "def get_user(): return 'user_v2'\n",
                    "src/views.py": "def render(): return 'view_v2'\n",
                },
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Revert models.py only",
                "files": {
                    "src/models.py": "def get_user(): return 'user'\n",
                    "src/views.py": "def render(): return 'view_v2'\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_revert_cycle",
        "license": "MIT",
    })

    # TEMP-REV-04: Revert commit that introduced security vulnerability / secret
    cases.append({
        "id": "TEMP-REV-04",
        "slice": "revert_cycles",
        "name": "Revert commit introducing vulnerability",
        "description": "Commit c2 introduced insecure bypass; c3 reverts it. Lineage keeps audit trail but c3 graph is clean",
        "repository": "repo_temp_rev_04",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Secure authentication",
                "files": {"src/sec.py": "def check_access(user):\n    return user.is_authenticated\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Accidental bypass",
                "files": {"src/sec.py": "def check_access(user):\n    return True\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Revert accidental bypass",
                "files": {"src/sec.py": "def check_access(user):\n    return user.is_authenticated\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_revert_cycle",
        "license": "MIT",
    })

    # TEMP-REV-05: Revert removal of contract interface
    cases.append({
        "id": "TEMP-REV-05",
        "slice": "revert_cycles",
        "name": "Revert removal of required interface",
        "description": "Interface send_alert removed in c2 breaking callers; c3 reverts removal restoring all edges",
        "repository": "repo_temp_rev_05",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Alerting contract and caller",
                "files": {
                    "src/alert.py": "def send_alert(msg):\n    return len(msg)\n",
                    "src/monitor.py": "def check_metric(val):\n    if val > 100: send_alert('high')\n",
                },
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Accidental deletion of send_alert",
                "files": {
                    "src/alert.py": "# alert removed\n",
                    "src/monitor.py": "def check_metric(val):\n    if val > 100: send_alert('high')\n",
                },
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Revert deletion of send_alert",
                "files": {
                    "src/alert.py": "def send_alert(msg):\n    return len(msg)\n",
                    "src/monitor.py": "def check_metric(val):\n    if val > 100: send_alert('high')\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_revert_cycle",
        "license": "MIT",
    })

    # TEMP-REV-06: Revert with conflict resolution / adaptation
    cases.append({
        "id": "TEMP-REV-06",
        "slice": "revert_cycles",
        "name": "Revert with manual adaptation / conflict resolution",
        "description": "Commit c2 adds feature, c3 adds logging, c4 reverts feature while keeping logging",
        "repository": "repo_temp_rev_06",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base service",
                "files": {"src/svc.py": "def run():\n    return 'base'\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Add experimental feature",
                "files": {"src/svc.py": "def run():\n    return 'feature'\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Add logger function",
                "files": {"src/svc.py": "def log(msg): return msg\ndef run():\n    return 'feature'\n"},
            },
            {
                "commit_id": "c4", "parent_id": "c3", "branch": "main",
                "message": "Revert feature but retain log",
                "files": {"src/svc.py": "def log(msg): return msg\ndef run():\n    return 'base'\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
            {"commit_id": "c4", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c4", "target_branch": "main"},
        "falsifier_class": "temporal_revert_cycle",
        "license": "MIT",
    })

    # TEMP-REV-07: Multi-step sequential revert chain: c2 -> c3 -> revert c3 -> revert c2
    cases.append({
        "id": "TEMP-REV-07",
        "slice": "revert_cycles",
        "name": "Sequential multi-commit unwind: c2, c3, revert c3, revert c2",
        "description": "Unwinding two sequential changes restores base state exactly",
        "repository": "repo_temp_rev_07",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base state",
                "files": {"src/pipe.py": "def step1(): return 1\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Add step2",
                "files": {"src/pipe.py": "def step1(): return 1\ndef step2(): return 2\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Add step3",
                "files": {"src/pipe.py": "def step1(): return 1\ndef step2(): return 2\ndef step3(): return 3\n"},
            },
            {
                "commit_id": "c4", "parent_id": "c3", "branch": "main",
                "message": "Revert step3",
                "files": {"src/pipe.py": "def step1(): return 1\ndef step2(): return 2\n"},
            },
            {
                "commit_id": "c5", "parent_id": "c4", "branch": "main",
                "message": "Revert step2",
                "files": {"src/pipe.py": "def step1(): return 1\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
            {"commit_id": "c4", "branch": "main"},
            {"commit_id": "c5", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c5", "target_branch": "main"},
        "falsifier_class": "temporal_revert_cycle",
        "license": "MIT",
    })

    # TEMP-REV-08: Revert cycle oscillation: c1 (A) -> c2 (B) -> c3 (revert c2) -> c4 (B) -> c5 (revert c4)
    cases.append({
        "id": "TEMP-REV-08",
        "slice": "revert_cycles",
        "name": "Oscillating double revert sequence",
        "description": "Two distinct cycles of modification and revert; tests timeline preservation with no live interval bloat",
        "repository": "repo_temp_rev_08",
        "scenario_type": "linear",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "State A",
                "files": {"src/state.py": "def get_flag(): return False\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "State B",
                "files": {"src/state.py": "def get_flag(): return True\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Revert c2 (State A)",
                "files": {"src/state.py": "def get_flag(): return False\n"},
            },
            {
                "commit_id": "c4", "parent_id": "c3", "branch": "main",
                "message": "State B again",
                "files": {"src/state.py": "def get_flag(): return True\n"},
            },
            {
                "commit_id": "c5", "parent_id": "c4", "branch": "main",
                "message": "Revert c4 (State A final)",
                "files": {"src/state.py": "def get_flag(): return False\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
            {"commit_id": "c4", "branch": "main"},
            {"commit_id": "c5", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c5", "target_branch": "main"},
        "falsifier_class": "temporal_revert_cycle",
        "license": "MIT",
    })

    return cases


def build_cherry_pick_slice() -> list[dict]:
    cases = []

    # TEMP-CP-01: Feature commit cherry-picked onto main
    cases.append({
        "id": "TEMP-CP-01",
        "slice": "cherry_pick_cross_branch",
        "name": "Feature branch commit cherry-picked to main",
        "description": "Commit adding format_currency on feature branch cherry-picked to main with distinct commit ID",
        "repository": "repo_temp_cp_01",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base main",
                "files": {"src/main.py": "def run(): return 1\n"},
            },
            {
                "commit_id": "feat_1", "parent_id": "c1", "branch": "feature",
                "message": "Add currency formatting",
                "files": {"src/main.py": "def run(): return 1\n", "src/curr.py": "def format_currency(v): return f'${v}'\n"},
            },
            {
                "commit_id": "main_cp", "parent_id": "c1", "branch": "main",
                "message": "Cherry-pick format_currency to main",
                "files": {"src/main.py": "def run(): return 1\n", "src/curr.py": "def format_currency(v): return f'${v}'\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "feat_1", "branch": "feature"},
            {"commit_id": "main_cp", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "main_cp", "target_branch": "main"},
        "falsifier_class": "temporal_cherry_pick",
        "license": "MIT",
    })

    # TEMP-CP-02: Cherry-pick of removal commit across branches
    cases.append({
        "id": "TEMP-CP-02",
        "slice": "cherry_pick_cross_branch",
        "name": "Cherry-pick of function deprecation/removal commit",
        "description": "Deprecation commit removing old_connect on dev cherry-picked to release branch",
        "repository": "repo_temp_cp_02",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Initial connect functions",
                "files": {"src/conn.py": "def old_connect(): return 'v1'\ndef new_connect(): return 'v2'\n"},
            },
            {
                "commit_id": "dev_1", "parent_id": "c1", "branch": "dev",
                "message": "Remove old_connect",
                "files": {"src/conn.py": "def new_connect(): return 'v2'\n"},
            },
            {
                "commit_id": "rel_cp", "parent_id": "c1", "branch": "release",
                "message": "Cherry-pick removal to release branch",
                "files": {"src/conn.py": "def new_connect(): return 'v2'\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "dev_1", "branch": "dev"},
            {"commit_id": "rel_cp", "branch": "release"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "rel_cp", "target_branch": "release"},
        "falsifier_class": "temporal_cherry_pick",
        "license": "MIT",
    })

    # TEMP-CP-03: Cherry-pick modifying call site to pre-existing callee
    cases.append({
        "id": "TEMP-CP-03",
        "slice": "cherry_pick_cross_branch",
        "name": "Cherry-pick modifying caller to bind existing callee on target branch",
        "description": "Caller updated on feature branch and cherry-picked to main where dispatch already exists",
        "repository": "repo_temp_cp_03",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base with dispatch and caller",
                "files": {
                    "src/core.py": "def dispatch(ev): return ev\n",
                    "src/worker.py": "def run_job(j): return j\n",
                },
            },
            {
                "commit_id": "feat_1", "parent_id": "c1", "branch": "feature",
                "message": "Call dispatch in worker",
                "files": {
                    "src/core.py": "def dispatch(ev): return ev\n",
                    "src/worker.py": "def run_job(j): return dispatch(j)\n",
                },
            },
            {
                "commit_id": "main_cp", "parent_id": "c1", "branch": "main",
                "message": "Cherry-pick worker update to main",
                "files": {
                    "src/core.py": "def dispatch(ev): return ev\n",
                    "src/worker.py": "def run_job(j): return dispatch(j)\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "feat_1", "branch": "feature"},
            {"commit_id": "main_cp", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "main_cp", "target_branch": "main"},
        "falsifier_class": "temporal_cherry_pick",
        "license": "MIT",
    })

    # TEMP-CP-04: Cherry-pick onto divergent branch with distinct base files
    cases.append({
        "id": "TEMP-CP-04",
        "slice": "cherry_pick_cross_branch",
        "name": "Cherry-pick onto divergent branch with distinct base files",
        "description": "Target branch has advanced with distinct files; cherry-pick adds patch cleanly",
        "repository": "repo_temp_cp_04",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/base.py": "def base(): return 0\n"},
            },
            {
                "commit_id": "main_2", "parent_id": "c1", "branch": "main",
                "message": "Main adds extra file",
                "files": {"src/base.py": "def base(): return 0\n", "src/extra.py": "def extra(): return 1\n"},
            },
            {
                "commit_id": "feat_1", "parent_id": "c1", "branch": "feature",
                "message": "Feature adds helper",
                "files": {"src/base.py": "def base(): return 0\n", "src/helper.py": "def helper(): return 2\n"},
            },
            {
                "commit_id": "main_cp", "parent_id": "main_2", "branch": "main",
                "message": "Cherry-pick helper to main",
                "files": {
                    "src/base.py": "def base(): return 0\n",
                    "src/extra.py": "def extra(): return 1\n",
                    "src/helper.py": "def helper(): return 2\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "main_2", "branch": "main"},
            {"commit_id": "feat_1", "branch": "feature"},
            {"commit_id": "main_cp", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "main_cp", "target_branch": "main"},
        "falsifier_class": "temporal_cherry_pick",
        "license": "MIT",
    })

    # TEMP-CP-05: Double cherry-pick onto two independent release branches
    cases.append({
        "id": "TEMP-CP-05",
        "slice": "cherry_pick_cross_branch",
        "name": "Double cherry-pick to release-1.0 and release-2.0",
        "description": "Hotfix commit on dev cherry-picked to two independent release branches",
        "repository": "repo_temp_cp_05",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/sec.py": "def verify(): return False\n"},
            },
            {
                "commit_id": "dev_hotfix", "parent_id": "c1", "branch": "dev",
                "message": "Fix security check",
                "files": {"src/sec.py": "def verify(): return True\n"},
            },
            {
                "commit_id": "rel1_cp", "parent_id": "c1", "branch": "release-1.0",
                "message": "Cherry-pick to release 1",
                "files": {"src/sec.py": "def verify(): return True\n"},
            },
            {
                "commit_id": "rel2_cp", "parent_id": "c1", "branch": "release-2.0",
                "message": "Cherry-pick to release 2",
                "files": {"src/sec.py": "def verify(): return True\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "dev_hotfix", "branch": "dev"},
            {"commit_id": "rel1_cp", "branch": "release-1.0"},
            {"commit_id": "rel2_cp", "branch": "release-2.0"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "rel2_cp", "target_branch": "release-2.0"},
        "falsifier_class": "temporal_cherry_pick",
        "license": "MIT",
    })

    # TEMP-CP-06: Cherry-pick followed by branch merge
    cases.append({
        "id": "TEMP-CP-06",
        "slice": "cherry_pick_cross_branch",
        "name": "Cherry-pick followed by full branch merge",
        "description": "Commit cherry-picked to main first, then entire feature branch merged later without collision",
        "repository": "repo_temp_cp_06",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/m.py": "def m(): return 1\n"},
            },
            {
                "commit_id": "feat_1", "parent_id": "c1", "branch": "feature",
                "message": "Feature adds f1",
                "files": {"src/m.py": "def m(): return 1\n", "src/f1.py": "def f1(): return 10\n"},
            },
            {
                "commit_id": "feat_2", "parent_id": "feat_1", "branch": "feature",
                "message": "Feature adds f2",
                "files": {
                    "src/m.py": "def m(): return 1\n",
                    "src/f1.py": "def f1(): return 10\n",
                    "src/f2.py": "def f2(): return 20\n",
                },
            },
            {
                "commit_id": "main_cp", "parent_id": "c1", "branch": "main",
                "message": "Early cherry-pick of f1 to main",
                "files": {"src/m.py": "def m(): return 1\n", "src/f1.py": "def f1(): return 10\n"},
            },
            {
                "commit_id": "main_merge", "parent_ids": ["main_cp", "feat_2"], "branch": "main",
                "message": "Merge feature into main",
                "files": {
                    "src/m.py": "def m(): return 1\n",
                    "src/f1.py": "def f1(): return 10\n",
                    "src/f2.py": "def f2(): return 20\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "feat_1", "branch": "feature"},
            {"commit_id": "feat_2", "branch": "feature"},
            {"commit_id": "main_cp", "branch": "main"},
            {"commit_id": "main_merge", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "main_merge", "target_branch": "main"},
        "falsifier_class": "temporal_cherry_pick",
        "license": "MIT",
    })

    # TEMP-CP-07: Cherry-pick of multi-file refactor
    cases.append({
        "id": "TEMP-CP-07",
        "slice": "cherry_pick_cross_branch",
        "name": "Cherry-pick of multi-file refactor commit",
        "description": "Refactoring touching 2 files cherry-picked across divergent branches",
        "repository": "repo_temp_cp_07",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {
                    "src/a.py": "def a(): return 1\n",
                    "src/b.py": "def b(): return 2\n",
                },
            },
            {
                "commit_id": "feat_1", "parent_id": "c1", "branch": "feature",
                "message": "Refactor a and b",
                "files": {
                    "src/a.py": "def a(): return 10\n",
                    "src/b.py": "def b(): return 20\n",
                },
            },
            {
                "commit_id": "main_cp", "parent_id": "c1", "branch": "main",
                "message": "Cherry-pick refactor to main",
                "files": {
                    "src/a.py": "def a(): return 10\n",
                    "src/b.py": "def b(): return 20\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "feat_1", "branch": "feature"},
            {"commit_id": "main_cp", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "main_cp", "target_branch": "main"},
        "falsifier_class": "temporal_cherry_pick",
        "license": "MIT",
    })

    # TEMP-CP-08: Cherry-pick of a revert commit
    cases.append({
        "id": "TEMP-CP-08",
        "slice": "cherry_pick_cross_branch",
        "name": "Cherry-pick of revert commit to maintenance branch",
        "description": "Commit that reverted a bugfix on main cherry-picked to maintenance branch",
        "repository": "repo_temp_cp_08",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/f.py": "def f(): return 'original'\n"},
            },
            {
                "commit_id": "main_bug", "parent_id": "c1", "branch": "main",
                "message": "Buggy change",
                "files": {"src/f.py": "def f(): return 'buggy'\n"},
            },
            {
                "commit_id": "main_rev", "parent_id": "main_bug", "branch": "main",
                "message": "Revert buggy change",
                "files": {"src/f.py": "def f(): return 'original'\n"},
            },
            {
                "commit_id": "maint_cp", "parent_id": "c1", "branch": "maint",
                "message": "Cherry-pick revert to maint branch",
                "files": {"src/f.py": "def f(): return 'original'\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "main_bug", "branch": "main"},
            {"commit_id": "main_rev", "branch": "main"},
            {"commit_id": "maint_cp", "branch": "maint"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "maint_cp", "target_branch": "maint"},
        "falsifier_class": "temporal_cherry_pick",
        "license": "MIT",
    })

    return cases


def build_branch_isolation_slice() -> list[dict]:
    cases = []

    # TEMP-BR-01: Interleaved commit ingest: main -> feat-A -> feat-B -> feat-A. Query feat-A.
    cases.append({
        "id": "TEMP-BR-01",
        "slice": "interleaved_branch_ingest",
        "name": "Strict branch isolation during interleaved multi-branch ingestion",
        "description": "Interleaved commits on feat-A and feat-B; query feat-A must contain zero entities from feat-B",
        "repository": "repo_temp_br_01",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base main",
                "files": {"src/common.py": "def common(): return 1\n"},
            },
            {
                "commit_id": "a1", "parent_id": "c1", "branch": "feat-A",
                "message": "feat-A commit 1",
                "files": {"src/common.py": "def common(): return 1\n", "src/feat_a.py": "def a_work(): return 'A'\n"},
            },
            {
                "commit_id": "b1", "parent_id": "c1", "branch": "feat-B",
                "message": "feat-B commit 1",
                "files": {"src/common.py": "def common(): return 1\n", "src/feat_b.py": "def b_secret(): return 'B'\n"},
            },
            {
                "commit_id": "a2", "parent_id": "a1", "branch": "feat-A",
                "message": "feat-A commit 2",
                "files": {"src/common.py": "def common(): return 1\n", "src/feat_a.py": "def a_work(): return 'A2'\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "a1", "branch": "feat-A"},
            {"commit_id": "b1", "branch": "feat-B"},
            {"commit_id": "a2", "branch": "feat-A"},
        ],
        "target_query": {
            "type": "branch_isolation",
            "target_commit": "a2",
            "target_branch": "feat-A",
            "check_isolation_branch": "feat-B",
        },
        "falsifier_class": "temporal_branch_isolation",
        "license": "MIT",
    })

    # TEMP-BR-02: Conflicting entity definitions on parallel branches
    cases.append({
        "id": "TEMP-BR-02",
        "slice": "interleaved_branch_ingest",
        "name": "Conflicting entity implementations on parallel branches",
        "description": "feat-Chrome defines get_driver returning Chrome; feat-Firefox defines get_driver returning Firefox",
        "repository": "repo_temp_br_02",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base main",
                "files": {"src/driver.py": "def get_driver(): return 'default'\n"},
            },
            {
                "commit_id": "chr_1", "parent_id": "c1", "branch": "feat-Chrome",
                "message": "Chrome driver",
                "files": {"src/driver.py": "def get_driver(): return 'Chrome'\n"},
            },
            {
                "commit_id": "ff_1", "parent_id": "c1", "branch": "feat-Firefox",
                "message": "Firefox driver",
                "files": {"src/driver.py": "def get_driver(): return 'Firefox'\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "chr_1", "branch": "feat-Chrome"},
            {"commit_id": "ff_1", "branch": "feat-Firefox"},
        ],
        "target_query": {
            "type": "branch_isolation",
            "target_commit": "chr_1",
            "target_branch": "feat-Chrome",
            "check_isolation_branch": "feat-Firefox",
        },
        "falsifier_class": "temporal_branch_isolation",
        "license": "MIT",
    })

    # TEMP-BR-03: Entity deleted on feat-A must NOT be marked closed on feat-B
    cases.append({
        "id": "TEMP-BR-03",
        "slice": "interleaved_branch_ingest",
        "name": "Entity deletion on branch A does not close entity on branch B",
        "description": "feat-A deletes shared_utility; feat-B retains it. Interleaved ingest must keep it live on feat-B",
        "repository": "repo_temp_br_03",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base with shared utility",
                "files": {"src/util.py": "def shared_utility(): return 42\n"},
            },
            {
                "commit_id": "a1", "parent_id": "c1", "branch": "feat-A",
                "message": "feat-A deletes utility",
                "files": {"src/util.py": "# deleted\n"},
            },
            {
                "commit_id": "b1", "parent_id": "c1", "branch": "feat-B",
                "message": "feat-B uses utility",
                "files": {"src/util.py": "def shared_utility(): return 42\n", "src/b.py": "def b(): return shared_utility()\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "a1", "branch": "feat-A"},
            {"commit_id": "b1", "branch": "feat-B"},
        ],
        "target_query": {
            "type": "branch_isolation",
            "target_commit": "b1",
            "target_branch": "feat-B",
            "check_isolation_branch": "feat-A",
        },
        "falsifier_class": "temporal_branch_isolation",
        "license": "MIT",
    })

    # TEMP-BR-04: Three parallel branches ingesting round-robin
    cases.append({
        "id": "TEMP-BR-04",
        "slice": "interleaved_branch_ingest",
        "name": "Three parallel branches ingesting round-robin",
        "description": "Branches feat-1, feat-2, feat-3 ingest in alternating sequence; query feat-3 is isolated from 1 and 2",
        "repository": "repo_temp_br_04",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/base.py": "def base(): return 0\n"},
            },
            {
                "commit_id": "f1_1", "parent_id": "c1", "branch": "feat-1",
                "files": {"src/base.py": "def base(): return 0\n", "src/f1.py": "def f1(): return 1\n"},
            },
            {
                "commit_id": "f2_1", "parent_id": "c1", "branch": "feat-2",
                "files": {"src/base.py": "def base(): return 0\n", "src/f2.py": "def f2(): return 2\n"},
            },
            {
                "commit_id": "f3_1", "parent_id": "c1", "branch": "feat-3",
                "files": {"src/base.py": "def base(): return 0\n", "src/f3.py": "def f3(): return 3\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "f1_1", "branch": "feat-1"},
            {"commit_id": "f2_1", "branch": "feat-2"},
            {"commit_id": "f3_1", "branch": "feat-3"},
        ],
        "target_query": {
            "type": "branch_isolation",
            "target_commit": "f3_1",
            "target_branch": "feat-3",
            "check_isolation_branch": "feat-1",
        },
        "falsifier_class": "temporal_branch_isolation",
        "license": "MIT",
    })

    # TEMP-BR-05: Point-in-time query stability after extensive interleaving
    cases.append({
        "id": "TEMP-BR-05",
        "slice": "interleaved_branch_ingest",
        "name": "Point-in-time historical query stability after extensive interleaving",
        "description": "Querying historical commit a1 after 5 subsequent commits on other branches returns identical state",
        "repository": "repo_temp_br_05",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/base.py": "def base(): return 0\n"},
            },
            {
                "commit_id": "a1", "parent_id": "c1", "branch": "feat-A",
                "message": "Historical anchor target",
                "files": {"src/base.py": "def base(): return 0\n", "src/a.py": "def a_initial(): return 100\n"},
            },
            {
                "commit_id": "b1", "parent_id": "c1", "branch": "feat-B",
                "files": {"src/base.py": "def base(): return 0\n", "src/b.py": "def b1(): return 200\n"},
            },
            {
                "commit_id": "b2", "parent_id": "b1", "branch": "feat-B",
                "files": {"src/base.py": "def base(): return 0\n", "src/b.py": "def b2(): return 201\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "files": {"src/base.py": "def base(): return 10\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "a1", "branch": "feat-A"},
            {"commit_id": "b1", "branch": "feat-B"},
            {"commit_id": "b2", "branch": "feat-B"},
            {"commit_id": "c2", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "a1", "target_branch": "feat-A"},
        "falsifier_class": "temporal_branch_isolation",
        "license": "MIT",
    })

    # TEMP-BR-06: Branch rebase onto updated main
    cases.append({
        "id": "TEMP-BR-06",
        "slice": "interleaved_branch_ingest",
        "name": "Feature branch rebase onto updated main",
        "description": "Branch feat-A rebased from c1 onto c2; replay graph incorporates c2 changes cleanly",
        "repository": "repo_temp_br_06",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/main.py": "def run(): return 'v1'\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "message": "Main v2",
                "files": {"src/main.py": "def run(): return 'v2'\n"},
            },
            {
                "commit_id": "a_orig", "parent_id": "c1", "branch": "feat-A-old",
                "message": "Old feat-A on c1",
                "files": {"src/main.py": "def run(): return 'v1'\n", "src/feat.py": "def f(): return 'feat'\n"},
            },
            {
                "commit_id": "a_rebased", "parent_id": "c2", "branch": "feat-A",
                "message": "Rebased feat-A on c2",
                "files": {"src/main.py": "def run(): return 'v2'\n", "src/feat.py": "def f(): return 'feat'\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "a_orig", "branch": "feat-A-old"},
            {"commit_id": "a_rebased", "branch": "feat-A"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "a_rebased", "target_branch": "feat-A"},
        "falsifier_class": "temporal_branch_isolation",
        "license": "MIT",
    })

    # TEMP-BR-07: Branch with internal dependency vs unrelated branch
    cases.append({
        "id": "TEMP-BR-07",
        "slice": "interleaved_branch_ingest",
        "name": "Branch with internal dependency graph vs unrelated branch",
        "description": "Branch A builds complex caller-callee module; Branch B modifies readme/tests; isolation holds",
        "repository": "repo_temp_br_07",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/app.py": "def start(): return True\n"},
            },
            {
                "commit_id": "a1", "parent_id": "c1", "branch": "feat-A",
                "message": "Feat A modules",
                "files": {
                    "src/app.py": "def start(): return True\n",
                    "src/sub.py": "def sub(): return 1\ndef caller(): return sub()\n",
                },
            },
            {
                "commit_id": "b1", "parent_id": "c1", "branch": "feat-B",
                "message": "Feat B tests",
                "files": {"src/app.py": "def start(): return True\n", "src/tests.py": "def test_start(): assert True\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "a1", "branch": "feat-A"},
            {"commit_id": "b1", "branch": "feat-B"},
        ],
        "target_query": {
            "type": "branch_isolation",
            "target_commit": "a1",
            "target_branch": "feat-A",
            "check_isolation_branch": "feat-B",
        },
        "falsifier_class": "temporal_branch_isolation",
        "license": "MIT",
    })

    # TEMP-BR-08: Cross-branch isolation tripwire
    cases.append({
        "id": "TEMP-BR-08",
        "slice": "interleaved_branch_ingest",
        "name": "Negative assertion: entity from branch B is not visible in branch A",
        "description": "Strict negative assertion verifying isolated namespace across branches",
        "repository": "repo_temp_br_08",
        "scenario_type": "branching",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/init.py": "def init(): return 1\n"},
            },
            {
                "commit_id": "a1", "parent_id": "c1", "branch": "feat-A",
                "files": {"src/init.py": "def init(): return 1\n", "src/a.py": "def a(): return 'A'\n"},
            },
            {
                "commit_id": "b1", "parent_id": "c1", "branch": "feat-B",
                "files": {"src/init.py": "def init(): return 1\n", "src/b.py": "def secret_b(): return 'B'\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "a1", "branch": "feat-A"},
            {"commit_id": "b1", "branch": "feat-B"},
        ],
        "target_query": {
            "type": "branch_isolation",
            "target_commit": "a1",
            "target_branch": "feat-A",
            "check_isolation_branch": "feat-B",
        },
        "falsifier_class": "temporal_branch_isolation",
        "license": "MIT",
    })

    return cases


def build_merge_slice() -> list[dict]:
    cases = []

    # TEMP-MRG-01: Standard 2-parent merge: main merges feat-A
    cases.append({
        "id": "TEMP-MRG-01",
        "slice": "criss_cross_merges",
        "name": "Standard two-parent branch merge",
        "description": "Base commit forks into main and feat-A; merge commit m1 merges feat-A into main",
        "repository": "repo_temp_mrg_01",
        "scenario_type": "merge",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/common.py": "def common(): return 0\n"},
            },
            {
                "commit_id": "main_1", "parent_id": "c1", "branch": "main",
                "message": "Main adds m_func",
                "files": {"src/common.py": "def common(): return 0\n", "src/m.py": "def m_func(): return 1\n"},
            },
            {
                "commit_id": "feat_1", "parent_id": "c1", "branch": "feat-A",
                "message": "Feat adds f_func",
                "files": {"src/common.py": "def common(): return 0\n", "src/f.py": "def f_func(): return 2\n"},
            },
            {
                "commit_id": "merge_1", "parent_ids": ["main_1", "feat_1"], "branch": "main",
                "message": "Merge feat-A into main",
                "files": {
                    "src/common.py": "def common(): return 0\n",
                    "src/m.py": "def m_func(): return 1\n",
                    "src/f.py": "def f_func(): return 2\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "main_1", "branch": "main"},
            {"commit_id": "feat_1", "branch": "feat-A"},
            {"commit_id": "merge_1", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "merge_1", "target_branch": "main"},
        "falsifier_class": "temporal_criss_cross_merge",
        "license": "MIT",
    })

    # TEMP-MRG-02: Criss-cross merge: branch A and branch B merge each other at different points
    cases.append({
        "id": "TEMP-MRG-02",
        "slice": "criss_cross_merges",
        "name": "Criss-cross merge with two distinct merge sync points",
        "description": "Branches A and B merge each other's intermediate commits resulting in criss-cross DAG",
        "repository": "repo_temp_mrg_02",
        "scenario_type": "merge",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/init.py": "def init(): return 0\n"},
            },
            {
                "commit_id": "a1", "parent_id": "c1", "branch": "feat-A",
                "files": {"src/init.py": "def init(): return 0\n", "src/a.py": "def a(): return 1\n"},
            },
            {
                "commit_id": "b1", "parent_id": "c1", "branch": "feat-B",
                "files": {"src/init.py": "def init(): return 0\n", "src/b.py": "def b(): return 2\n"},
            },
            {
                "commit_id": "m_a", "parent_ids": ["a1", "b1"], "branch": "feat-A",
                "message": "Merge B into A",
                "files": {
                    "src/init.py": "def init(): return 0\n",
                    "src/a.py": "def a(): return 1\n",
                    "src/b.py": "def b(): return 2\n",
                },
            },
            {
                "commit_id": "b2", "parent_id": "b1", "branch": "feat-B",
                "message": "B adds b2",
                "files": {
                    "src/init.py": "def init(): return 0\n",
                    "src/b.py": "def b(): return 2\ndef b2(): return 20\n",
                },
            },
            {
                "commit_id": "m_final", "parent_ids": ["m_a", "b2"], "branch": "feat-A",
                "message": "Second criss-cross merge",
                "files": {
                    "src/init.py": "def init(): return 0\n",
                    "src/a.py": "def a(): return 1\n",
                    "src/b.py": "def b(): return 2\ndef b2(): return 20\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "a1", "branch": "feat-A"},
            {"commit_id": "b1", "branch": "feat-B"},
            {"commit_id": "m_a", "branch": "feat-A"},
            {"commit_id": "b2", "branch": "feat-B"},
            {"commit_id": "m_final", "branch": "feat-A"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "m_final", "target_branch": "feat-A"},
        "falsifier_class": "temporal_criss_cross_merge",
        "license": "MIT",
    })

    # TEMP-MRG-03: Fast-forward merge simulation
    cases.append({
        "id": "TEMP-MRG-03",
        "slice": "criss_cross_merges",
        "name": "Fast-forward branch progression",
        "description": "Main fast-forwards directly to feature branch tip without merge commit",
        "repository": "repo_temp_mrg_03",
        "scenario_type": "merge",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/app.py": "def start(): return 1\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "feat-A",
                "message": "Feat-A step 1",
                "files": {"src/app.py": "def start(): return 1\n", "src/f.py": "def step1(): return 1\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "message": "Fast-forward main to c3",
                "files": {"src/app.py": "def start(): return 1\n", "src/f.py": "def step1(): return 1\ndef step2(): return 2\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "feat-A"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_criss_cross_merge",
        "license": "MIT",
    })

    # TEMP-MRG-04: Merge combining orthogonal modules
    cases.append({
        "id": "TEMP-MRG-04",
        "slice": "criss_cross_merges",
        "name": "Merge combining orthogonal modules from separate branches",
        "description": "feat-A adds reporting.py, feat-B adds billing.py; merge unites both cleanly",
        "repository": "repo_temp_mrg_04",
        "scenario_type": "merge",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/core.py": "def core(): return 0\n"},
            },
            {
                "commit_id": "rep_1", "parent_id": "c1", "branch": "feat-Reporting",
                "files": {"src/core.py": "def core(): return 0\n", "src/reporting.py": "def generate_report(): return 'rep'\n"},
            },
            {
                "commit_id": "bill_1", "parent_id": "c1", "branch": "feat-Billing",
                "files": {"src/core.py": "def core(): return 0\n", "src/billing.py": "def bill_customer(): return 'bill'\n"},
            },
            {
                "commit_id": "merge_clean", "parent_ids": ["rep_1", "bill_1"], "branch": "main",
                "message": "Merge reporting and billing",
                "files": {
                    "src/core.py": "def core(): return 0\n",
                    "src/reporting.py": "def generate_report(): return 'rep'\n",
                    "src/billing.py": "def bill_customer(): return 'bill'\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "rep_1", "branch": "feat-Reporting"},
            {"commit_id": "bill_1", "branch": "feat-Billing"},
            {"commit_id": "merge_clean", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "merge_clean", "target_branch": "main"},
        "falsifier_class": "temporal_criss_cross_merge",
        "license": "MIT",
    })

    # TEMP-MRG-05: Merge resolving rename-vs-edit
    cases.append({
        "id": "TEMP-MRG-05",
        "slice": "criss_cross_merges",
        "name": "Merge resolving rename-vs-edit on separate branches",
        "description": "Branch A renamed function; Branch B edited body; Merge applies edit to renamed function",
        "repository": "repo_temp_mrg_05",
        "scenario_type": "merge",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/math_util.py": "def square(x):\n    return x * x\n"},
            },
            {
                "commit_id": "ren_1", "parent_id": "c1", "branch": "feat-Rename",
                "message": "Rename square to power2",
                "files": {"src/math_util.py": "def power2(x):\n    return x * x\n"},
            },
            {
                "commit_id": "edit_1", "parent_id": "c1", "branch": "feat-Edit",
                "message": "Edit square logic to use math pow",
                "files": {"src/math_util.py": "def square(x):\n    return pow(x, 2)\n"},
            },
            {
                "commit_id": "merge_res", "parent_ids": ["ren_1", "edit_1"], "branch": "main",
                "message": "Resolved: power2 uses pow",
                "files": {"src/math_util.py": "def power2(x):\n    return pow(x, 2)\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "ren_1", "branch": "feat-Rename"},
            {"commit_id": "edit_1", "branch": "feat-Edit"},
            {"commit_id": "merge_res", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "merge_res", "target_branch": "main"},
        "falsifier_class": "temporal_criss_cross_merge",
        "license": "MIT",
    })

    # TEMP-MRG-06: Octo-merge: 3 branches merged simultaneously
    cases.append({
        "id": "TEMP-MRG-06",
        "slice": "criss_cross_merges",
        "name": "Octo-merge of 3 feature branches into main",
        "description": "Merge commit with 3 parent commits uniting features f1, f2, and f3",
        "repository": "repo_temp_mrg_06",
        "scenario_type": "merge",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/main.py": "def app(): return 'app'\n"},
            },
            {
                "commit_id": "f1", "parent_id": "c1", "branch": "feat-1",
                "files": {"src/main.py": "def app(): return 'app'\n", "src/f1.py": "def f1(): return 1\n"},
            },
            {
                "commit_id": "f2", "parent_id": "c1", "branch": "feat-2",
                "files": {"src/main.py": "def app(): return 'app'\n", "src/f2.py": "def f2(): return 2\n"},
            },
            {
                "commit_id": "f3", "parent_id": "c1", "branch": "feat-3",
                "files": {"src/main.py": "def app(): return 'app'\n", "src/f3.py": "def f3(): return 3\n"},
            },
            {
                "commit_id": "octo_m", "parent_ids": ["f1", "f2", "f3"], "branch": "main",
                "message": "Octo-merge of f1, f2, f3",
                "files": {
                    "src/main.py": "def app(): return 'app'\n",
                    "src/f1.py": "def f1(): return 1\n",
                    "src/f2.py": "def f2(): return 2\n",
                    "src/f3.py": "def f3(): return 3\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "f1", "branch": "feat-1"},
            {"commit_id": "f2", "branch": "feat-2"},
            {"commit_id": "f3", "branch": "feat-3"},
            {"commit_id": "octo_m", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "octo_m", "target_branch": "main"},
        "falsifier_class": "temporal_criss_cross_merge",
        "license": "MIT",
    })

    # TEMP-MRG-07: Merge with file deletion on one side and modification on other
    cases.append({
        "id": "TEMP-MRG-07",
        "slice": "criss_cross_merges",
        "name": "Merge combining file deletion on branch A with modification on branch B",
        "description": "Branch A deleted legacy.py; Branch B improved active.py; Merge retains only active.py",
        "repository": "repo_temp_mrg_07",
        "scenario_type": "merge",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/legacy.py": "def old(): return 0\n", "src/active.py": "def act(): return 1\n"},
            },
            {
                "commit_id": "del_1", "parent_id": "c1", "branch": "feat-Del",
                "message": "Delete legacy",
                "files": {"src/active.py": "def act(): return 1\n"},
            },
            {
                "commit_id": "mod_1", "parent_id": "c1", "branch": "feat-Mod",
                "message": "Modify active",
                "files": {"src/legacy.py": "def old(): return 0\n", "src/active.py": "def act(): return 10\n"},
            },
            {
                "commit_id": "m_union", "parent_ids": ["del_1", "mod_1"], "branch": "main",
                "message": "Merge: legacy deleted, active modified",
                "files": {"src/active.py": "def act(): return 10\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "del_1", "branch": "feat-Del"},
            {"commit_id": "mod_1", "branch": "feat-Mod"},
            {"commit_id": "m_union", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "m_union", "target_branch": "main"},
        "falsifier_class": "temporal_criss_cross_merge",
        "license": "MIT",
    })

    # TEMP-MRG-08: Complex merge DAG with 4 branches and multiple sync points
    cases.append({
        "id": "TEMP-MRG-08",
        "slice": "criss_cross_merges",
        "name": "Complex multi-branch merge DAG with multiple sync points",
        "description": "Comprehensive integration DAG uniting 4 branches through tiered merges",
        "repository": "repo_temp_mrg_08",
        "scenario_type": "merge",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base",
                "files": {"src/core.py": "def c(): return 0\n"},
            },
            {
                "commit_id": "b1", "parent_id": "c1", "branch": "feat-1",
                "files": {"src/core.py": "def c(): return 0\n", "src/f1.py": "def f1(): return 1\n"},
            },
            {
                "commit_id": "b2", "parent_id": "c1", "branch": "feat-2",
                "files": {"src/core.py": "def c(): return 0\n", "src/f2.py": "def f2(): return 2\n"},
            },
            {
                "commit_id": "m_tier1", "parent_ids": ["b1", "b2"], "branch": "staging",
                "files": {
                    "src/core.py": "def c(): return 0\n",
                    "src/f1.py": "def f1(): return 1\n",
                    "src/f2.py": "def f2(): return 2\n",
                },
            },
            {
                "commit_id": "b3", "parent_id": "c1", "branch": "feat-3",
                "files": {"src/core.py": "def c(): return 0\n", "src/f3.py": "def f3(): return 3\n"},
            },
            {
                "commit_id": "m_final", "parent_ids": ["m_tier1", "b3"], "branch": "main",
                "message": "Final tier-2 merge into main",
                "files": {
                    "src/core.py": "def c(): return 0\n",
                    "src/f1.py": "def f1(): return 1\n",
                    "src/f2.py": "def f2(): return 2\n",
                    "src/f3.py": "def f3(): return 3\n",
                },
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "b1", "branch": "feat-1"},
            {"commit_id": "b2", "branch": "feat-2"},
            {"commit_id": "m_tier1", "branch": "staging"},
            {"commit_id": "b3", "branch": "feat-3"},
            {"commit_id": "m_final", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "m_final", "target_branch": "main"},
        "falsifier_class": "temporal_criss_cross_merge",
        "license": "MIT",
    })

    return cases


def build_idempotence_slice() -> list[dict]:
    cases = []

    # TEMP-IDEM-01: Identical commit ingested twice consecutively with incremental
    cases.append({
        "id": "TEMP-IDEM-01",
        "slice": "stale_cache_and_idempotence",
        "name": "Consecutive duplicate ingest of identical commit in incremental mode",
        "description": "Re-ingesting unchanged repository commit yields zero duplicate rows and identical graph",
        "repository": "repo_temp_idem_01",
        "scenario_type": "idempotence",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base commit",
                "files": {"src/calc.py": "def add(a, b): return a + b\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c1", "branch": "main", "repeat": True},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c1", "target_branch": "main"},
        "falsifier_class": "temporal_cache_idempotence",
        "license": "MIT",
    })

    # TEMP-IDEM-02: Identical commit ingested twice in clean snapshot mode
    cases.append({
        "id": "TEMP-IDEM-02",
        "slice": "stale_cache_and_idempotence",
        "name": "Consecutive duplicate ingest in clean snapshot mode",
        "description": "Snapshot ingestion is strictly idempotent without row leakage",
        "repository": "repo_temp_idem_02",
        "scenario_type": "idempotence",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "message": "Base commit",
                "files": {"src/parser.py": "class Parser:\n    def parse(self, s): return s\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c1", "branch": "main", "repeat": True},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c1", "target_branch": "main"},
        "falsifier_class": "temporal_cache_idempotence",
        "license": "MIT",
    })

    # TEMP-IDEM-03: Interleaved identical re-ingest: c1 -> c2 -> re-ingest c1 -> re-ingest c2
    cases.append({
        "id": "TEMP-IDEM-03",
        "slice": "stale_cache_and_idempotence",
        "name": "Interleaved re-ingest sequence c1 -> c2 -> c1 -> c2",
        "description": "Repeated historical replay does not corrupt intermediate or final validity intervals",
        "repository": "repo_temp_idem_03",
        "scenario_type": "idempotence",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "files": {"src/v.py": "def v(): return 1\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "files": {"src/v.py": "def v(): return 2\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c1", "branch": "main", "repeat": True},
            {"commit_id": "c2", "branch": "main", "repeat": True},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c2", "target_branch": "main"},
        "falsifier_class": "temporal_cache_idempotence",
        "license": "MIT",
    })

    # TEMP-IDEM-04: Rapid repeated ingest (high frequency timestamp tie-breaking)
    cases.append({
        "id": "TEMP-IDEM-04",
        "slice": "stale_cache_and_idempotence",
        "name": "Rapid sub-millisecond repeated ingestion sequence",
        "description": "High-frequency commit ingest sequence handled deterministically with no timestamp collisions",
        "repository": "repo_temp_idem_04",
        "scenario_type": "idempotence",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "files": {"src/step.py": "def step(): return 1\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "files": {"src/step.py": "def step(): return 2\n"},
            },
            {
                "commit_id": "c3", "parent_id": "c2", "branch": "main",
                "files": {"src/step.py": "def step(): return 3\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c3", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c3", "target_branch": "main"},
        "falsifier_class": "temporal_cache_idempotence",
        "license": "MIT",
    })

    # TEMP-IDEM-05: Mtime touched but identical content hash
    cases.append({
        "id": "TEMP-IDEM-05",
        "slice": "stale_cache_and_idempotence",
        "name": "File mtime touch with identical content hash preserves identity",
        "description": "FileSystem timestamp updated without content change; verify entity hashes remain invariant",
        "repository": "repo_temp_idem_05",
        "scenario_type": "idempotence",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "files": {"src/cached.py": "def heavy_computation(): return 42\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "files": {"src/cached.py": "def heavy_computation(): return 42\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c2", "target_branch": "main"},
        "falsifier_class": "temporal_cache_idempotence",
        "license": "MIT",
    })

    # TEMP-IDEM-06: Alternating incremental and snapshot ingest
    cases.append({
        "id": "TEMP-IDEM-06",
        "slice": "stale_cache_and_idempotence",
        "name": "Alternating incremental and snapshot ingestion",
        "description": "Incremental ingest followed by snapshot ingest followed by incremental yields unified graph",
        "repository": "repo_temp_idem_06",
        "scenario_type": "idempotence",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "files": {"src/f1.py": "def f1(): return 1\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "files": {"src/f1.py": "def f1(): return 1\n", "src/f2.py": "def f2(): return 2\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main", "mode": "snapshot"},
            {"commit_id": "c2", "branch": "main", "mode": "incremental"},
            {"commit_id": "c2", "branch": "main", "mode": "snapshot"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c2", "target_branch": "main"},
        "falsifier_class": "temporal_cache_idempotence",
        "license": "MIT",
    })

    # TEMP-IDEM-07: Whitespace change only (AST structure identical)
    cases.append({
        "id": "TEMP-IDEM-07",
        "slice": "stale_cache_and_idempotence",
        "name": "Whitespace formatting change with identical AST semantic nodes",
        "description": "File has altered whitespace formatting; AST structure and logical entities match",
        "repository": "repo_temp_idem_07",
        "scenario_type": "idempotence",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "files": {"src/fmt.py": "def foo(a,b):\n    return a+b\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "files": {"src/fmt.py": "def foo(a, b):\n\n    return a + b\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c2", "target_branch": "main"},
        "falsifier_class": "temporal_cache_idempotence",
        "license": "MIT",
    })

    # TEMP-IDEM-08: Atomic replay idempotence after simulated interruption
    cases.append({
        "id": "TEMP-IDEM-08",
        "slice": "stale_cache_and_idempotence",
        "name": "Atomic replay idempotence after simulated interruption",
        "description": "Re-running ingestion after interrupted transaction preserves database integrity",
        "repository": "repo_temp_idem_08",
        "scenario_type": "idempotence",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "files": {"src/tx.py": "def commit_tx(): return True\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "files": {"src/tx.py": "def commit_tx(): return True\ndef rollback_tx(): return False\n"},
            },
        ],
        "replay_sequence": [
            {"commit_id": "c1", "branch": "main"},
            {"commit_id": "c2", "branch": "main"},
            {"commit_id": "c2", "branch": "main", "repeat": True},
        ],
        "target_query": {"type": "replay_equivalence", "target_commit": "c2", "target_branch": "main"},
        "falsifier_class": "temporal_cache_idempotence",
        "license": "MIT",
    })

    return cases


def build_tripwire_slice() -> list[dict]:
    cases = []

    # TEMP-TRIP-01: Orphan commit ingested with unknown parent_id not present in store
    cases.append({
        "id": "TEMP-TRIP-01",
        "slice": "truncated_lineage_tripwire",
        "name": "Orphan commit with missing parent in ingest log",
        "description": "Commit references parent commit unknown_parent_hash_9999 that does not exist in store",
        "repository": "repo_temp_trip_01",
        "scenario_type": "tripwire",
        "tripwire_anomaly": "missing_parent_lineage",
        "commits": [
            {
                "commit_id": "orphan_c1", "parent_id": "unknown_parent_hash_9999", "branch": "main",
                "message": "Commit with fabricated or missing parent",
                "files": {"src/orphan.py": "def orphan(): return True\n"},
            },
        ],
        "replay_sequence": [{"commit_id": "orphan_c1", "branch": "main"}],
        "target_query": {"type": "lineage_tripwire", "target_commit": "orphan_c1", "target_branch": "main"},
        "falsifier_class": "temporal_lineage_tripwire",
        "license": "MIT",
    })

    # TEMP-TRIP-02: Shallow clone gap: history jumps from c1 to c4 skipping c2 and c3
    cases.append({
        "id": "TEMP-TRIP-02",
        "slice": "truncated_lineage_tripwire",
        "name": "Shallow clone history truncation gap",
        "description": "Commit c4 claims parent c3, but c2 and c3 were never fetched or ingested",
        "repository": "repo_temp_trip_02",
        "scenario_type": "tripwire",
        "tripwire_anomaly": "shallow_clone_gap",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "files": {"src/base.py": "def base(): return 0\n"},
            },
            {
                "commit_id": "c4", "parent_id": "missing_c3", "branch": "main",
                "files": {"src/base.py": "def base(): return 0\n", "src/new.py": "def new(): return 4\n"},
            },
        ],
        "replay_sequence": [{"commit_id": "c1", "branch": "main"}, {"commit_id": "c4", "branch": "main"}],
        "target_query": {"type": "lineage_tripwire", "target_commit": "c4", "target_branch": "main"},
        "falsifier_class": "temporal_lineage_tripwire",
        "license": "MIT",
    })

    # TEMP-TRIP-03: Cyclic ancestry anomaly: commit claims to be its own parent
    cases.append({
        "id": "TEMP-TRIP-03",
        "slice": "truncated_lineage_tripwire",
        "name": "Cyclic ancestry self-reference anomaly",
        "description": "Corrupted git metadata where commit claims parent pointer to itself",
        "repository": "repo_temp_trip_03",
        "scenario_type": "tripwire",
        "tripwire_anomaly": "self_cycle_detected",
        "commits": [
            {
                "commit_id": "cycle_c1", "parent_id": "cycle_c1", "branch": "main",
                "files": {"src/cycle.py": "def cycle(): return 1\n"},
            },
        ],
        "replay_sequence": [{"commit_id": "cycle_c1", "branch": "main"}],
        "target_query": {"type": "lineage_tripwire", "target_commit": "cycle_c1", "target_branch": "main"},
        "falsifier_class": "temporal_lineage_tripwire",
        "license": "MIT",
    })

    # TEMP-TRIP-04: Corrupted anchor snapshot in database
    cases.append({
        "id": "TEMP-TRIP-04",
        "slice": "truncated_lineage_tripwire",
        "name": "Corrupted anchor snapshot record in storage",
        "description": "Anchor JSON payload corrupted / unparseable; system must fail closed with INCONCLUSIVE",
        "repository": "repo_temp_trip_04",
        "scenario_type": "tripwire",
        "tripwire_anomaly": "corrupted_anchor_snapshot",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "files": {"src/a.py": "def a(): return 1\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "corrupted_anchor": True,
                "files": {"src/a.py": "def a(): return 2\n"},
            },
        ],
        "replay_sequence": [{"commit_id": "c1", "branch": "main"}, {"commit_id": "c2", "branch": "main"}],
        "target_query": {"type": "lineage_tripwire", "target_commit": "c2", "target_branch": "main"},
        "falsifier_class": "temporal_lineage_tripwire",
        "license": "MIT",
    })

    # TEMP-TRIP-05: Fabricated lineage: commit claims to be revert of non-existent revision
    cases.append({
        "id": "TEMP-TRIP-05",
        "slice": "truncated_lineage_tripwire",
        "name": "Fabricated revert target lineage claims",
        "description": "Commit metadata asserts revert of ghost revision never recorded in the DAG",
        "repository": "repo_temp_trip_05",
        "scenario_type": "tripwire",
        "tripwire_anomaly": "fabricated_revert_target",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "files": {"src/f.py": "def f(): return 1\n"},
            },
            {
                "commit_id": "c2", "parent_id": "c1", "branch": "main",
                "fabricated_revert_of": "ghost_revision_0000",
                "files": {"src/f.py": "def f(): return 2\n"},
            },
        ],
        "replay_sequence": [{"commit_id": "c1", "branch": "main"}, {"commit_id": "c2", "branch": "main"}],
        "target_query": {"type": "lineage_tripwire", "target_commit": "c2", "target_branch": "main"},
        "falsifier_class": "temporal_lineage_tripwire",
        "license": "MIT",
    })

    # TEMP-TRIP-06: Tampered content hash in revision metadata
    cases.append({
        "id": "TEMP-TRIP-06",
        "slice": "truncated_lineage_tripwire",
        "name": "Tampered source content hash mismatch",
        "description": "Claimed revision digest does not match SHA-256 of physical files; tamper tripwire",
        "repository": "repo_temp_trip_06",
        "scenario_type": "tripwire",
        "tripwire_anomaly": "tampered_content_hash",
        "commits": [
            {
                "commit_id": "c1", "parent_id": None, "branch": "main",
                "tampered_source_hash": "deadbeef00000000000000000000000000000000000000000000000000000000",
                "files": {"src/t.py": "def t(): return 'tampered'\n"},
            },
        ],
        "replay_sequence": [{"commit_id": "c1", "branch": "main"}],
        "target_query": {"type": "lineage_tripwire", "target_commit": "c1", "target_branch": "main"},
        "falsifier_class": "temporal_lineage_tripwire",
        "license": "MIT",
    })

    # TEMP-TRIP-07: Ambiguous conflicting parent lineages without merge commit
    cases.append({
        "id": "TEMP-TRIP-07",
        "slice": "truncated_lineage_tripwire",
        "name": "Ambiguous unmerged parent lineage claims",
        "description": "Commit asserts multiple parents p1 and p2 but lacks merge resolution anchor",
        "repository": "repo_temp_trip_07",
        "scenario_type": "tripwire",
        "tripwire_anomaly": "ambiguous_unresolved_parents",
        "commits": [
            {
                "commit_id": "p1", "parent_id": None, "branch": "branch1",
                "files": {"src/x.py": "def x(): return 1\n"},
            },
            {
                "commit_id": "p2", "parent_id": None, "branch": "branch2",
                "files": {"src/x.py": "def x(): return 2\n"},
            },
            {
                "commit_id": "ambig_c3", "parent_ids": ["p1", "p2"], "branch": "main",
                "unresolved_conflict": True,
                "files": {"src/x.py": "<<<<<<< HEAD\ndef x(): return 1\n=======\ndef x(): return 2\n>>>>>>>\n"},
            },
        ],
        "replay_sequence": [{"commit_id": "p1", "branch": "branch1"}, {"commit_id": "p2", "branch": "branch2"}, {"commit_id": "ambig_c3", "branch": "main"}],
        "target_query": {"type": "lineage_tripwire", "target_commit": "ambig_c3", "target_branch": "main"},
        "falsifier_class": "temporal_lineage_tripwire",
        "license": "MIT",
    })

    # TEMP-TRIP-08: Alien repository root in multi-branch repo
    cases.append({
        "id": "TEMP-TRIP-08",
        "slice": "truncated_lineage_tripwire",
        "name": "Alien repository root lineage contamination",
        "description": "Branch asserts base commit originating from completely foreign repository namespace",
        "repository": "repo_temp_trip_08",
        "scenario_type": "tripwire",
        "tripwire_anomaly": "alien_repository_root",
        "commits": [
            {
                "commit_id": "alien_root", "parent_id": "foreign_repo_root_commit", "branch": "alien_branch",
                "message": "Commit with external foreign repo root",
                "files": {"src/foreign.py": "def alien(): return 'ufo'\n"},
            },
        ],
        "replay_sequence": [{"commit_id": "alien_root", "branch": "alien_branch"}],
        "target_query": {"type": "lineage_tripwire", "target_commit": "alien_root", "target_branch": "alien_branch"},
        "falsifier_class": "temporal_lineage_tripwire",
        "license": "MIT",
    })

    return cases


def build_all_cases() -> list[dict]:
    all_cases = []
    all_cases.extend(build_rename_slice())
    all_cases.extend(build_delete_restore_slice())
    all_cases.extend(build_revert_slice())
    all_cases.extend(build_cherry_pick_slice())
    all_cases.extend(build_branch_isolation_slice())
    all_cases.extend(build_merge_slice())
    all_cases.extend(build_idempotence_slice())
    all_cases.extend(build_tripwire_slice())
    return all_cases


def generate_benchmark_files():
    cases = build_all_cases()
    assert len(cases) == 64, f"Expected 64 cases, got {len(cases)}"

    print(f"Authoring {len(cases)} cases across 8 slices...")

    # Evaluate all cases with the Independent Oracle (oracle.py)
    oracle_manifest_records = []
    labels_records = []

    for case in cases:
        oracle_eval = oracle.evaluate_oracle_case(case)
        oracle_manifest_records.append(oracle_eval)

        # Build clean gold label row
        label_row = {
            "id": case["id"],
            "slice": case["slice"],
            "expected_status": oracle_eval["expected_status"],
            "ground_truth": oracle_eval["ground_truth"],
            "ground_truth_rationale": oracle_eval["ground_truth_rationale"],
            "falsifier_class": oracle_eval["falsifier_class"],
            "target_commit": oracle_eval["target_commit"],
            "expected_canonical_digest": oracle_eval["canonical_digest"],
        }
        labels_records.append(label_row)

    # 1. Write cases.jsonl
    cases_path = BENCHMARK_DIR / "cases.jsonl"
    cases_lines = [json.dumps(c, sort_keys=True) for c in cases]
    cases_content = ("\n".join(cases_lines) + "\n").encode("utf-8")
    cases_path.write_bytes(cases_content)
    corpus_sha256 = hashlib.sha256(cases_content).hexdigest()

    # 2. Write labels.jsonl
    labels_path = BENCHMARK_DIR / "labels.jsonl"
    labels_lines = [json.dumps(lbl, sort_keys=True) for lbl in labels_records]
    labels_content = ("\n".join(labels_lines) + "\n").encode("utf-8")
    labels_path.write_bytes(labels_content)
    label_sha256 = hashlib.sha256(labels_content).hexdigest()

    # 3. Write oracle_manifest.jsonl
    manifest_path = BENCHMARK_DIR / "oracle_manifest.jsonl"
    manifest_lines = [json.dumps(m, sort_keys=True) for m in oracle_manifest_records]
    manifest_content = ("\n".join(manifest_lines) + "\n").encode("utf-8")
    manifest_path.write_bytes(manifest_content)
    manifest_sha256 = hashlib.sha256(manifest_content).hexdigest()

    # 4. Emit hash files
    (BENCHMARK_DIR / "CORPUS_SHA256").write_bytes((corpus_sha256 + "\n").encode("utf-8"))
    (BENCHMARK_DIR / "LABEL_SHA256").write_bytes((label_sha256 + "\n").encode("utf-8"))
    (BENCHMARK_DIR / "ORACLE_MANIFEST_SHA256").write_bytes((manifest_sha256 + "\n").encode("utf-8"))

    # 5. Write config.json
    config = {
        "experiment_id": "CAP-006",
        "title": "Temporal Lineage & Multi-Branch Replay Attestation Benchmark",
        "description": "Evaluation of VerifyCI temporal graph, lineage preservation, multi-branch isolation, and fail-closed tripwires",
        "corpus_sha256": corpus_sha256,
        "label_sha256": label_sha256,
        "oracle_manifest_sha256": manifest_sha256,
        "total_cases": 64,
        "slices": {
            "rename_edit_rename_back": 8,
            "delete_and_restore": 8,
            "revert_cycles": 8,
            "cherry_pick_cross_branch": 8,
            "interleaved_branch_ingest": 8,
            "criss_cross_merges": 8,
            "stale_cache_and_idempotence": 8,
            "truncated_lineage_tripwire": 8,
        },
        "target_distribution": {
            "PASS": 56,
            "INCONCLUSIVE": 8,
            "FAIL": 0,
        },
        "gates": [
            "T1_incremental_replay_equivalence",
            "T2_rename_lineage_continuity",
            "T3_revert_cycle_correctness",
            "T4_branch_divergence_isolation",
            "T5_merge_attestation_determinism",
            "T6_anchor_point_in_time_stability",
            "T7_temporal_fail_closed_integrity",
            "T8_corpus_replay_agreement",
        ],
    }
    (BENCHMARK_DIR / "config.json").write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # 6. Write MODE_PROTOCOL.md
    protocol_text = f"""# CAP-006 Protocol: Temporal Lineage & Multi-Branch Replay Attestation (FROZEN)

**Experiment ID**: CAP-006  
**Corpus SHA-256**: `{corpus_sha256}`  
**Label SHA-256**: `{label_sha256}`  
**Oracle Manifest SHA-256**: `{manifest_sha256}`  
**Total Cases**: 64  
**Total Slices**: 8  

## Evaluation Gates (T1–T8)
- **T1: Incremental Replay Equivalence**: CanonicalSemanticGraph(IncrementalReplay(H)) == CanonicalSemanticGraph(CleanSnapshot(H)).
- **T2: Rename Lineage Continuity**: Entity identity survives file and symbol renames without duplicate live intervals.
- **T3: Revert Cycle Correctness**: Linear and cyclic reverts restore exact historical states while recording lineage.
- **T4: Branch Divergence Isolation**: Interleaved multi-branch ingestion guarantees zero cross-branch graph contamination.
- **T5: Merge Attestation Determinism**: Two-parent, fast-forward, and criss-cross merges yield deterministic canonical semantic graphs.
- **T6: Anchor Point-in-Time Stability**: Historical queries (`as_of`) remain invariant across subsequent ingestion.
- **T7: Temporal Fail-Closed Integrity**: Corrupted anchors, disconnected lineage, and cyclic anomalies strictly fail closed with INCONCLUSIVE.
- **T8: Corpus Replay Agreement**: Comprehensive agreement on frozen corpus across all 64 cases.

## Category & Slice Distribution
- Total Cases: 64
- Ground Truth PASS: 56
- Ground Truth INCONCLUSIVE (Tripwires): 8
- Ground Truth FAIL: 0

### Stratified Slices
- `rename_edit_rename_back`: 8
- `delete_and_restore`: 8
- `revert_cycles`: 8
- `cherry_pick_cross_branch`: 8
- `interleaved_branch_ingest`: 8
- `criss_cross_merges`: 8
- `stale_cache_and_idempotence`: 8
- `truncated_lineage_tripwire`: 8

## Core Protocol Locks
1. **LOCK-1 (Frozen History)**:
   Corpus and gold labels are sealed and immutable upon Step 1 commit.
2. **LOCK-2 (Independent Oracle Requirement)**:
   Ground truth was derived exclusively by the standalone independent oracle (`oracle.py`), which imports zero modules from `verifyci`.
3. **LOCK-3 (No Post-Result Relabeling)**:
   Observed measurement discrepancies cannot alter frozen cases or labels.
4. **LOCK-4 (Fail-Closed Contract)**:
   Disconnected lineage, shallow gaps, or corrupted DAG metadata must yield INCONCLUSIVE, never an invented PASS.
5. **LOCK-5 (Explicit Branch Identity Coordinates)**:
   Every case specifies explicit commit IDs, parent IDs, branches, and replay sequences.
"""
    (BENCHMARK_DIR / "MODE_PROTOCOL.md").write_text(protocol_text, encoding="utf-8")

    print("\nBenchmark authored successfully:")
    print(f"  Corpus SHA-256:         {corpus_sha256}")
    print(f"  Label SHA-256:          {label_sha256}")
    print(f"  Oracle Manifest SHA-256: {manifest_sha256}")


if __name__ == "__main__":
    generate_benchmark_files()
