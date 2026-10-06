#!/usr/bin/env python3
"""Author and cryptographically freeze CAP-004 Call-Semantics Corpus.

Generates:
- cases.jsonl
- labels.jsonl (sealed from implementation path)
- config.json
- MODE_PROTOCOL.md
- CORPUS_SHA256
- LABEL_SHA256
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
HERE.mkdir(parents=True, exist_ok=True)

CASES = [
    # Slice 1: keyword_argument_values (5 cases)
    {
        "id": "CALL-KWD-01",
        "slice": "keyword_argument_values",
        "description": "Call with keyword arguments strictly matching required security contract",
        "call_code": "verify_token(raw_tok, strict=True, algorithm='RS256')",
        "callee_signature": {
            "name": "verify_token",
            "parameters": ["token", "strict", "algorithm"],
            "defaults": {"strict": False, "algorithm": "HS256"}
        },
        "contract": {
            "callee": "verify_token",
            "required_kwargs": {"strict": True, "algorithm": "RS256"},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/auth.py b/src/auth.py\n--- a/src/auth.py\n+++ b/src/auth.py\n@@ -10,2 +10,2 @@\n def check(raw_tok):\n-    return None\n+    return verify_token(raw_tok, strict=True, algorithm='RS256')\n"
    },
    {
        "id": "CALL-KWD-02",
        "slice": "keyword_argument_values",
        "description": "Call with keyword argument directly violating required strict=True policy",
        "call_code": "verify_token(raw_tok, strict=False, algorithm='RS256')",
        "callee_signature": {
            "name": "verify_token",
            "parameters": ["token", "strict", "algorithm"],
            "defaults": {"strict": True, "algorithm": "RS256"}
        },
        "contract": {
            "callee": "verify_token",
            "required_kwargs": {"strict": True},
            "forbidden_kwargs": {"strict": False}
        },
        "diff": "diff --git a/src/auth.py b/src/auth.py\n--- a/src/auth.py\n+++ b/src/auth.py\n@@ -10,2 +10,2 @@\n def check(raw_tok):\n-    return None\n+    return verify_token(raw_tok, strict=False, algorithm='RS256')\n"
    },
    {
        "id": "CALL-KWD-03",
        "slice": "keyword_argument_values",
        "description": "Call supplying forbidden shell=True keyword argument to subprocess invocation",
        "call_code": "run_subprocess(cmd, shell=True)",
        "callee_signature": {
            "name": "run_subprocess",
            "parameters": ["cmd", "shell", "check"],
            "defaults": {"shell": False, "check": True}
        },
        "contract": {
            "callee": "run_subprocess",
            "required_kwargs": {"shell": False},
            "forbidden_kwargs": {"shell": True}
        },
        "diff": "diff --git a/src/exec.py b/src/exec.py\n--- a/src/exec.py\n+++ b/src/exec.py\n@@ -5,2 +5,2 @@\n def execute(cmd):\n-    return run_subprocess(cmd)\n+    return run_subprocess(cmd, shell=True)\n"
    },
    {
        "id": "CALL-KWD-04",
        "slice": "keyword_argument_values",
        "description": "Call configuring modern TLS cipher version satisfying TLSv1.3 contract",
        "call_code": "configure_tls('/path/cert.pem', min_version='TLSv1.3')",
        "callee_signature": {
            "name": "configure_tls",
            "parameters": ["cert_file", "min_version"],
            "defaults": {"min_version": "TLSv1.2"}
        },
        "contract": {
            "callee": "configure_tls",
            "required_kwargs": {"min_version": "TLSv1.3"},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/net.py b/src/net.py\n--- a/src/net.py\n+++ b/src/net.py\n@@ -12,2 +12,2 @@\n def init_tls():\n-    pass\n+    configure_tls('/path/cert.pem', min_version='TLSv1.3')\n"
    },
    {
        "id": "CALL-KWD-05",
        "slice": "keyword_argument_values",
        "description": "Call passing ungrounded dynamic function call result to security keyword argument",
        "call_code": "sanitize_input(query, mode=config.get_mode())",
        "callee_signature": {
            "name": "sanitize_input",
            "parameters": ["text", "mode"],
            "defaults": {"mode": "strict"}
        },
        "contract": {
            "callee": "sanitize_input",
            "required_kwargs": {"mode": "strict"},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/query.py b/src/query.py\n--- a/src/query.py\n+++ b/src/query.py\n@@ -8,2 +8,2 @@\n def sanitize(query):\n-    return query\n+    return sanitize_input(query, mode=config.get_mode())\n"
    },

    # Slice 2: positional_argument_values (5 cases)
    {
        "id": "CALL-POS-01",
        "slice": "positional_argument_values",
        "description": "Call providing literal True at positional index 2 matching parameter use_ssl",
        "call_code": "connect_db('db.internal', 5432, True)",
        "callee_signature": {
            "name": "connect_db",
            "parameters": ["host", "port", "use_ssl"],
            "defaults": {"use_ssl": False}
        },
        "contract": {
            "callee": "connect_db",
            "required_args": {"use_ssl": True},
            "forbidden_args": {}
        },
        "diff": "diff --git a/src/db.py b/src/db.py\n--- a/src/db.py\n+++ b/src/db.py\n@@ -4,2 +4,2 @@\n def get_conn():\n-    return None\n+    return connect_db('db.internal', 5432, True)\n"
    },
    {
        "id": "CALL-POS-02",
        "slice": "positional_argument_values",
        "description": "Call providing literal False at positional index 2 violating use_ssl requirement",
        "call_code": "connect_db('db.internal', 5432, False)",
        "callee_signature": {
            "name": "connect_db",
            "parameters": ["host", "port", "use_ssl"],
            "defaults": {"use_ssl": True}
        },
        "contract": {
            "callee": "connect_db",
            "required_args": {"use_ssl": True},
            "forbidden_args": {"use_ssl": False}
        },
        "diff": "diff --git a/src/db.py b/src/db.py\n--- a/src/db.py\n+++ b/src/db.py\n@@ -4,2 +4,2 @@\n def get_conn():\n-    return None\n+    return connect_db('db.internal', 5432, False)\n"
    },
    {
        "id": "CALL-POS-03",
        "slice": "positional_argument_values",
        "description": "Call with positional arguments matching non-writable non-executable file mode",
        "call_code": "set_permissions('/var/log', True, False, False)",
        "callee_signature": {
            "name": "set_permissions",
            "parameters": ["path", "readable", "writable", "executable"],
            "defaults": {}
        },
        "contract": {
            "callee": "set_permissions",
            "required_args": {"writable": False, "executable": False},
            "forbidden_args": {"executable": True}
        },
        "diff": "diff --git a/src/fs.py b/src/fs.py\n--- a/src/fs.py\n+++ b/src/fs.py\n@@ -7,2 +7,2 @@\n def protect_log():\n-    pass\n+    set_permissions('/var/log', True, False, False)\n"
    },
    {
        "id": "CALL-POS-04",
        "slice": "positional_argument_values",
        "description": "Call with positional argument True at index 3 violating executable=False policy",
        "call_code": "set_permissions('/var/log', True, True, True)",
        "callee_signature": {
            "name": "set_permissions",
            "parameters": ["path", "readable", "writable", "executable"],
            "defaults": {}
        },
        "contract": {
            "callee": "set_permissions",
            "required_args": {"executable": False},
            "forbidden_args": {"executable": True}
        },
        "diff": "diff --git a/src/fs.py b/src/fs.py\n--- a/src/fs.py\n+++ b/src/fs.py\n@@ -7,2 +7,2 @@\n def protect_log():\n-    pass\n+    set_permissions('/var/log', True, True, True)\n"
    },
    {
        "id": "CALL-POS-05",
        "slice": "positional_argument_values",
        "description": "Call with dynamic function call at positional index 2 ungrounded at compile-time",
        "call_code": "connect_db('db.internal', 5432, get_ssl_flag())",
        "callee_signature": {
            "name": "connect_db",
            "parameters": ["host", "port", "use_ssl"],
            "defaults": {"use_ssl": False}
        },
        "contract": {
            "callee": "connect_db",
            "required_args": {"use_ssl": True},
            "forbidden_args": {}
        },
        "diff": "diff --git a/src/db.py b/src/db.py\n--- a/src/db.py\n+++ b/src/db.py\n@@ -4,2 +4,2 @@\n def get_conn():\n-    return None\n+    return connect_db('db.internal', 5432, get_ssl_flag())\n"
    },

    # Slice 3: argument_order_swap (4 cases)
    {
        "id": "CALL-ORD-01",
        "slice": "argument_order_swap",
        "description": "Call passing arguments in expected order (source_acct, target_acct, amount)",
        "call_code": "transfer_funds(source_id, target_id, 100)",
        "callee_signature": {
            "name": "transfer_funds",
            "parameters": ["source_acct", "target_acct", "amount"],
            "defaults": {}
        },
        "contract": {
            "callee": "transfer_funds",
            "required_param_bindings": {"source_acct": "source_id", "target_acct": "target_id"},
            "forbidden_param_bindings": {}
        },
        "diff": "diff --git a/src/ledger.py b/src/ledger.py\n--- a/src/ledger.py\n+++ b/src/ledger.py\n@@ -15,2 +15,2 @@\n def pay(source_id, target_id):\n-    pass\n+    transfer_funds(source_id, target_id, 100)\n"
    },
    {
        "id": "CALL-ORD-02",
        "slice": "argument_order_swap",
        "description": "Call inverting positional order of source and target accounts in financial transfer",
        "call_code": "transfer_funds(target_id, source_id, 100)",
        "callee_signature": {
            "name": "transfer_funds",
            "parameters": ["source_acct", "target_acct", "amount"],
            "defaults": {}
        },
        "contract": {
            "callee": "transfer_funds",
            "required_param_bindings": {"source_acct": "source_id", "target_acct": "target_id"},
            "forbidden_param_bindings": {"source_acct": "target_id"}
        },
        "diff": "diff --git a/src/ledger.py b/src/ledger.py\n--- a/src/ledger.py\n+++ b/src/ledger.py\n@@ -15,2 +15,2 @@\n def pay(source_id, target_id):\n-    transfer_funds(source_id, target_id, 100)\n+    transfer_funds(target_id, source_id, 100)\n"
    },
    {
        "id": "CALL-ORD-03",
        "slice": "argument_order_swap",
        "description": "Call swapping role and principal arguments violating typed parameter contract",
        "call_code": "grant_permission(user_id, 'viewer')",
        "callee_signature": {
            "name": "grant_permission",
            "parameters": ["role", "principal"],
            "defaults": {}
        },
        "contract": {
            "callee": "grant_permission",
            "required_param_bindings": {"role": "viewer"},
            "forbidden_param_bindings": {"role": "user_id"}
        },
        "diff": "diff --git a/src/rbac.py b/src/rbac.py\n--- a/src/rbac.py\n+++ b/src/rbac.py\n@@ -20,2 +20,2 @@\n def assign(user_id):\n-    grant_permission('viewer', user_id)\n+    grant_permission(user_id, 'viewer')\n"
    },
    {
        "id": "CALL-ORD-04",
        "slice": "argument_order_swap",
        "description": "Call specifying arguments out of positional order via explicit keyword binding",
        "call_code": "create_user(email='user@test.org', name='Alice')",
        "callee_signature": {
            "name": "create_user",
            "parameters": ["name", "email"],
            "defaults": {}
        },
        "contract": {
            "callee": "create_user",
            "required_param_bindings": {"name": "Alice", "email": "user@test.org"},
            "forbidden_param_bindings": {}
        },
        "diff": "diff --git a/src/users.py b/src/users.py\n--- a/src/users.py\n+++ b/src/users.py\n@@ -3,2 +3,2 @@\n def signup():\n-    pass\n+    create_user(email='user@test.org', name='Alice')\n"
    },

    # Slice 4: dynamic_expression_args (5 cases)
    {
        "id": "CALL-DYN-01",
        "slice": "dynamic_expression_args",
        "description": "Call passing runtime os.environ.get lookup to verify argument",
        "call_code": "http_request('https://api.internal', verify=os.environ.get('VERIFY_SSL'))",
        "callee_signature": {
            "name": "http_request",
            "parameters": ["url", "timeout", "verify"],
            "defaults": {"timeout": 30, "verify": True}
        },
        "contract": {
            "callee": "http_request",
            "required_kwargs": {"verify": True},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/client.py b/src/client.py\n--- a/src/client.py\n+++ b/src/client.py\n@@ -8,2 +8,2 @@\n def fetch(url):\n-    return http_request(url, verify=True)\n+    return http_request(url, verify=os.environ.get('VERIFY_SSL'))\n"
    },
    {
        "id": "CALL-DYN-02",
        "slice": "dynamic_expression_args",
        "description": "Call passing session.is_readonly() method invocation to readonly argument",
        "call_code": "exec_query(user_query, readonly=session.is_readonly())",
        "callee_signature": {
            "name": "exec_query",
            "parameters": ["sql", "readonly"],
            "defaults": {"readonly": True}
        },
        "contract": {
            "callee": "exec_query",
            "required_kwargs": {"readonly": True},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/session.py b/src/session.py\n--- a/src/session.py\n+++ b/src/session.py\n@@ -14,2 +14,2 @@\n def run(sql):\n-    return exec_query(sql, readonly=True)\n+    return exec_query(sql, readonly=session.is_readonly())\n"
    },
    {
        "id": "CALL-DYN-03",
        "slice": "dynamic_expression_args",
        "description": "Call passing dynamic helper function choose_cipher(cfg) to cipher argument",
        "call_code": "encrypt_payload(buf, cipher=choose_cipher(cfg), key_len=256)",
        "callee_signature": {
            "name": "encrypt_payload",
            "parameters": ["data", "cipher", "key_len"],
            "defaults": {"cipher": "AES-GCM", "key_len": 256}
        },
        "contract": {
            "callee": "encrypt_payload",
            "required_kwargs": {"cipher": "AES-GCM"},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/crypto.py b/src/crypto.py\n--- a/src/crypto.py\n+++ b/src/crypto.py\n@@ -22,2 +22,2 @@\n def encrypt(buf):\n-    return encrypt_payload(buf, cipher='AES-GCM')\n+    return encrypt_payload(buf, cipher=choose_cipher(cfg), key_len=256)\n"
    },
    {
        "id": "CALL-DYN-04",
        "slice": "dynamic_expression_args",
        "description": "Call with conditional expression permitting allow_builtins=True in debug branch",
        "call_code": "sandbox_eval(code, allow_builtins=True if debug_mode else False)",
        "callee_signature": {
            "name": "sandbox_eval",
            "parameters": ["expr", "allow_builtins"],
            "defaults": {"allow_builtins": False}
        },
        "contract": {
            "callee": "sandbox_eval",
            "required_kwargs": {"allow_builtins": False},
            "forbidden_kwargs": {"allow_builtins": True}
        },
        "diff": "diff --git a/src/sandbox.py b/src/sandbox.py\n--- a/src/sandbox.py\n+++ b/src/sandbox.py\n@@ -9,2 +9,2 @@\n def run_sandbox(code):\n-    return sandbox_eval(code, allow_builtins=False)\n+    return sandbox_eval(code, allow_builtins=True if debug_mode else False)\n"
    },
    {
        "id": "CALL-DYN-05",
        "slice": "dynamic_expression_args",
        "description": "Call with statically resolvable constant binary operations folding to verified contract",
        "call_code": "configure_crypto(cipher='AES' + '-GCM', iterations=100 * 1000)",
        "callee_signature": {
            "name": "configure_crypto",
            "parameters": ["cipher", "iterations"],
            "defaults": {}
        },
        "contract": {
            "callee": "configure_crypto",
            "required_kwargs": {"cipher": "AES-GCM", "iterations": 100000},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/crypto.py b/src/crypto.py\n--- a/src/crypto.py\n+++ b/src/crypto.py\n@@ -30,2 +30,2 @@\n def setup():\n-    pass\n+    configure_crypto(cipher='AES' + '-GCM', iterations=100 * 1000)\n"
    },

    # Slice 5: kwargs_unpacking (4 cases)
    {
        "id": "CALL-KWA-01",
        "slice": "kwargs_unpacking",
        "description": "Call delegating security flags to ungrounded dynamic **session_options dictionary",
        "call_code": "create_session(uid, **session_options)",
        "callee_signature": {
            "name": "create_session",
            "parameters": ["user_id", "secure", "httponly"],
            "defaults": {"secure": True, "httponly": True}
        },
        "contract": {
            "callee": "create_session",
            "required_kwargs": {"secure": True, "httponly": True},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/auth.py b/src/auth.py\n--- a/src/auth.py\n+++ b/src/auth.py\n@@ -40,2 +40,2 @@\n def login(uid):\n-    return create_session(uid, secure=True, httponly=True)\n+    return create_session(uid, **session_options)\n"
    },
    {
        "id": "CALL-KWA-02",
        "slice": "kwargs_unpacking",
        "description": "Call passing variable *event_payload ungrounded at compile-time",
        "call_code": "dispatch_event('audit_log', *event_payload)",
        "callee_signature": {
            "name": "dispatch_event",
            "parameters": ["event_name", "payload"],
            "defaults": {}
        },
        "contract": {
            "callee": "dispatch_event",
            "required_args": {"payload": {"action": "write"}},
            "forbidden_args": {}
        },
        "diff": "diff --git a/src/audit.py b/src/audit.py\n--- a/src/audit.py\n+++ b/src/audit.py\n@@ -11,2 +11,2 @@\n def record():\n-    pass\n+    dispatch_event('audit_log', *event_payload)\n"
    },
    {
        "id": "CALL-KWA-03",
        "slice": "kwargs_unpacking",
        "description": "Call passing explicit debug=True alongside **extra_opts unpacking",
        "call_code": "init_service('worker', debug=True, **extra_opts)",
        "callee_signature": {
            "name": "init_service",
            "parameters": ["name", "debug"],
            "defaults": {"debug": False}
        },
        "contract": {
            "callee": "init_service",
            "required_kwargs": {"debug": False},
            "forbidden_kwargs": {"debug": True}
        },
        "diff": "diff --git a/src/service.py b/src/service.py\n--- a/src/service.py\n+++ b/src/service.py\n@@ -18,2 +18,2 @@\n def start():\n-    init_service('worker', debug=False)\n+    init_service('worker', debug=True, **extra_opts)\n"
    },
    {
        "id": "CALL-KWA-04",
        "slice": "kwargs_unpacking",
        "description": "Call unpacking literal dict constructor with statically resolvable arguments",
        "call_code": "api_client('https://service', **{'timeout': 30, 'retries': 3})",
        "callee_signature": {
            "name": "api_client",
            "parameters": ["endpoint", "timeout", "retries"],
            "defaults": {"timeout": 10, "retries": 1}
        },
        "contract": {
            "callee": "api_client",
            "required_kwargs": {"timeout": 30},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/client.py b/src/client.py\n--- a/src/client.py\n+++ b/src/client.py\n@@ -5,2 +5,2 @@\n def connect():\n-    pass\n+    api_client('https://service', **{'timeout': 30, 'retries': 3})\n"
    },

    # Slice 6: default_arg_reliance (4 cases)
    {
        "id": "CALL-DEF-01",
        "slice": "default_arg_reliance",
        "description": "Caller omits optional parameter relying on secure default algorithm='argon2id'",
        "call_code": "hash_password(user_pw)",
        "callee_signature": {
            "name": "hash_password",
            "parameters": ["pw", "algorithm", "rounds"],
            "defaults": {"algorithm": "argon2id", "rounds": 3}
        },
        "contract": {
            "callee": "hash_password",
            "required_kwargs": {"algorithm": "argon2id"},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/auth.py b/src/auth.py\n--- a/src/auth.py\n+++ b/src/auth.py\n@@ -55,2 +55,2 @@\n def store_pw(user_pw):\n-    pass\n+    hash_password(user_pw)\n"
    },
    {
        "id": "CALL-DEF-02",
        "slice": "default_arg_reliance",
        "description": "Caller omits tls parameter relying on insecure default tls=False",
        "call_code": "open_channel('gateway.prod', 9000)",
        "callee_signature": {
            "name": "open_channel",
            "parameters": ["host", "port", "tls"],
            "defaults": {"tls": False}
        },
        "contract": {
            "callee": "open_channel",
            "required_kwargs": {"tls": True},
            "forbidden_kwargs": {"tls": False}
        },
        "diff": "diff --git a/src/conn.py b/src/conn.py\n--- a/src/conn.py\n+++ b/src/conn.py\n@@ -25,2 +25,2 @@\n def connect():\n-    pass\n+    open_channel('gateway.prod', 9000)\n"
    },
    {
        "id": "CALL-DEF-03",
        "slice": "default_arg_reliance",
        "description": "Caller omits bypass_cache parameter relying on safe default bypass_cache=False",
        "call_code": "fetch_record(rec_id)",
        "callee_signature": {
            "name": "fetch_record",
            "parameters": ["record_id", "bypass_cache"],
            "defaults": {"bypass_cache": False}
        },
        "contract": {
            "callee": "fetch_record",
            "required_kwargs": {"bypass_cache": False},
            "forbidden_kwargs": {"bypass_cache": True}
        },
        "diff": "diff --git a/src/cache.py b/src/cache.py\n--- a/src/cache.py\n+++ b/src/cache.py\n@@ -10,2 +10,2 @@\n def get(rec_id):\n-    pass\n+    fetch_record(rec_id)\n"
    },
    {
        "id": "CALL-DEF-04",
        "slice": "default_arg_reliance",
        "description": "Caller relies on omitted parameter for external callee with unmodeled signature",
        "call_code": "third_party_call(payload)",
        "callee_signature": {
            "name": "third_party_call",
            "parameters": [],
            "defaults": {}
        },
        "contract": {
            "callee": "third_party_call",
            "required_kwargs": {"validate": True},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/external.py b/src/external.py\n--- a/src/external.py\n+++ b/src/external.py\n@@ -3,2 +3,2 @@\n def call_ext(payload):\n-    pass\n+    third_party_call(payload)\n"
    },

    # Slice 7: overload_receiver_context (4 cases)
    {
        "id": "CALL-RCV-01",
        "slice": "overload_receiver_context",
        "description": "Method call on explicit SecureStorage receiver matching required contract",
        "call_code": "secure_store.write('token', tok)",
        "callee_signature": {
            "name": "write",
            "parameters": ["self", "key", "value"],
            "defaults": {}
        },
        "contract": {
            "callee": "write",
            "required_receiver_type": "SecureStorage",
            "forbidden_receiver_type": None
        },
        "receiver_type": "SecureStorage",
        "diff": "diff --git a/src/storage.py b/src/storage.py\n--- a/src/storage.py\n+++ b/src/storage.py\n@@ -8,2 +8,2 @@\n def save(tok):\n-    pass\n+    secure_store.write('token', tok)\n"
    },
    {
        "id": "CALL-RCV-02",
        "slice": "overload_receiver_context",
        "description": "Method call on InsecureStorage receiver violating required SecureStorage receiver",
        "call_code": "insecure_store.write('token', tok)",
        "callee_signature": {
            "name": "write",
            "parameters": ["self", "key", "value"],
            "defaults": {}
        },
        "contract": {
            "callee": "write",
            "required_receiver_type": "SecureStorage",
            "forbidden_receiver_type": "InsecureStorage"
        },
        "receiver_type": "InsecureStorage",
        "diff": "diff --git a/src/storage.py b/src/storage.py\n--- a/src/storage.py\n+++ b/src/storage.py\n@@ -8,2 +8,2 @@\n def save(tok):\n-    pass\n+    insecure_store.write('token', tok)\n"
    },
    {
        "id": "CALL-RCV-03",
        "slice": "overload_receiver_context",
        "description": "Method call on untyped parameter manager with ungrounded receiver type",
        "call_code": "manager.validate()",
        "callee_signature": {
            "name": "validate",
            "parameters": ["self"],
            "defaults": {}
        },
        "contract": {
            "callee": "validate",
            "required_receiver_type": "AuthManager",
            "forbidden_receiver_type": None
        },
        "receiver_type": None,
        "diff": "diff --git a/src/manager.py b/src/manager.py\n--- a/src/manager.py\n+++ b/src/manager.py\n@@ -15,2 +15,2 @@\n def handle(manager):\n-    pass\n+    manager.validate()\n"
    },
    {
        "id": "CALL-RCV-04",
        "slice": "overload_receiver_context",
        "description": "Method call on DatabaseConnection receiver with sanitize=True keyword argument",
        "call_code": "db.query(raw_sql, sanitize=True)",
        "callee_signature": {
            "name": "query",
            "parameters": ["self", "sql", "sanitize"],
            "defaults": {"sanitize": True}
        },
        "contract": {
            "callee": "query",
            "required_receiver_type": "DatabaseConnection",
            "required_kwargs": {"sanitize": True}
        },
        "receiver_type": "DatabaseConnection",
        "diff": "diff --git a/src/db.py b/src/db.py\n--- a/src/db.py\n+++ b/src/db.py\n@@ -20,2 +20,2 @@\n def run_query(db, raw_sql):\n-    pass\n+    db.query(raw_sql, sanitize=True)\n"
    },

    # Slice 8: call_routing_mutation (5 cases) - CAP-002 N-S4 falsifier axis!
    {
        "id": "CALL-MUT-01",
        "slice": "call_routing_mutation",
        "description": "Diff mutates send_email recipient from 'a' to 'b' (replica of CAP-002 N-S4)",
        "call_code": "send_email('b')",
        "callee_signature": {
            "name": "send_email",
            "parameters": ["recipient"],
            "defaults": {}
        },
        "contract": {
            "callee": "send_email",
            "required_args": {"recipient": "a"},
            "forbidden_args": {"recipient": "b"}
        },
        "diff": "diff --git a/src/callers.py b/src/callers.py\n--- a/src/callers.py\n+++ b/src/callers.py\n@@ -3,3 +3,3 @@\n def notify_1():\n-    send_email(\"a\")\n+    send_email(\"b\")\n \n"
    },
    {
        "id": "CALL-MUT-02",
        "slice": "call_routing_mutation",
        "description": "Diff mutates audit level from 'INFO' to 'DEBUG' downgrading security audit severity",
        "call_code": "audit_logger.log(event='auth_success', level='DEBUG')",
        "callee_signature": {
            "name": "log",
            "parameters": ["self", "event", "level"],
            "defaults": {"level": "INFO"}
        },
        "contract": {
            "callee": "log",
            "required_kwargs": {"level": "INFO"},
            "forbidden_kwargs": {"level": "DEBUG"}
        },
        "diff": "diff --git a/src/audit.py b/src/audit.py\n--- a/src/audit.py\n+++ b/src/audit.py\n@@ -30,2 +30,2 @@\n def log_event():\n-    audit_logger.log(event='auth_success', level='INFO')\n+    audit_logger.log(event='auth_success', level='DEBUG')\n"
    },
    {
        "id": "CALL-MUT-03",
        "slice": "call_routing_mutation",
        "description": "Diff updates timeout parameter from 5 to 30 meeting required 30s policy",
        "call_code": "fetch_remote(url, timeout=30)",
        "callee_signature": {
            "name": "fetch_remote",
            "parameters": ["url", "timeout"],
            "defaults": {"timeout": 10}
        },
        "contract": {
            "callee": "fetch_remote",
            "required_kwargs": {"timeout": 30},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/fetch.py b/src/fetch.py\n--- a/src/fetch.py\n+++ b/src/fetch.py\n@@ -5,2 +5,2 @@\n def fetch(url):\n-    fetch_remote(url, timeout=5)\n+    fetch_remote(url, timeout=30)\n"
    },
    {
        "id": "CALL-MUT-04",
        "slice": "call_routing_mutation",
        "description": "Diff mutates priority from static 1 to dynamic get_priority(msg)",
        "call_code": "queue.push(msg, priority=get_priority(msg))",
        "callee_signature": {
            "name": "push",
            "parameters": ["self", "item", "priority"],
            "defaults": {"priority": 1}
        },
        "contract": {
            "callee": "push",
            "required_kwargs": {"priority": 1},
            "forbidden_kwargs": {}
        },
        "diff": "diff --git a/src/queue.py b/src/queue.py\n--- a/src/queue.py\n+++ b/src/queue.py\n@@ -12,2 +12,2 @@\n def enqueue(msg):\n-    queue.push(msg, priority=1)\n+    queue.push(msg, priority=get_priority(msg))\n"
    },
    {
        "id": "CALL-MUT-05",
        "slice": "call_routing_mutation",
        "description": "Diff mutates rbac role assignment from 'viewer' to 'admin' (unauthorized privilege escalation)",
        "call_code": "rbac.assign(user, 'admin')",
        "callee_signature": {
            "name": "assign",
            "parameters": ["self", "principal", "role"],
            "defaults": {}
        },
        "contract": {
            "callee": "assign",
            "required_kwargs": {"role": "viewer"},
            "forbidden_kwargs": {"role": "admin"}
        },
        "diff": "diff --git a/src/rbac.py b/src/rbac.py\n--- a/src/rbac.py\n+++ b/src/rbac.py\n@@ -45,2 +45,2 @@\n def set_role(user):\n-    rbac.assign(user, 'viewer')\n+    rbac.assign(user, 'admin')\n"
    }
]

LABELS = [
    {"id": "CALL-KWD-01", "slice": "keyword_argument_values", "expected": "VERIFIED", "intent": "explicit keyword arguments match verified contract exactly"},
    {"id": "CALL-KWD-02", "slice": "keyword_argument_values", "expected": "FAIL", "intent": "explicit keyword argument strict=False directly violates security policy"},
    {"id": "CALL-KWD-03", "slice": "keyword_argument_values", "expected": "FAIL", "intent": "forbidden argument shell=True detected in subprocess call"},
    {"id": "CALL-KWD-04", "slice": "keyword_argument_values", "expected": "VERIFIED", "intent": "explicit keyword satisfies required TLSv1.3 version"},
    {"id": "CALL-KWD-05", "slice": "keyword_argument_values", "expected": "INCONCLUSIVE", "intent": "dynamic function call as keyword argument cannot be statically grounded"},

    {"id": "CALL-POS-01", "slice": "positional_argument_values", "expected": "VERIFIED", "intent": "positional index 2 maps to parameter use_ssl and matches True"},
    {"id": "CALL-POS-02", "slice": "positional_argument_values", "expected": "FAIL", "intent": "positional index 2 maps to parameter use_ssl and violates with False"},
    {"id": "CALL-POS-03", "slice": "positional_argument_values", "expected": "VERIFIED", "intent": "positional arguments index 2 and 3 match non-writable non-executable policy"},
    {"id": "CALL-POS-04", "slice": "positional_argument_values", "expected": "FAIL", "intent": "positional index 3 provides True violating executable=False policy"},
    {"id": "CALL-POS-05", "slice": "positional_argument_values", "expected": "INCONCLUSIVE", "intent": "positional index 2 is dynamic expression; ungrounded proof routes to INCONCLUSIVE"},

    {"id": "CALL-ORD-01", "slice": "argument_order_swap", "expected": "VERIFIED", "intent": "arguments passed in canonical semantic parameter order"},
    {"id": "CALL-ORD-02", "slice": "argument_order_swap", "expected": "FAIL", "intent": "transposed arguments invert financial transfer direction"},
    {"id": "CALL-ORD-03", "slice": "argument_order_swap", "expected": "FAIL", "intent": "swapped arguments pass user_id into role parameter violating type semantics"},
    {"id": "CALL-ORD-04", "slice": "argument_order_swap", "expected": "VERIFIED", "intent": "named arguments out of positional order safely bind to corresponding parameters"},

    {"id": "CALL-DYN-01", "slice": "dynamic_expression_args", "expected": "INCONCLUSIVE", "intent": "os.environ.get is dynamic environment lookup; absence of proof is not proof of compliance"},
    {"id": "CALL-DYN-02", "slice": "dynamic_expression_args", "expected": "INCONCLUSIVE", "intent": "method call session.is_readonly() unresolvable statically"},
    {"id": "CALL-DYN-03", "slice": "dynamic_expression_args", "expected": "INCONCLUSIVE", "intent": "dynamic helper function choose_cipher(cfg) is ungrounded"},
    {"id": "CALL-DYN-04", "slice": "dynamic_expression_args", "expected": "FAIL", "intent": "conditional expression contains branch with forbidden value allow_builtins=True"},
    {"id": "CALL-DYN-05", "slice": "dynamic_expression_args", "expected": "VERIFIED", "intent": "compile-time constant binary operations fold to verified contract values"},

    {"id": "CALL-KWA-01", "slice": "kwargs_unpacking", "expected": "INCONCLUSIVE", "intent": "dynamic **kwargs dictionary cannot be statically grounded"},
    {"id": "CALL-KWA-02", "slice": "kwargs_unpacking", "expected": "INCONCLUSIVE", "intent": "variable *args unpacking cannot be statically grounded"},
    {"id": "CALL-KWA-03", "slice": "kwargs_unpacking", "expected": "FAIL", "intent": "explicit debug=True alongside **kwargs directly violates security contract"},
    {"id": "CALL-KWA-04", "slice": "kwargs_unpacking", "expected": "VERIFIED", "intent": "literal dictionary unpacking can be statically resolved and satisfies contract"},

    {"id": "CALL-DEF-01", "slice": "default_arg_reliance", "expected": "VERIFIED", "intent": "caller reliance on callee default parameter argon2id satisfies contract"},
    {"id": "CALL-DEF-02", "slice": "default_arg_reliance", "expected": "FAIL", "intent": "caller reliance on omitted parameter inherits insecure default tls=False"},
    {"id": "CALL-DEF-03", "slice": "default_arg_reliance", "expected": "VERIFIED", "intent": "caller reliance on default parameter bypass_cache=False satisfies contract"},
    {"id": "CALL-DEF-04", "slice": "default_arg_reliance", "expected": "INCONCLUSIVE", "intent": "omitted parameter on unmodeled callee signature routes to INCONCLUSIVE"},

    {"id": "CALL-RCV-01", "slice": "overload_receiver_context", "expected": "VERIFIED", "intent": "receiver type SecureStorage matches required receiver contract"},
    {"id": "CALL-RCV-02", "slice": "overload_receiver_context", "expected": "FAIL", "intent": "receiver type InsecureStorage violates required SecureStorage receiver policy"},
    {"id": "CALL-RCV-03", "slice": "overload_receiver_context", "expected": "INCONCLUSIVE", "intent": "untyped parameter receiver cannot be statically proven"},
    {"id": "CALL-RCV-04", "slice": "overload_receiver_context", "expected": "VERIFIED", "intent": "receiver type and keyword argument values both satisfy verified contract"},

    {"id": "CALL-MUT-01", "slice": "call_routing_mutation", "expected": "FAIL", "intent": "call argument string literal mutated from 'a' to 'b' (resolves CAP-002 N-S4 falsifier)"},
    {"id": "CALL-MUT-02", "slice": "call_routing_mutation", "expected": "FAIL", "intent": "call keyword argument mutated from INFO to DEBUG downgrading audit severity"},
    {"id": "CALL-MUT-03", "slice": "call_routing_mutation", "expected": "VERIFIED", "intent": "diff updates timeout from 5 to 30 satisfying required 30s policy"},
    {"id": "CALL-MUT-04", "slice": "call_routing_mutation", "expected": "INCONCLUSIVE", "intent": "call argument mutated to ungrounded dynamic function call"},
    {"id": "CALL-MUT-05", "slice": "call_routing_mutation", "expected": "FAIL", "intent": "call argument mutated from viewer to admin (unauthorized privilege escalation)"}
]


def main() -> None:
    # 1. Write cases.jsonl
    cases_lines = [json.dumps(c, sort_keys=True) for c in CASES]
    cases_content = "\n".join(cases_lines) + "\n"
    cases_bytes = cases_content.encode("utf-8")
    cases_hash = hashlib.sha256(cases_bytes).hexdigest()
    (HERE / "cases.jsonl").write_bytes(cases_bytes)

    # 2. Write labels.jsonl
    labels_lines = [json.dumps(lbl, sort_keys=True) for lbl in LABELS]
    labels_content = "\n".join(labels_lines) + "\n"
    labels_bytes = labels_content.encode("utf-8")
    labels_hash = hashlib.sha256(labels_bytes).hexdigest()
    (HERE / "labels.jsonl").write_bytes(labels_bytes)

    # 3. Write SHA256 hashes
    (HERE / "CORPUS_SHA256").write_text(f"{cases_hash}\n", encoding="utf-8")
    (HERE / "LABEL_SHA256").write_text(f"{labels_hash}\n", encoding="utf-8")

    # 4. Verify counts
    slice_counts = {}
    for c in CASES:
        slice_counts[c["slice"]] = slice_counts.get(c["slice"], 0) + 1

    expected_counts = {}
    for lbl in LABELS:
        expected_counts[lbl["expected"]] = expected_counts.get(lbl["expected"], 0) + 1

    # 5. Write config.json
    cfg = {
        "experiment_id": "CAP-004",
        "title": "Argument-Value / Call-Semantics Verification",
        "case_count": len(CASES),
        "slice_counts": slice_counts,
        "expected_counts": expected_counts,
        "corpus_sha256": cases_hash,
        "label_sha256": labels_hash,
        "status": "CORPUS_FROZEN_IMPLEMENTATION_NOT_YET_EVALUATED",
        "freeze_rule": "Gold labels sealed from implementation path; no reclassification permitted."
    }
    (HERE / "config.json").write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")

    # 6. Write MODE_PROTOCOL.md
    proto = f"""# CAP-004 Protocol: Argument-Value / Call-Semantics Verification (FROZEN)

**Experiment ID**: CAP-004  
**Corpus SHA-256**: `{cases_hash}`  
**Label SHA-256**: `{labels_hash}`  
**Total Cases**: {len(CASES)}  

## Category & Slice Distribution
- Total Cases: {len(CASES)}
- Verified (Positive): {expected_counts.get('VERIFIED', 0)}
- Fail (Rejection): {expected_counts.get('FAIL', 0)}
- Inconclusive (Dynamic/Ungrounded/Unmodeled): {expected_counts.get('INCONCLUSIVE', 0)}

### Slices
{json.dumps(slice_counts, indent=2)}

## Core Invariants
1. **Absence of Proof is Not Proof of Compliance**:
   Dynamic runtime expressions (`os.environ.get`, `session.method()`, variable `**kwargs` / `*args`, unmodeled signatures) must route to `INCONCLUSIVE` (`established=False`), never `VERIFIED` and never false `PASS`.
2. **Call Semantics Over Graph Topology**:
   A graph edge `CALLS(caller, callee)` is necessary but not sufficient. When a contract governs argument values (e.g. `strict=True`, `verify=True`, `shell=False`), violating argument values must route to `FAIL`.
3. **Positional and Keyword Mapping**:
   Arguments must be resolved against parameter signatures. Positional arguments map to parameter indices; keyword arguments map to parameter names; default parameter values are consulted when arguments are omitted.
4. **Adversarial Argument Mutation (CAP-002 N-S4 Falsifier Resolution)**:
   Diffs modifying existing call arguments (e.g. `send_email("a")` -> `send_email("b")`, role escalation `"viewer"` -> `"admin"`) without authorization must be detected and routed to `FAIL` (or review escalation), eliminating the argument-blindness failure mode of legacy systems.
5. **Anti-Circularity**:
   Gold labels are sealed before C1 redesign implementation. No case may be altered or reclassified after observing results.
"""
    (HERE / "MODE_PROTOCOL.md").write_text(proto, encoding="utf-8")

    print(f"Generated {len(CASES)} cases and {len(LABELS)} labels.")
    print(f"Corpus SHA256: {cases_hash}")
    print(f"Label SHA256:  {labels_hash}")
    print(f"Slices: {slice_counts}")
    print(f"Outcomes: {expected_counts}")


if __name__ == "__main__":
    main()
