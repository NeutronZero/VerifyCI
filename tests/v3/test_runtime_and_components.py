"""Unit tests for VerifyCI v3.1 runtime, cache, frontend, and analysis modules."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import pytest
from verifyci.runtime.budget import WorkBudget, DEFAULT_BUDGET
from verifyci.runtime.diagnostics import format_diagnostic
from verifyci.runtime.scheduler import run_deterministic_batch
from verifyci.index.cache import CacheStore, entry_digest
from verifyci.index.facts import FileFacts
from verifyci.index.symbol_index import SymbolIndex
from verifyci.index.provider import FactProvider
from verifyci.frontend.vfir import EntityStatus, Capability
from verifyci.frontend.python_frontend import PythonFrontend
from verifyci.frontend.ts_frontend import TypeScriptFrontend
from verifyci.frontend.fidelity import check_fidelity
from verifyci.analysis.cfg import CFG
from verifyci.analysis.ssa import SSAForm
from verifyci.analysis.guards import GuardAnalyzer
from verifyci.analysis.effects import EffectModel
from verifyci.analysis.taint import TaintAnalyzer
from verifyci.analysis.summaries import FunctionSummary


def test_runtime_budget():
    b = WorkBudget(max_entities=500)
    d = b.to_dict()
    assert d["max_entities"] == 500
    assert len(b.digest()) == 64
    assert len(DEFAULT_BUDGET.digest()) == 64


def test_runtime_diagnostics():
    diag = format_diagnostic("code_foo", "detail_bar", extra="baz")
    assert diag["code"] == "code_foo"
    assert diag["detail"] == "detail_bar"
    assert diag["metadata"]["extra"] == "baz"


def test_runtime_scheduler():
    items = [1, 2, 3, 4]
    out = run_deterministic_batch(items, lambda x: x * 2)
    assert out == [2, 4, 6, 8]


def test_index_cache_none_mode():
    with tempfile.TemporaryDirectory() as td:
        c = CacheStore(td, mode="none")
        put_ok = c.put("entity_spans", {"path": "a.py"}, {"spans": []})
        assert not put_ok
        val, hit = c.get("entity_spans", {"path": "a.py"})
        assert not hit
        assert val is None


def test_index_cache_local_mode():
    with tempfile.TemporaryDirectory() as td:
        c = CacheStore(td, mode="local")
        components = {"path": "src/foo.py", "blob_hash": "sha1:1111"}
        put_ok = c.put("entity_spans", components, [{"name": "bar"}])
        assert put_ok
        val, hit = c.get("entity_spans", components)
        assert hit
        assert val == [{"name": "bar"}]

        # Negative results must not be stored in local mode
        neg_ok = c.put("summary", components, {"status": "no_path"}, is_negative=True)
        assert not neg_ok


def test_index_cache_authenticated_mode():
    with tempfile.TemporaryDirectory() as td:
        key = b"0" * 32
        c = CacheStore(td, mode="authenticated", key=key, key_id="sec-1")
        components = {"path": "src/bar.py", "blob_hash": "sha1:2222"}
        put_ok = c.put("summary", components, {"status": "clean"}, is_negative=True)
        assert put_ok

        val, hit = c.get("summary", components)
        assert hit
        assert val == {"status": "clean"}

        # Tampered entry should fail HMAC check
        k_hex = entry_digest("summary", components)
        p = Path(td) / k_hex[:2] / f"{k_hex}.json"
        assert p.is_file()
        content = p.read_text(encoding="utf-8")
        tampered = content.replace("clean", "dirty")
        p.write_text(tampered, encoding="utf-8")

        val2, hit2 = c.get("summary", components)
        assert not hit2
        assert val2 is None


def test_index_cache_validation_and_envelope_integrity():
    with tempfile.TemporaryDirectory() as td:
        # Invalid cache mode raises ValueError
        with pytest.raises(ValueError, match="Invalid cache mode"):
            CacheStore(td, mode="invalid_mode")

        # Authenticated mode without key raises ValueError
        with pytest.raises(ValueError, match="requires a non-empty cryptographic key"):
            CacheStore(td, mode="authenticated", key=None)

        # Mismatched envelope metadata fails hit
        key = b"1" * 32
        store = CacheStore(td, mode="authenticated", key=key, key_id="key-a")
        components = {"path": "src/x.py"}
        store.put("entity_spans", components, {"data": 123})
        k_hex = entry_digest("entity_spans", components)
        p = Path(td) / k_hex[:2] / f"{k_hex}.json"
        assert p.is_file()

        # Different key_id store fails hit
        other_key_store = CacheStore(td, mode="authenticated", key=key, key_id="key-b")
        val, hit = other_key_store.get("entity_spans", components)
        assert not hit
        assert val is None

        # Corrupted envelope object_type in record fails hit
        record = json.loads(p.read_text(encoding="utf-8"))
        record["object_type"] = "other_type"
        p.write_text(json.dumps(record), encoding="utf-8")
        val, hit = store.get("entity_spans", components)
        assert not hit
        assert val is None



def test_index_facts_and_symbol_index():
    ff = FileFacts(
        path="src/a.py",
        definitions=({"qname": "a:func"},),
        imports=({"module": "b"},),
        exports=("func",),
        call_sites=({"callee": "b:helper", "line": 10},),
    )
    d = ff.to_dict()
    assert d["path"] == "src/a.py"

    idx = SymbolIndex()
    idx.add_file_facts(d)
    assert "a:func" in idx.definitions
    callers = idx.find_callers("b:helper")
    assert len(callers) == 1
    assert callers[0]["caller_file"] == "src/a.py"


def test_fact_provider():
    with tempfile.TemporaryDirectory() as td:
        c = CacheStore(td, mode="local")
        fp = FactProvider(c)
        assert fp.get_entity_spans("x.py", "blob1") is None
        fp.put_entity_spans("x.py", "blob1", [{"entity": "main"}])
        cached = fp.get_entity_spans("x.py", "blob1")
        assert cached == [{"entity": "main"}]


def test_frontend_vfir_and_python():
    py_code = b"def greet(name):\n    return 'hello ' + name\n"
    fe = PythonFrontend()
    vfir = fe.lower(py_code, "test.py", "test:greet")
    assert vfir.status == EntityStatus.LOWERED
    assert vfir.parameters == ("name",)
    assert Capability.CFG in vfir.capabilities

    bad_code = b"def greet(:\n"
    vfir_bad = fe.lower(bad_code, "test.py", "test:greet")
    assert vfir_bad.status == EntityStatus.OPAQUE
    assert "parse_error" in vfir_bad.reason_codes


def test_frontend_ts_and_fidelity():
    ts_fe = TypeScriptFrontend()
    vfir = ts_fe.lower(b"function foo() {}", "test.ts", "test:foo")
    assert vfir.status == EntityStatus.LOWERED
    assert check_fidelity(b"source", 42) is True


def test_analysis_stubs():
    cfg = CFG([{"id": "b1"}])
    assert cfg.blocks[0]["id"] == "b1"

    ssa = SSAForm()
    ssa.variables["x"] = ["x0", "x1"]
    assert len(ssa.variables["x"]) == 2

    g = GuardAnalyzer()
    assert g is not None
    eff = EffectModel()
    assert eff is not None
    t = TaintAnalyzer()
    assert t is not None
    s = FunctionSummary("mod:func")
    assert s.qualified_name == "mod:func"
