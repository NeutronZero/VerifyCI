from __future__ import annotations

import ast
from types import SimpleNamespace

import pytest

from verifyci_v2.contracts.attestation import DSSEEnvelope
from verifyci_v2.contracts.ssa_ir import (
    FunctionUSSA,
    ParameterSpec,
    TaintSummary,
)
from verifyci_v2.ingestion.salsa_cutoff import SalsaIncrementalEngine
from verifyci_v2.provenance.gittuf_rsl import GittufRSLLedger, InMemoryGitPlumbingAdapter
from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore, LineageIntegrityError
from verifyci_v2.store.rabitq_index import pack_rabitq_sign_bits
from verifyci_v2.symbolic.secrets_taint import TaintTrackedSecretEngine


def _function(
    qname: str,
    *,
    body: str,
    calls: tuple[str, ...] = (),
) -> FunctionUSSA:
    return FunctionUSSA(
        node_uid=f"node:{qname}",
        repo_id="test-repo",
        qualified_name=qname,
        file_path=f"{qname.split('.')[0]}.py",
        language="python",
        start_line=1,
        end_line=2,
        canonical_signature=f"{qname}()",
        parameters=(),
        return_annotation="int",
        basic_blocks=(),
        cfg_edges=(),
        dfg_edges=(),
        call_targets=calls,
        taint_summary=TaintSummary(
            param_to_return=(),
            param_to_sinks=(),
            mutated_globals=(),
            raised_exceptions=(),
            is_pure=True,
        ),
        h_body=body,
        h_interface=f"{qname}() -> int",
    )


def test_salsa_behavioral_digest_includes_transitive_callees() -> None:
    engine = SalsaIncrementalEngine(repo_id="test-repo")
    old_functions = {
        "pkg.top": _function("pkg.top", body="return middle()", calls=("pkg.middle",)),
        "pkg.middle": _function("pkg.middle", body="return leaf()", calls=("pkg.leaf",)),
        "pkg.leaf": _function("pkg.leaf", body="return 1"),
    }
    new_functions = dict(old_functions)
    new_functions["pkg.leaf"] = _function("pkg.leaf", body="return 2")

    old_digest = engine._behavioral_digest("pkg.top", functions=old_functions)
    new_digest = engine._behavioral_digest("pkg.top", functions=new_functions)
    assert old_digest != new_digest


def test_parameter_binding_handles_keyword_posonly_varargs_and_kwarg() -> None:
    params = (
        ParameterSpec(name="source", kind="POSONLY"),
        ParameterSpec(name="payload", kind="POS_OR_KW"),
        ParameterSpec(name="extra", kind="VAR_POSITIONAL"),
        ParameterSpec(name="named", kind="KWONLY"),
        ParameterSpec(name="kwargs", kind="VAR_KEYWORD"),
    )
    callee = SimpleNamespace(parameters=tuple(p.name for p in params), param_specs=params)

    call = ast.parse("helper(safe, payload=secret)", mode="eval").body
    bound, uncertain = TaintTrackedSecretEngine._bind_call_tainted_params(call, callee, {"secret"})
    assert "payload" in bound
    assert not uncertain

    spread_call = ast.parse("helper(*secret_args)", mode="eval").body
    spread_bound, spread_uncertain = TaintTrackedSecretEngine._bind_call_tainted_params(
        spread_call, callee, {"secret_args"}
    )
    assert spread_uncertain
    assert {"source", "payload", "extra"}.issubset(spread_bound)

    kw_spread_call = ast.parse("helper(**secret_kwargs)", mode="eval").body
    kw_bound, kw_uncertain = TaintTrackedSecretEngine._bind_call_tainted_params(
        kw_spread_call, callee, {"secret_kwargs"}
    )
    assert kw_uncertain
    assert {"payload", "named", "kwargs"}.issubset(kw_bound)


def test_rabitq_bit_packing_is_canonical_for_non_aligned_dimensions() -> None:
    for dim in (1, 7, 8, 63, 64, 65, 127, 128, 129):
        a = [1.0 if i % 3 else -1.0 for i in range(dim)]
        b = [-1.0 if i % 5 else 1.0 for i in range(dim)]
        a_bytes, a_int = pack_rabitq_sign_bits(a)
        b_bytes, b_int = pack_rabitq_sign_bits(b)
        expected_len = ((dim + 63) // 64) * 8
        assert len(a_bytes) == expected_len
        assert len(b_bytes) == expected_len
        assert int.from_bytes(a_bytes, "little") == a_int
        assert int.from_bytes(b_bytes, "little") == b_int
        assert (a_int ^ b_int).bit_count() == sum(
            1 for x, y in zip(a, b) if (x >= 0.0) != (y >= 0.0)
        )


def test_commit_bound_snapshot_requires_explicit_git_validation_mode() -> None:
    store = DuckDBCPGStore(":memory:", backend="sqlite")
    try:
        with pytest.raises(LineageIntegrityError):
            store.record_source_snapshot("synthetic-commit", {"src/module.py": "value = 1\n"})
    finally:
        store.close()


def test_source_snapshot_manifest_detects_tampered_file() -> None:
    store = DuckDBCPGStore(":memory:", backend="sqlite", allow_unverified_snapshots=True)
    try:
        store.record_source_snapshot("synthetic-commit", {"src/module.py": "value = 1\n"})
        assert store.load_source_snapshot("synthetic-commit") == {"src/module.py": "value = 1\n"}
        store._conn.execute(
            "UPDATE source_snapshots SET source_text = ? WHERE commit_sha = ? AND file_path = ?",
            ("value = 2\n", "synthetic-commit", "src/module.py"),
        )
        store._conn.commit()
        with pytest.raises(LineageIntegrityError):
            store.load_source_snapshot("synthetic-commit")
    finally:
        store.close()


def test_in_memory_rsl_keeps_hash_chain_valid() -> None:
    ledger = GittufRSLLedger(git_adapter=InMemoryGitPlumbingAdapter())
    envelope = DSSEEnvelope(
        payloadType="application/vnd.in-toto+json",
        payload="e30=",
        signatures=(),
    )
    entry = ledger.append_reference_entry(
        ref_name="refs/heads/main",
        target_commit_sha="synthetic-commit",
        ussa_merkle_root="0" * 64,
        dsse_envelope=envelope,
        timestamp_epoch=1,
    )
    assert ledger.latest_entry == entry
    assert ledger.verify_rsl_lineage(expected_head_commit="synthetic-commit")


def test_source_snapshot_manifest_binds_commit_identity() -> None:
    store = DuckDBCPGStore(":memory:", backend="sqlite", allow_unverified_snapshots=True)
    try:
        store.record_source_snapshot("commit-a", {"src/module.py": "value = 1\n"})
        # Moving intact rows to a new commit key must not preserve the manifest.
        store._conn.execute(
            "UPDATE source_snapshots SET commit_sha = ? WHERE commit_sha = ?",
            ("commit-b", "commit-a"),
        )
        store._conn.execute(
            "UPDATE source_snapshot_manifests SET commit_sha = ? WHERE commit_sha = ?",
            ("commit-b", "commit-a"),
        )
        store._conn.commit()
        with pytest.raises(LineageIntegrityError):
            store.load_source_snapshot("commit-b")
    finally:
        store.close()
