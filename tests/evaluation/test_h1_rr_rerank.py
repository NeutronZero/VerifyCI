"""H1-RR rerank-revision guard: pins the reviewed rerank evidence.

Frozen H1 fusion baseline (results.json) is untouched and asserted
elsewhere. This pins the separate H1-RR claim: reranked hybrid vs dense.

Set VERIFYCI_RERANK_RERUN=1 to re-measure (requires a loadable local
cross-encoder; skips clearly when the model is unavailable).
"""
import hashlib
import json
import os
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REVISION = Path(HERE, "..", "..", "benchmarks", "beir", "rerank_revision")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _results():
    return json.loads((REVISION / "results.json").read_text(encoding="utf-8"))


def test_h1_rr_recorded_metrics_stable():
    from verifyci.evidence.claims import evaluate_claim

    rec = _results()
    assert rec["metrics"]["dense"]["ndcg"] == 0.6219642456212527
    assert rec["metrics"]["hybrid"]["ndcg"] == 0.7103848369178659
    assert rec["run"]["queries"] == 62
    assert rec["frozen"]["model_rerank"] == "cross-encoder/ms-marco-MiniLM-L-6-v2"
    assert rec["frozen"]["rerank_depth"] == 20
    assert rec["frozen"]["model_snapshot_commit"] == "233902d25c440f23af6f7d6e94d2946bac0bee0a"
    assert rec["frozen"]["model_snapshot_sha256"] == (
        "db6ad87969c7dc78320152e68a16118aeb4b2a6f7d8cc979c57f61ddb5e2ab2a")
    assert rec["frozen"]["model_files"]["model.safetensors"] == (
        "821d1aa69520101d6e0737f78a042ae25b19e5cb9160701909d10434f4aeb0ae")
    assert rec["frozen"]["revision_config_sha256"] == _sha(REVISION / "config.json")
    assert evaluate_claim("H1_RR_reranked_hybrid", rec)["status"] == "ESTABLISHED"


@pytest.mark.skipif(os.environ.get("VERIFYCI_RERANK_RERUN") != "1",
                    reason="rerank re-measure; set VERIFYCI_RERANK_RERUN=1")
def test_h1_rr_measurement_reproduces():
    try:
        from sentence_transformers import CrossEncoder  # type: ignore # noqa: F401
        CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2", local_files_only=True)
    except Exception:
        pytest.skip("local cross-encoder model unavailable")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "rerank_measure", Path(HERE, "..", "..", "benchmarks", "beir", "rerank_measure.py"))
    measure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(measure)
    before = _results()
    measure.main()
    after = _results()
    assert after["metrics"]["delta_ndcg"] == before["metrics"]["delta_ndcg"]
    assert after["frozen"]["corpus_sha256"] == before["frozen"]["corpus_sha256"]
