from pathlib import Path

from src.contracts.scheduler import ExecutableDAG, TaskStatus


def test_executable_dag_contract():
    dag = ExecutableDAG(dag_id="d1", nodes=[{"step_id": "s1"}], task_id="t1")
    assert dag.dag_id == "d1"
    assert dag.nodes[0]["step_id"] == "s1"


def test_frozen_contract_modules_import():
    import src.contracts.embedding as e
    import src.contracts.vector_store as v
    import src.contracts.tool as t
    import src.contracts.retriever as r
    import src.contracts.code_intel as c
    assert hasattr(e, "Embedder") and hasattr(v, "VectorStore")
    assert hasattr(t, "Tool") and hasattr(r, "Retriever") and hasattr(c, "CodeIntelProvider")


def test_contracts_readme_marks_not_frozen():
    readme = Path(__file__).parent.parent.parent / "src" / "contracts" / "README.md"
    text = readme.read_text()
    assert "Not Frozen" in text


def test_task_status_values():
    assert TaskStatus.PENDING.value == "PENDING"
    assert TaskStatus.FAILED.value == "FAILED"
