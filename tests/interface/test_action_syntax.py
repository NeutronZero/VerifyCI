"""Validation test for GitHub Action action.yml specification."""
from pathlib import Path
import yaml


def test_action_yml_validity():
    action_path = Path("action.yml")
    assert action_path.is_file(), "action.yml must exist at repository root"

    content = action_path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    assert data["name"] == "VerifyCI Gate"
    assert "description" in data
    assert "inputs" in data
    assert "outputs" in data
    assert "runs" in data

    # Verify expected inputs
    expected_inputs = ["path", "db", "base-ref", "head-ref", "format", "output-file", "fail-on-inconclusive"]
    for inp in expected_inputs:
        assert inp in data["inputs"], f"action.yml missing input {inp}"

    # Verify expected outputs
    expected_outputs = ["status", "rationale", "exit-code", "report-file"]
    for outp in expected_outputs:
        assert outp in data["outputs"], f"action.yml missing output {outp}"

    assert data["runs"]["using"] == "composite"
    steps = data["runs"]["steps"]
    assert len(steps) >= 1
    run_step = steps[0]
    assert "run" in run_step
    assert "verifyci verify-diff" in run_step["run"]
