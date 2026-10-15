"""Structural guards for the frozen-corpus ground-truth oracle (remediation #5).

These tests assert that the oracle MEASURES. They deliberately do not assert
metric values: a capability that fails its bar must stay failing and visible,
so pinning the score here would turn an evidence check into a promotion gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.common.cap_adjudicator import V2CapabilityAdjudicator

BENCHMARKS_ROOT = Path(__file__).resolve().parents[2] / "benchmarks"

MEASURED_CAPS = {
    "cap002b",
    "cap011",
    "cap002_heldout",
    "cap004",
    "cap003a",
    "cap009",
    "cap010",
}


@pytest.fixture(scope="module")
def oracle_report() -> dict:
    return V2CapabilityAdjudicator().adjudicate_corpus_oracles(BENCHMARKS_ROOT)


def test_oracle_measures_every_measurable_capability(oracle_report: dict) -> None:
    """Every corpus with a v2 engine entry point must carry a real measurement."""
    by_cap = {sc["cap_id"]: sc for sc in oracle_report["scorecards"]}
    for cap_id in MEASURED_CAPS:
        scorecard = by_cap[cap_id]
        assert scorecard["passed"] is not None, f"{cap_id} produced no measurement"
        assert scorecard["metric_value"] is not None
        assert scorecard["scored"] > 0
        assert scorecard["not_scored_reason"] is None


def test_unmeasurable_capabilities_fail_closed(oracle_report: dict) -> None:
    """A capability with no v2 equivalent is reported unmeasurable, never as a pass."""
    by_cap = {sc["cap_id"]: sc for sc in oracle_report["scorecards"]}
    unmeasurable = [
        sc for sc in by_cap.values() if sc["cap_id"] not in MEASURED_CAPS
    ]
    assert unmeasurable, "expected known-unmeasurable capabilities to be declared"
    for scorecard in unmeasurable:
        assert scorecard["passed"] is None, (
            f"{scorecard['cap_id']} reported passed={scorecard['passed']} "
            "without a ground-truth measurement"
        )
        assert scorecard["not_scored_reason"]


def test_false_accepts_are_counted_not_hidden(oracle_report: dict) -> None:
    """Fail-open cases must be counted explicitly on every measured capability."""
    for scorecard in oracle_report["scorecards"]:
        if scorecard["cap_id"] not in MEASURED_CAPS:
            continue
        assert "false_accept_count" in scorecard
        assert isinstance(scorecard["false_accept_count"], int)
    assert "total_false_accepts" in oracle_report


def test_oracle_thresholds_are_declared_with_a_basis(oracle_report: dict) -> None:
    """Every bar must state where it came from so it cannot be silently lowered."""
    for scorecard in oracle_report["scorecards"]:
        if scorecard["cap_id"] not in MEASURED_CAPS:
            continue
        assert scorecard["threshold_basis"], scorecard["cap_id"]
        assert scorecard["target_threshold"] > 0


def test_corpus_adjudication_surfaces_oracles() -> None:
    """`adjudicate --corpus` must report integrity AND measurement together."""
    report = V2CapabilityAdjudicator().adjudicate_corpus(BENCHMARKS_ROOT)
    assert report["all_verified"] is True
    assert "oracles" in report
    assert report["oracles"]["measured_capabilities"] >= len(MEASURED_CAPS)