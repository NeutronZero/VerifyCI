"""Unit tests for shared benchmark helpers (provenance and retrieval rules)."""
from __future__ import annotations

from pathlib import Path
import pytest

from benchmarks.common.provenance import get_git_provenance, is_path_exempt
from benchmarks.common.retrieval_rules import evaluate_retrieval_abstention


def test_provenance_is_path_exempt():
    assert is_path_exempt("benchmarks/diff_impact_corpus/cap009/results.json")
    assert is_path_exempt("benchmarks\\diff_impact_corpus\\cap009\\results.json")
    assert is_path_exempt("benchmark-results-run1.json")
    assert not is_path_exempt("src/verifyci/core.py")


def test_provenance_clean_repo():
    commit, dirty = get_git_provenance()
    assert commit and len(commit) == 40
    # On this test run, dirty is a boolean
    assert isinstance(dirty, bool)


def test_retrieval_abstention_pure_logic():
    doc_map = {
        "doc1": "Contains quantum_teleportation_helper function",
        "doc2": "Irrelevant document without symbol",
    }
    # 1. Grounded symbol found in top-5
    abstained, reason = evaluate_retrieval_abstention(
        "Find quantum_teleportation_helper", ["doc1", "doc2"], doc_map
    )
    assert not abstained
    assert reason == "symbol_grounded"

    # 2. Ungrounded symbol missing from top-5
    abstained, reason = evaluate_retrieval_abstention(
        "Find quantum_teleportation_helper", ["doc2"], doc_map
    )
    assert abstained
    assert reason == "ungrounded_symbol_abstention"

    # 3. No specific symbol in query
    abstained, reason = evaluate_retrieval_abstention(
        "General documentation search query", ["doc2"], doc_map
    )
    assert not abstained
    assert reason == "no_specific_symbol_claimed"
